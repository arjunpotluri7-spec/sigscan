#include "sigscan/scanner.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "sigscan/file_io.hpp"

namespace sigscan {
namespace {

constexpr std::size_t kMaxSnippetMatchBytes = 24;

std::string too_large_message(std::uint64_t size, std::uint64_t limit) {
  return "file is " + format_size(size) + ", above the --max-filesize limit of " +
         format_size(limit);
}

}  // namespace

Scanner::Scanner(std::shared_ptr<const Ruleset> ruleset, ScanOptions options)
    : ruleset_(std::move(ruleset)), options_(options) {
  if (!ruleset_) {
    throw std::invalid_argument("Scanner needs a compiled ruleset");
  }
  options_.chunk_size = std::max<std::size_t>(options_.chunk_size, 1);
}

FileResult Scanner::scan_buffer(std::span<const std::uint8_t> data,
                                std::string display_name) const {
  std::size_t pos = 0;
  const ReadFn read = [&](std::span<std::uint8_t> out) -> std::size_t {
    const std::size_t n = std::min(out.size(), data.size() - pos);
    std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(pos), n, out.begin());
    pos += n;
    return n;
  };
  return scan_stream(read, std::move(display_name));
}

FileResult Scanner::scan_file(const std::filesystem::path& path, std::string display_name,
                              bool allow_symlink) const {
  InputFile file;
  if (auto err = file.open(path, allow_symlink || options_.follow_symlinks)) {
    FileResult result;
    result.path = std::move(display_name);
    result.status = FileStatus::Error;
    result.message = *err;
    return result;
  }
  if (file.size() > options_.max_filesize) {
    FileResult result;
    result.path = std::move(display_name);
    result.status = FileStatus::Skipped;
    result.size = file.size();
    result.message = too_large_message(file.size(), options_.max_filesize);
    return result;
  }
  const ReadFn read = [&](std::span<std::uint8_t> out) { return file.read(out); };
  try {
    return scan_stream(read, display_name);
  } catch (const std::runtime_error& e) {
    FileResult result;
    result.path = std::move(display_name);
    result.status = FileStatus::Error;
    result.message = e.what();
    return result;
  }
}

// Chunked scan with an overlap of (longest pattern - 1) bytes carried between buffers. The
// automaton restarts on every buffer, and a hit is kept only if it ends past the region already
// covered by the previous buffer. Any occurrence that ends inside the new bytes starts at most
// (longest pattern - 1) bytes earlier, so it lies entirely inside the buffer and is verified
// exactly once; occurrences ending earlier were already reported.
FileResult Scanner::scan_stream(const ReadFn& read, std::string display_name) const {
  FileResult result;
  result.path = std::move(display_name);
  const Ruleset& rs = *ruleset_;
  const auto& patterns = rs.patterns();
  std::vector<StringHits> hits(rs.strings().size());

  const std::size_t overlap = rs.max_pattern_length() > 0 ? rs.max_pattern_length() - 1 : 0;
  const std::size_t chunk = options_.chunk_size;
  const std::size_t ctx_bytes = options_.snippet_context;
  std::vector<std::uint8_t> buffer;
  buffer.reserve(overlap + chunk);
  std::uint64_t base = 0;     // file offset of buffer[0]
  std::uint64_t covered = 0;  // matches ending at or before this offset are already recorded
  std::uint64_t total = 0;

  for (;;) {
    const std::size_t keep = buffer.size();
    buffer.resize(keep + chunk);
    const std::size_t n = read(std::span<std::uint8_t>(buffer).subspan(keep, chunk));
    buffer.resize(keep + std::min(n, chunk));
    if (n == 0) {
      break;
    }
    total += n;
    if (total > options_.max_filesize) {
      result.status = FileStatus::Skipped;
      result.size = total;
      result.message = too_large_message(total, options_.max_filesize) + " (grew while reading)";
      return result;
    }

    const std::span<const std::uint8_t> view(buffer);
    rs.for_each_hit(view, [&](std::size_t pattern_id, std::size_t start) {
      const Pattern& p = patterns[pattern_id];
      const std::uint64_t abs_start = base + start;
      if (abs_start + p.size() <= covered) {
        return;
      }
      StringHits& h = hits[p.string_id];
      ++h.count;
      if (h.matches.size() >= options_.max_matches_per_string) {
        return;
      }
      MatchRecord m;
      m.offset = abs_start;
      m.length = static_cast<std::uint32_t>(p.size());
      const std::size_t ctx_start = start >= ctx_bytes ? start - ctx_bytes : 0;
      const std::size_t ctx_end =
          std::min(view.size(), start + std::min(p.size(), kMaxSnippetMatchBytes) + ctx_bytes);
      m.context.assign(view.begin() + static_cast<std::ptrdiff_t>(ctx_start),
                       view.begin() + static_cast<std::ptrdiff_t>(ctx_end));
      m.context_offset = base + ctx_start;
      h.matches.push_back(std::move(m));
    });

    covered = base + buffer.size();
    if (buffer.size() > overlap) {
      const std::size_t drop = buffer.size() - overlap;
      buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(drop));
      base += drop;
    }
  }
  result.size = total;

  // ascii and wide forms of one string can both match at the same offset; count it once.
  for (StringHits& h : hits) {
    std::stable_sort(
        h.matches.begin(), h.matches.end(),
        [](const MatchRecord& a, const MatchRecord& b) { return a.offset < b.offset; });
    const auto last = std::unique(
        h.matches.begin(), h.matches.end(),
        [](const MatchRecord& a, const MatchRecord& b) { return a.offset == b.offset; });
    h.count -= static_cast<std::uint64_t>(std::distance(last, h.matches.end()));
    h.matches.erase(last, h.matches.end());
  }

  const auto& rules = rs.rules();
  for (std::size_t r = 0; r < rules.size(); ++r) {
    const Rule& rule = rules[r];
    const std::size_t first = rs.first_string(r);
    const EvalContext ctx{std::span<const StringHits>(hits).subspan(first, rule.strings.size()),
                          total};
    if (!rule.condition || !evaluate(*rule.condition, ctx)) {
      continue;
    }
    RuleMatch match;
    match.rule_index = r;
    match.why = explain(rule, ctx);
    for (std::size_t i = 0; i < rule.strings.size(); ++i) {
      if (ctx.hits[i].count > 0) {
        match.strings.push_back(StringReport{rule.strings[i].id, ctx.hits[i]});
      }
    }
    result.matches.push_back(std::move(match));
  }
  return result;
}

}  // namespace sigscan
