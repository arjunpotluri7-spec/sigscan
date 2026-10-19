#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "sigscan/ast.hpp"
#include "sigscan/ruleset.hpp"

namespace sigscan {

inline constexpr std::uint64_t kDefaultMaxFilesize = 64ULL * 1024 * 1024;

struct ScanOptions {
  std::uint64_t max_filesize = kDefaultMaxFilesize;
  std::size_t chunk_size = std::size_t{1024} * 1024;
  std::size_t max_matches_per_string = 1000;  // offsets stored per string; counts stay exact
  std::size_t snippet_context = 4;            // bytes of context kept on each side of a match
  bool follow_symlinks = false;               // applies to files reached by directory walking
};

struct MatchRecord {
  std::uint64_t offset = 0;
  std::uint32_t length = 0;
  std::vector<std::uint8_t> context;  // match bytes (up to 24) plus a little context
  std::uint64_t context_offset = 0;   // file offset of context[0]
};

struct StringHits {
  std::uint64_t count = 0;
  std::vector<MatchRecord> matches;  // sorted by offset, at most max_matches_per_string
};

// Inputs to condition evaluation for one rule.
struct EvalContext {
  std::span<const StringHits> hits;  // indexed by rule-local string index
  std::uint64_t filesize = 0;
};

[[nodiscard]] bool evaluate(const Expr& expr, const EvalContext& ctx);

// One-line explanation of why a true condition is true, e.g.
// "matched because $a found at 0x1a0 and 2 of ($b, $c) found; filesize 4.1 KB < 5 MB".
[[nodiscard]] std::string explain(const Rule& rule, const EvalContext& ctx);

[[nodiscard]] std::string format_size(std::uint64_t bytes);

struct StringReport {
  std::string id;
  StringHits hits;
};

struct RuleMatch {
  std::size_t rule_index = 0;
  std::string why;
  std::vector<StringReport> strings;  // strings of the rule that were found
};

enum class FileStatus { Scanned, Skipped, Error };

struct FileResult {
  std::string path;
  FileStatus status = FileStatus::Scanned;
  std::string message;  // reason for Skipped/Error
  std::uint64_t size = 0;
  std::vector<RuleMatch> matches;
};

// Reads up to `buffer.size()` bytes; returns 0 at end of input. Throws on read errors.
using ReadFn = std::function<std::size_t(std::span<std::uint8_t> buffer)>;

// Runs a compiled ruleset over files or buffers. Stateless after construction and safe to share
// between threads.
class Scanner {
 public:
  Scanner(std::shared_ptr<const Ruleset> ruleset, ScanOptions options);

  [[nodiscard]] const Ruleset& ruleset() const { return *ruleset_; }
  [[nodiscard]] const ScanOptions& options() const { return options_; }

  // Scans an in-memory buffer through the same chunked path used for files.
  [[nodiscard]] FileResult scan_buffer(std::span<const std::uint8_t> data,
                                       std::string display_name = "<buffer>") const;

  // `allow_symlink` is true for paths the user named directly on the command line.
  [[nodiscard]] FileResult scan_file(const std::filesystem::path& path, std::string display_name,
                                     bool allow_symlink) const;

  // Core streaming scan. `read` is called repeatedly with chunk-sized buffers.
  [[nodiscard]] FileResult scan_stream(const ReadFn& read, std::string display_name) const;

 private:
  std::shared_ptr<const Ruleset> ruleset_;
  ScanOptions options_;
};

}  // namespace sigscan
