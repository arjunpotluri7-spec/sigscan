// libFuzzer harness: differential test of the matching engine.
//
// The input describes up to six patterns (text or hex, with nocase/wide/wildcards) followed by
// a haystack. The harness checks that
//   1. the Aho-Corasick engine finds exactly the hits of the naive matcher, and
//   2. a chunked scan with a fuzzer-chosen chunk size reports the same per-string offsets,
// and aborts on any difference.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "sigscan/ruleset.hpp"
#include "sigscan/scanner.hpp"

namespace {

class Input {
 public:
  explicit Input(std::span<const std::uint8_t> data) : data_(data) {}
  std::uint8_t byte() { return pos_ < data_.size() ? data_[pos_++] : 0; }
  [[nodiscard]] std::span<const std::uint8_t> rest() const { return data_.subspan(pos_); }

 private:
  std::span<const std::uint8_t> data_;
  std::size_t pos_ = 0;
};

std::string hex2(std::uint8_t b) {
  static constexpr const char* kHex = "0123456789ABCDEF";
  return std::string{kHex[b >> 4U], kHex[b & 0x0FU]};
}

void check(bool ok) {
  if (!ok) {
    std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size > 16 * 1024) {
    return 0;
  }
  Input in(std::span<const std::uint8_t>(data, size));
  const std::size_t chunk = 1 + (in.byte() % 64);
  const std::size_t count = 1 + (in.byte() % 6);

  std::string source = "rule fuzz {\n strings:\n";
  for (std::size_t i = 0; i < count; ++i) {
    const std::size_t len = 1 + (in.byte() % 8);
    const std::uint8_t flags = in.byte();
    const std::uint8_t wildcard_bits = in.byte();
    std::vector<std::uint8_t> bytes(len);
    for (auto& b : bytes) {
      // Small alphabet so that patterns actually occur in the haystack.
      b = static_cast<std::uint8_t>("aAbB\x00\xff"[in.byte() % 6]);
    }
    source += "  $s" + std::to_string(i) + " = ";
    if ((flags & 1U) != 0) {
      source += "{";
      bool literal = false;
      for (std::size_t k = 0; k < len; ++k) {
        const bool wild = k < 8 && ((wildcard_bits >> k) & 1U) != 0 && (literal || k + 1 < len);
        source += wild ? " ??" : " " + hex2(bytes[k]);
        literal = literal || !wild;
      }
      source += " }\n";
    } else {
      source += "\"";
      for (const std::uint8_t b : bytes) {
        source += "\\x" + hex2(b);
      }
      source += "\"";
      if ((flags & 2U) != 0) {
        source += " nocase";
      }
      if ((flags & 4U) != 0) {
        source += " wide";
      }
      if ((flags & 8U) != 0) {
        source += " ascii";
      }
      source += "\n";
    }
  }
  source += " condition:\n  any of them\n}\n";

  sigscan::RulesetBuilder builder;
  builder.add_source(source, "fuzz_matcher.sig");
  const sigscan::CompileResult compiled = builder.compile();
  check(compiled.ruleset != nullptr);
  const sigscan::Ruleset& rs = *compiled.ruleset;

  const std::span<const std::uint8_t> haystack = in.rest();
  const std::vector<sigscan::Hit> fast = rs.find_hits(haystack);
  const std::vector<sigscan::Hit> slow = sigscan::naive_find_all(rs.patterns(), haystack);
  check(fast == slow);

  std::map<std::string, std::set<std::uint64_t>> expected;
  for (const sigscan::Hit& h : slow) {
    expected[rs.strings()[rs.patterns()[h.pattern_id].string_id].id].insert(h.offset);
  }

  sigscan::ScanOptions options;
  options.chunk_size = chunk;
  options.max_matches_per_string = 1U << 20U;
  const sigscan::Scanner scanner(compiled.ruleset, options);
  const sigscan::FileResult result = scanner.scan_buffer(haystack);
  std::map<std::string, std::set<std::uint64_t>> actual;
  for (const auto& match : result.matches) {
    for (const auto& s : match.strings) {
      check(s.hits.count == s.hits.matches.size());
      for (const auto& m : s.hits.matches) {
        actual[s.id].insert(m.offset);
      }
    }
  }
  check(actual == expected);
  check(result.size == haystack.size());
  return 0;
}
