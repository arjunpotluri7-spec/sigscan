#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sigscan {

// ASCII-only case folding table (bytes >= 0x80 are left untouched).
[[nodiscard]] const std::array<std::uint8_t, 256>& ascii_fold_table();

[[nodiscard]] inline std::uint8_t fold_byte(std::uint8_t b) {
  return ascii_fold_table()[b];
}

// One concrete byte pattern. A text string with `ascii wide` compiles to two patterns.
struct Pattern {
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> mask;  // 0xFF literal, 0x00 wildcard
  bool nocase = false;
  bool wide = false;
  std::size_t string_id = 0;  // global string index in the Ruleset

  [[nodiscard]] std::size_t size() const { return bytes.size(); }

  // True if the full pattern matches `data` starting at `pos`. Out-of-range positions return
  // false rather than reading past the end.
  [[nodiscard]] bool matches_at(std::span<const std::uint8_t> data, std::size_t pos) const;
};

// The literal run chosen to represent a pattern inside the automaton.
struct AtomChoice {
  std::size_t offset = 0;  // where the atom starts inside the pattern
  std::size_t length = 0;  // 0 means the pattern has no literal byte
};

// Longest run of literal bytes (earliest on ties), truncated to `max_length`.
[[nodiscard]] AtomChoice choose_atom(const Pattern& pattern, std::size_t max_length);

struct Hit {
  std::size_t pattern_id = 0;
  std::uint64_t offset = 0;

  friend bool operator==(const Hit&, const Hit&) = default;
  friend auto operator<=>(const Hit&, const Hit&) = default;
};

// Reference matcher: checks every pattern at every offset. Used as the oracle in tests and
// fuzzing and as the baseline in `sigscan bench`. Result is sorted.
[[nodiscard]] std::vector<Hit> naive_find_all(std::span<const Pattern> patterns,
                                              std::span<const std::uint8_t> data);

}  // namespace sigscan
