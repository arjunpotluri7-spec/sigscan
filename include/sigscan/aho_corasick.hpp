#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace sigscan {

class AutomatonTooLarge : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

// Multi-pattern matcher over case-folded input.
//
// Every atom is folded (ASCII lower-case) when added and every input byte is folded while
// scanning, so one automaton serves case-sensitive and nocase strings alike; the caller verifies
// the exact pattern afterwards. Bytes that never occur in any atom collapse into one alphabet
// class, which keeps the dense transition table small (states x classes instead of states x 256).
class AhoCorasick {
 public:
  static constexpr std::uint32_t kNone = 0xFFFFFFFFU;
  static constexpr std::uint32_t kOutputFlag = 0x80000000U;
  static constexpr std::uint32_t kRowMask = 0x7FFFFFFFU;

  // Returns the atom id. Duplicate atoms are not merged here; the caller dedups.
  std::uint32_t add(std::span<const std::uint8_t> atom);

  // Builds failure links and the dense DFA. Throws AutomatonTooLarge if the transition table
  // would exceed `max_table_bytes`.
  void build(std::size_t max_table_bytes);

  [[nodiscard]] bool built() const { return built_; }
  [[nodiscard]] std::size_t state_count() const { return state_count_; }
  [[nodiscard]] std::size_t alphabet_classes() const { return classes_; }
  [[nodiscard]] std::size_t table_bytes() const { return delta_.size() * sizeof(std::uint32_t); }
  [[nodiscard]] std::size_t atom_count() const { return atom_lengths_.size(); }
  [[nodiscard]] std::size_t atom_length(std::uint32_t atom) const { return atom_lengths_[atom]; }

  // Calls on_match(atom_id, end) for every atom occurrence, where `end` is the index one past
  // the last byte of the occurrence inside `data`.
  template <typename OnMatch>
  void scan(std::span<const std::uint8_t> data, const OnMatch& on_match) const {
    if (!built_) {
      return;
    }
    // The table holds pre-multiplied row offsets with an "has output" flag in the top bit, so
    // the per-byte work is one class lookup, one table load and one well-predicted branch.
    const std::uint32_t* table = delta_.data();
    const std::uint32_t* classes = byte_class_.data();
    std::uint32_t row = 0;
    const std::size_t n = data.size();
    for (std::size_t i = 0; i < n; ++i) {
      const std::uint32_t next = table[row + classes[data[i]]];
      row = next & kRowMask;
      if ((next & kOutputFlag) != 0U) {
        const auto state = static_cast<std::uint32_t>(row / classes_);
        for (std::uint32_t s = state; s != kNone; s = dict_link_[s]) {
          const std::uint32_t begin = out_begin_[s];
          const std::uint32_t end = out_begin_[s + 1];
          for (std::uint32_t k = begin; k < end; ++k) {
            on_match(out_atoms_[k], i + 1);
          }
        }
      }
    }
  }

 private:
  std::vector<std::vector<std::uint8_t>> atoms_;  // folded, kept until build()
  std::vector<std::size_t> atom_lengths_;
  std::array<std::uint32_t, 256> byte_class_{};
  std::size_t classes_ = 1;
  std::size_t state_count_ = 1;
  std::vector<std::uint32_t> delta_;      // [row + class] -> next row (state * classes_) | flag
  std::vector<std::uint32_t> dict_link_;  // nearest suffix state with own output, or kNone
  std::vector<std::uint32_t> out_begin_;  // CSR offsets into out_atoms_, size states + 1
  std::vector<std::uint32_t> out_atoms_;
  bool built_ = false;
};

}  // namespace sigscan
