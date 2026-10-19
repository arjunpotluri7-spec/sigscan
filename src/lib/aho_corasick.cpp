#include "sigscan/aho_corasick.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "sigscan/pattern.hpp"

namespace sigscan {

std::uint32_t AhoCorasick::add(std::span<const std::uint8_t> atom) {
  std::vector<std::uint8_t> folded(atom.begin(), atom.end());
  for (std::uint8_t& b : folded) {
    b = fold_byte(b);
  }
  atoms_.push_back(std::move(folded));
  atom_lengths_.push_back(atom.size());
  built_ = false;
  return static_cast<std::uint32_t>(atoms_.size() - 1);
}

void AhoCorasick::build(std::size_t max_table_bytes) {
  // Alphabet compression: class 0 is every byte that no atom uses.
  std::array<bool, 256> used{};
  for (const auto& atom : atoms_) {
    for (const std::uint8_t b : atom) {
      used[b] = true;
    }
  }
  std::array<std::uint32_t, 256> class_of{};
  std::uint32_t next_class = 1;
  for (std::size_t b = 0; b < used.size(); ++b) {
    if (used[b]) {
      class_of[b] = next_class++;
    }
  }
  classes_ = next_class;
  for (std::size_t b = 0; b < byte_class_.size(); ++b) {
    byte_class_[b] = class_of[fold_byte(static_cast<std::uint8_t>(b))];
  }

  const std::size_t row_bytes = classes_ * sizeof(std::uint32_t);
  auto check_budget = [&](std::size_t states) {
    if (states > kRowMask / classes_ || states > max_table_bytes / row_bytes) {
      throw AutomatonTooLarge("automaton would need more than " +
                              std::to_string(max_table_bytes / (std::size_t{1024} * 1024)) +
                              " MiB of transition table (" + std::to_string(states) + " states x " +
                              std::to_string(classes_) + " classes)");
    }
  };

  // Trie, stored directly in the dense table; kNone marks a missing edge until the BFS below.
  state_count_ = 1;
  check_budget(1);
  delta_.assign(classes_, kNone);
  std::vector<std::vector<std::uint32_t>> own(1);
  for (std::size_t id = 0; id < atoms_.size(); ++id) {
    std::uint32_t s = 0;
    for (const std::uint8_t b : atoms_[id]) {
      const std::size_t slot = (static_cast<std::size_t>(s) * classes_) + class_of[b];
      std::uint32_t t = delta_[slot];
      if (t == kNone) {
        check_budget(state_count_ + 1);
        t = static_cast<std::uint32_t>(state_count_++);
        delta_.resize(state_count_ * classes_, kNone);
        own.emplace_back();
        delta_[slot] = t;
      }
      s = t;
    }
    own[s].push_back(static_cast<std::uint32_t>(id));
  }

  // BFS turns the trie into a DFA: a missing edge from s copies the edge from fail(s), whose row
  // is already complete because fail(s) is strictly shallower.
  std::vector<std::uint32_t> fail(state_count_, 0);
  dict_link_.assign(state_count_, kNone);
  std::deque<std::uint32_t> queue;
  for (std::size_t c = 0; c < classes_; ++c) {
    const std::uint32_t t = delta_[c];
    if (t == kNone) {
      delta_[c] = 0;
    } else {
      fail[t] = 0;
      queue.push_back(t);
    }
  }
  while (!queue.empty()) {
    const std::uint32_t s = queue.front();
    queue.pop_front();
    const std::size_t row = static_cast<std::size_t>(s) * classes_;
    const std::size_t fail_row = static_cast<std::size_t>(fail[s]) * classes_;
    for (std::size_t c = 0; c < classes_; ++c) {
      const std::uint32_t t = delta_[row + c];
      if (t == kNone) {
        delta_[row + c] = delta_[fail_row + c];
        continue;
      }
      const std::uint32_t f = delta_[fail_row + c];
      fail[t] = f;
      dict_link_[t] = own[f].empty() ? dict_link_[f] : f;
      queue.push_back(t);
    }
  }

  out_begin_.assign(state_count_ + 1, 0);
  out_atoms_.clear();
  std::vector<bool> has_output(state_count_, false);
  for (std::size_t s = 0; s < state_count_; ++s) {
    out_begin_[s] = static_cast<std::uint32_t>(out_atoms_.size());
    out_atoms_.insert(out_atoms_.end(), own[s].begin(), own[s].end());
    has_output[s] = !own[s].empty() || dict_link_[s] != kNone;
  }
  out_begin_[state_count_] = static_cast<std::uint32_t>(out_atoms_.size());

  // Replace state ids with row offsets so scanning needs no multiply.
  for (std::uint32_t& t : delta_) {
    const std::size_t row = static_cast<std::size_t>(t) * classes_;
    t = static_cast<std::uint32_t>(row) | (has_output[t] ? kOutputFlag : 0U);
  }

  built_ = true;
}

}  // namespace sigscan
