#include "sigscan/pattern.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace sigscan {

const std::array<std::uint8_t, 256>& ascii_fold_table() {
  static const std::array<std::uint8_t, 256> table = [] {
    std::array<std::uint8_t, 256> t{};
    for (std::size_t i = 0; i < t.size(); ++i) {
      auto b = static_cast<std::uint8_t>(i);
      if (b >= 'A' && b <= 'Z') {
        b = static_cast<std::uint8_t>(b - 'A' + 'a');
      }
      t[i] = b;
    }
    return t;
  }();
  return table;
}

bool Pattern::matches_at(std::span<const std::uint8_t> data, std::size_t pos) const {
  const std::size_t n = bytes.size();
  if (pos > data.size() || n > data.size() - pos) {
    return false;
  }
  const std::span<const std::uint8_t> window = data.subspan(pos, n);
  if (nocase) {
    for (std::size_t i = 0; i < n; ++i) {
      if (mask[i] != 0 && fold_byte(window[i]) != fold_byte(bytes[i])) {
        return false;
      }
    }
  } else {
    for (std::size_t i = 0; i < n; ++i) {
      if (mask[i] != 0 && window[i] != bytes[i]) {
        return false;
      }
    }
  }
  return true;
}

AtomChoice choose_atom(const Pattern& pattern, std::size_t max_length) {
  AtomChoice best;
  std::size_t run_start = 0;
  std::size_t run_len = 0;
  for (std::size_t i = 0; i <= pattern.mask.size(); ++i) {
    const bool literal = i < pattern.mask.size() && pattern.mask[i] != 0;
    if (literal) {
      if (run_len == 0) {
        run_start = i;
      }
      ++run_len;
      continue;
    }
    if (run_len > best.length) {
      best.offset = run_start;
      best.length = run_len;
    }
    run_len = 0;
  }
  best.length = std::min(best.length, max_length);
  return best;
}

std::vector<Hit> naive_find_all(std::span<const Pattern> patterns,
                                std::span<const std::uint8_t> data) {
  std::vector<Hit> hits;
  for (std::size_t p = 0; p < patterns.size(); ++p) {
    const Pattern& pattern = patterns[p];
    if (pattern.size() == 0 || pattern.size() > data.size()) {
      continue;
    }
    const std::size_t last = data.size() - pattern.size();
    for (std::size_t pos = 0; pos <= last; ++pos) {
      if (pattern.matches_at(data, pos)) {
        hits.push_back(Hit{p, pos});
      }
    }
  }
  std::sort(hits.begin(), hits.end());
  return hits;
}

}  // namespace sigscan
