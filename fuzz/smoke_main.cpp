// Portable fuzz smoke driver.
//
// Apple clang does not ship libFuzzer, so this driver links against the same
// LLVMFuzzerTestOneInput entry point and replays the seed corpus plus a fixed number of
// deterministic mutations (bit flips, byte edits, range deletes/duplicates, dictionary token
// inserts, splices). Built with -fsanitize=address,undefined it catches memory and UB bugs on any
// platform; coverage-guided fuzzing still runs in Linux CI with real libFuzzer.
//
// Usage: fuzz_smoke_<target> CORPUS_DIR ITERATIONS [SEED]
#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

namespace {

constexpr std::size_t kMaxInput = 4096;

constexpr std::array<std::string_view, 40> kDictionary = {
    "rule ",
    "{",
    "}",
    "meta:",
    "strings:",
    "condition:",
    "$a",
    "$b",
    "$a*",
    "#a",
    " = ",
    "\"",
    "{ ?? }",
    "{ 4D 5A }",
    " nocase",
    " wide",
    " ascii",
    " and ",
    " or ",
    " not ",
    "any of them",
    "all of ($*)",
    "2 of ($a, $b)",
    "filesize < 5MB",
    " at 0",
    " in (0..100)",
    "\\x41",
    "(",
    ")",
    "..",
    "==",
    ">=",
    "0x10",
    "KB",
    "MB",
    "//",
    "/*",
    "*/",
    "\n",
    "severity = \"high\"",
};

class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed == 0 ? 0x9E3779B97F4A7C15ULL : seed) {}
  std::uint64_t next() {
    state_ ^= state_ << 13U;
    state_ ^= state_ >> 7U;
    state_ ^= state_ << 17U;
    return state_;
  }
  std::size_t below(std::size_t n) { return n == 0 ? 0 : static_cast<std::size_t>(next() % n); }

 private:
  std::uint64_t state_;
};

using Bytes = std::vector<std::uint8_t>;

Bytes mutate(const Bytes& base, const std::vector<Bytes>& corpus, Rng& rng) {
  Bytes out = base;
  const std::size_t ops = 1 + rng.below(4);
  for (std::size_t op = 0; op < ops; ++op) {
    switch (rng.below(7)) {
      case 0:
        if (!out.empty()) {
          out[rng.below(out.size())] ^= static_cast<std::uint8_t>(1U << rng.below(8));
        }
        break;
      case 1:
        if (!out.empty()) {
          out[rng.below(out.size())] = static_cast<std::uint8_t>(rng.next());
        }
        break;
      case 2:
        out.insert(out.begin() + static_cast<std::ptrdiff_t>(rng.below(out.size() + 1)),
                   static_cast<std::uint8_t>(rng.next()));
        break;
      case 3:
        if (!out.empty()) {
          const std::size_t start = rng.below(out.size());
          const std::size_t len = std::min(out.size() - start, 1 + rng.below(8));
          out.erase(out.begin() + static_cast<std::ptrdiff_t>(start),
                    out.begin() + static_cast<std::ptrdiff_t>(start + len));
        }
        break;
      case 4:
        if (!out.empty()) {
          const std::size_t start = rng.below(out.size());
          const std::size_t len = std::min(out.size() - start, 1 + rng.below(16));
          const Bytes piece(out.begin() + static_cast<std::ptrdiff_t>(start),
                            out.begin() + static_cast<std::ptrdiff_t>(start + len));
          out.insert(out.begin() + static_cast<std::ptrdiff_t>(rng.below(out.size() + 1)),
                     piece.begin(), piece.end());
        }
        break;
      case 5: {
        const std::string_view token = kDictionary[rng.below(kDictionary.size())];
        out.insert(out.begin() + static_cast<std::ptrdiff_t>(rng.below(out.size() + 1)),
                   token.begin(), token.end());
        break;
      }
      default: {
        const Bytes& other = corpus[rng.below(corpus.size())];
        const std::size_t cut = rng.below(out.size() + 1);
        const std::size_t from = rng.below(other.size() + 1);
        out.resize(cut);
        out.insert(out.end(), other.begin() + static_cast<std::ptrdiff_t>(from), other.end());
        break;
      }
    }
  }
  if (out.size() > kMaxInput) {
    out.resize(kMaxInput);
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  const std::vector<std::string> args(argv, argv + argc);
  if (args.size() < 3) {
    std::cerr << "usage: " << args.front() << " CORPUS_DIR ITERATIONS [SEED]\n";
    return 2;
  }
  const std::filesystem::path corpus_dir = args[1];
  const unsigned long long iterations = std::strtoull(args[2].c_str(), nullptr, 10);
  const std::uint64_t seed = args.size() > 3 ? std::strtoull(args[3].c_str(), nullptr, 10) : 1;

  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(corpus_dir)) {
    if (entry.is_regular_file()) {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());
  std::vector<Bytes> corpus;
  for (const auto& path : files) {
    std::ifstream in(path, std::ios::binary);
    corpus.emplace_back(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  }
  if (corpus.empty()) {
    std::cerr << "no seed inputs in " << corpus_dir << '\n';
    return 2;
  }

  const auto start = std::chrono::steady_clock::now();
  for (const Bytes& input : corpus) {
    LLVMFuzzerTestOneInput(input.data(), input.size());
  }
  Rng rng(seed);
  std::size_t bytes = 0;
  for (unsigned long long i = 0; i < iterations; ++i) {
    const Bytes input = mutate(corpus[i % corpus.size()], corpus, rng);
    bytes += input.size();
    LLVMFuzzerTestOneInput(input.data(), input.size());
  }
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start)
                      .count();
  std::cout << "fuzz-smoke: " << corpus.size() << " seed inputs + " << iterations
            << " mutated inputs (" << bytes << " bytes, seed " << seed << ") ran clean in " << ms
            << " ms\n";
  return 0;
}
