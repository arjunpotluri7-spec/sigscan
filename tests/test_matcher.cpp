#include <gtest/gtest.h>

#include <cstdint>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "sigscan/aho_corasick.hpp"
#include "sigscan/pattern.hpp"
#include "sigscan/ruleset.hpp"
#include "test_util.hpp"

namespace sigscan {
namespace {

using test::bytes_of;

Pattern text_pattern(std::string_view text, bool nocase = false) {
  Pattern p;
  p.bytes = bytes_of(text);
  p.mask.assign(p.bytes.size(), 0xFF);
  p.nocase = nocase;
  return p;
}

TEST(Pattern, CaseSensitiveAndNocaseVerification) {
  const auto data = bytes_of("xxConnect-BACKxx");
  EXPECT_FALSE(text_pattern("connect-back").matches_at(data, 2));
  EXPECT_TRUE(text_pattern("connect-back", true).matches_at(data, 2));
  EXPECT_TRUE(text_pattern("Connect-BACK").matches_at(data, 2));
  EXPECT_FALSE(text_pattern("connect-back", true).matches_at(data, 3));
}

TEST(Pattern, NocaseOnlyFoldsAscii) {
  Pattern p;
  p.bytes = {0xC4, 'a'};
  p.mask = {0xFF, 0xFF};
  p.nocase = true;
  const std::vector<std::uint8_t> upper = {0xC4, 'A'};
  const std::vector<std::uint8_t> other = {0xE4, 'A'};
  EXPECT_TRUE(p.matches_at(upper, 0));
  EXPECT_FALSE(p.matches_at(other, 0));
}

TEST(Pattern, HexWildcardsMatchAnyByte) {
  Pattern p;
  p.bytes = {0x4D, 0x5A, 0x00, 0x00};
  p.mask = {0xFF, 0xFF, 0x00, 0xFF};
  EXPECT_TRUE(p.matches_at(std::vector<std::uint8_t>{0x4D, 0x5A, 0x90, 0x00}, 0));
  EXPECT_TRUE(p.matches_at(std::vector<std::uint8_t>{0x4D, 0x5A, 0xFF, 0x00}, 0));
  EXPECT_FALSE(p.matches_at(std::vector<std::uint8_t>{0x4D, 0x5A, 0xFF, 0x01}, 0));
}

TEST(Pattern, OutOfRangeNeverReadsPastTheEnd) {
  const Pattern p = text_pattern("abc");
  const auto data = bytes_of("xxab");
  EXPECT_FALSE(p.matches_at(data, 2));
  EXPECT_FALSE(p.matches_at(data, 4));
  EXPECT_FALSE(p.matches_at(data, 1000));
}

TEST(Pattern, AtomIsLongestLiteralRunTruncated) {
  Pattern p;
  p.bytes = {1, 2, 0, 4, 5, 6, 0, 8};
  p.mask = {0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0, 0xFF};
  AtomChoice a = choose_atom(p, 32);
  EXPECT_EQ(a.offset, 3U);
  EXPECT_EQ(a.length, 3U);
  a = choose_atom(p, 2);
  EXPECT_EQ(a.offset, 3U);
  EXPECT_EQ(a.length, 2U);
  Pattern all_wild;
  all_wild.bytes = {0, 0};
  all_wild.mask = {0, 0};
  EXPECT_EQ(choose_atom(all_wild, 32).length, 0U);
  // Ties go to the earliest run.
  Pattern tie;
  tie.bytes = {1, 0, 2};
  tie.mask = {0xFF, 0, 0xFF};
  EXPECT_EQ(choose_atom(tie, 32).offset, 0U);
}

TEST(AhoCorasick, ClassicOverlappingDictionary) {
  AhoCorasick ac;
  const std::vector<std::string> words = {"he", "she", "his", "hers"};
  for (const auto& w : words) {
    ac.add(bytes_of(w));
  }
  ac.build(1U << 20U);
  std::set<std::pair<std::uint32_t, std::size_t>> found;
  ac.scan(bytes_of("ushers"),
          [&](std::uint32_t atom, std::size_t end) { found.emplace(atom, end); });
  const std::set<std::pair<std::uint32_t, std::size_t>> expected = {{1, 4}, {0, 4}, {3, 6}};
  EXPECT_EQ(found, expected);
  EXPECT_EQ(ac.state_count(), 10U);      // root + h,he,her,hers,hi,his,s,sh,she
  EXPECT_EQ(ac.alphabet_classes(), 6U);  // e,h,i,r,s + "other"
}

TEST(AhoCorasick, MatchesAreCaseFolded) {
  AhoCorasick ac;
  ac.add(bytes_of("AbC"));
  ac.build(1U << 20U);
  std::size_t hits = 0;
  ac.scan(bytes_of("abc ABC aBc"), [&](std::uint32_t, std::size_t) { ++hits; });
  EXPECT_EQ(hits, 3U);
}

TEST(AhoCorasick, EmptyAutomatonAndEmptyInput) {
  AhoCorasick ac;
  ac.build(1U << 20U);
  std::size_t hits = 0;
  ac.scan(bytes_of("anything"), [&](std::uint32_t, std::size_t) { ++hits; });
  EXPECT_EQ(hits, 0U);
  AhoCorasick one;
  one.add(bytes_of("x"));
  one.build(1U << 20U);
  one.scan(std::span<const std::uint8_t>(), [&](std::uint32_t, std::size_t) { ++hits; });
  EXPECT_EQ(hits, 0U);
}

TEST(AhoCorasick, TableBudgetIsEnforced) {
  AhoCorasick ac;
  ac.add(bytes_of(std::string(200, 'a') + "bcdefghij"));
  EXPECT_THROW(ac.build(1024), AutomatonTooLarge);
}

TEST(Ruleset, IdenticalAtomsAreShared) {
  const auto rs = test::compile_or_fail(R"(
    rule a { strings: $x = "Marker" $y = "marker" nocase condition: $x or $y }
    rule b { strings: $z = "MARKER" condition: $z })");
  ASSERT_NE(rs, nullptr);
  EXPECT_EQ(rs->stats().patterns, 3U);
  EXPECT_EQ(rs->stats().atoms, 1U);
  const auto hits = rs->find_hits(bytes_of("Marker MARKER"));
  // $x at 0; $y (nocase) at 0 and 7; $z at 7.
  EXPECT_EQ(hits.size(), 4U);
}

// Property test: the automaton plus verification finds exactly what the naive scanner finds,
// across random patterns (text, nocase, wide, hex with wildcards) and random haystacks over a
// small alphabet so that overlaps and near-misses are common.
TEST(Ruleset, AhoCorasickAgreesWithNaiveOnRandomInputs) {
  const std::string alphabet("aAbB\x00\xff", 6);
  for (std::uint32_t seed = 1; seed <= 60; ++seed) {
    std::mt19937 rng(seed);
    auto pick = [&](std::size_t n) { return static_cast<std::size_t>(rng() % n); };
    std::string src = "rule r { strings:\n";
    const std::size_t count = 1 + pick(8);
    for (std::size_t i = 0; i < count; ++i) {
      const std::size_t len = 1 + pick(6);
      src += "  $s" + std::to_string(i) + " = ";
      if (pick(3) == 0) {
        src += "{";
        for (std::size_t k = 0; k < len; ++k) {
          if (k > 0 && pick(3) == 0) {
            src += " ??";
          } else {
            static constexpr const char* kHex = "0123456789ABCDEF";
            const auto b = static_cast<unsigned char>(alphabet[pick(alphabet.size())]);
            src += std::string(" ") + kHex[b >> 4U] + kHex[b & 0xFU];
          }
        }
        src += " }\n";
      } else {
        src += "\"";
        for (std::size_t k = 0; k < len; ++k) {
          static constexpr const char* kHex = "0123456789abcdef";
          const auto b = static_cast<unsigned char>(alphabet[pick(alphabet.size())]);
          src += std::string("\\x") + kHex[b >> 4U] + kHex[b & 0xFU];
        }
        src += "\"";
        if (pick(2) == 0) {
          src += " nocase";
        }
        if (pick(3) == 0) {
          src += pick(2) == 0 ? " wide" : " wide ascii";
        }
        src += "\n";
      }
    }
    src += " condition: any of them }";

    RulesetBuilder builder;
    builder.add_source(src, "random.sig");
    const CompileResult compiled = builder.compile();
    ASSERT_NE(compiled.ruleset, nullptr) << src;
    const Ruleset& rs = *compiled.ruleset;

    std::vector<std::uint8_t> haystack(pick(400));
    for (auto& b : haystack) {
      b = static_cast<std::uint8_t>(alphabet[pick(alphabet.size())]);
    }
    EXPECT_EQ(rs.find_hits(haystack), naive_find_all(rs.patterns(), haystack))
        << "seed " << seed << "\n"
        << src;
  }
}

TEST(Ruleset, WideStringsBecomeUtf16LePatterns) {
  const auto rs = test::compile_or_fail(
      "rule r { strings: $w = \"ab\" wide $b = \"ab\" wide ascii condition: $w and $b }");
  ASSERT_NE(rs, nullptr);
  ASSERT_EQ(rs->patterns().size(), 3U);
  EXPECT_EQ(rs->patterns()[0].bytes, (std::vector<std::uint8_t>{'a', 0, 'b', 0}));
  EXPECT_TRUE(rs->patterns()[0].wide);
  EXPECT_EQ(rs->patterns()[1].bytes, (std::vector<std::uint8_t>{'a', 'b'}));
  EXPECT_EQ(rs->patterns()[2].bytes, (std::vector<std::uint8_t>{'a', 0, 'b', 0}));
}

TEST(Ruleset, SingleByteAnchorWarns) {
  RulesetBuilder builder;
  builder.add_source("rule r { strings: $h = { 41 ?? ?? } condition: $h }", "w.sig");
  const CompileResult result = builder.compile();
  ASSERT_NE(result.ruleset, nullptr);
  ASSERT_EQ(result.diagnostics.size(), 1U);
  EXPECT_EQ(result.diagnostics[0].level, DiagLevel::Warning);
  EXPECT_NE(result.diagnostics[0].message.find("anchored on a single byte"), std::string::npos);
}

TEST(Ruleset, OversizedAutomatonIsACompileError) {
  std::string src = "rule big { strings:\n";
  for (int i = 0; i < 50; ++i) {
    src += "  $s" + std::to_string(i) + " = \"" + std::string(30, static_cast<char>('a' + i % 26)) +
           std::to_string(i) + "\"\n";
  }
  src += " condition: any of them }";
  RulesetBuilder builder;
  builder.add_source(src, "big.sig");
  CompileOptions options;
  options.max_table_bytes = 4096;
  const CompileResult result = builder.compile(options);
  EXPECT_EQ(result.ruleset, nullptr);
  ASSERT_FALSE(result.diagnostics.empty());
  EXPECT_NE(result.diagnostics.back().message.find("automaton would need more than"),
            std::string::npos);
}

}  // namespace
}  // namespace sigscan
