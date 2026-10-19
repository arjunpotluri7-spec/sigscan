#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "sigscan/scanner.hpp"
#include "test_util.hpp"

namespace sigscan {
namespace {

using test::compile_or_fail;
using test::matched;
using test::scan_text;

std::string utf16(std::string_view ascii) {
  std::string out;
  for (const char c : ascii) {
    out += c;
    out += '\0';
  }
  return out;
}

const StringReport* find_string(const FileResult& r, std::string_view id) {
  for (const auto& m : r.matches) {
    for (const auto& s : m.strings) {
      if (s.id == id) {
        return &s;
      }
    }
  }
  return nullptr;
}

// Condition evaluated against a fixed haystack; returns whether rule "r" matched.
bool cond(std::string_view strings, std::string_view condition, std::string_view data) {
  const std::string section = strings.empty() ? "" : "strings:\n" + std::string(strings);
  const auto rs =
      compile_or_fail("rule r { " + section + "\n condition: " + std::string(condition) + " }");
  if (!rs) {
    return false;
  }
  return matched(scan_text(rs, data), "r", *rs);
}

TEST(Scanner, PatternsAcrossEveryChunkBoundaryAreFoundOnce) {
  const auto rs = compile_or_fail(R"(rule r { strings:
      $t = "BOUNDARY-MARKER"
      $h = { 42 4F ?? 4E 44 }
      $w = "wide" wide
      $n = "NoCase" nocase
    condition: any of them })");
  ASSERT_NE(rs, nullptr);
  const std::string payload = "BOUNDARY-MARKER" + utf16("wide") + "nocase";
  for (std::size_t prefix = 0; prefix < 24; ++prefix) {
    const std::string data = std::string(prefix, '.') + payload + std::string(5, '.');
    for (std::size_t chunk = 1; chunk <= 40; ++chunk) {
      ScanOptions options;
      options.chunk_size = chunk;
      const FileResult r = scan_text(rs, data, options);
      ASSERT_EQ(r.matches.size(), 1U) << "prefix " << prefix << " chunk " << chunk;
      const auto* t = find_string(r, "$t");
      const auto* h = find_string(r, "$h");
      const auto* w = find_string(r, "$w");
      const auto* n = find_string(r, "$n");
      ASSERT_TRUE(t && h && w && n) << "prefix " << prefix << " chunk " << chunk;
      EXPECT_EQ(t->hits.count, 1U);
      EXPECT_EQ(t->hits.matches.front().offset, prefix);
      EXPECT_EQ(h->hits.count, 1U);
      EXPECT_EQ(w->hits.matches.front().offset, prefix + 15);
      EXPECT_EQ(n->hits.matches.front().offset, prefix + 15 + 8);
      EXPECT_EQ(r.size, data.size());
    }
  }
}

TEST(Scanner, ChunkBoundaryInRealFile) {
  const auto rs =
      compile_or_fail("rule r { strings: $a = \"SPLIT-ACROSS-CHUNKS\" condition: #a == 3 }");
  ASSERT_NE(rs, nullptr);
  test::TempDir dir;
  // 64 KiB chunks; place one marker straddling each of the first three boundaries.
  std::string data(3 * 65536 + 100, 'x');
  for (std::size_t k = 1; k <= 3; ++k) {
    data.replace(k * 65536 - 7, 19, "SPLIT-ACROSS-CHUNKS");
  }
  test::write_file(dir / "big.bin", data);
  ScanOptions options;
  options.chunk_size = 65536;
  const Scanner scanner(rs, options);
  const FileResult r = scanner.scan_file(dir / "big.bin", "big.bin", true);
  ASSERT_EQ(r.status, FileStatus::Scanned) << r.message;
  ASSERT_EQ(r.matches.size(), 1U);
  const auto& hits = r.matches[0].strings[0].hits;
  ASSERT_EQ(hits.matches.size(), 3U);
  EXPECT_EQ(hits.matches[0].offset, 65536U - 7);
  EXPECT_EQ(hits.matches[2].offset, 3U * 65536 - 7);
}

TEST(Scanner, OverlappingOccurrencesAreAllCounted) {
  const auto rs = compile_or_fail("rule r { strings: $a = \"aa\" condition: #a == 4 }");
  ASSERT_NE(rs, nullptr);
  for (std::size_t chunk = 1; chunk <= 6; ++chunk) {
    ScanOptions options;
    options.chunk_size = chunk;
    EXPECT_TRUE(matched(scan_text(rs, "aaaaa", options), "r", *rs)) << chunk;
  }
}

TEST(Scanner, BooleanOperators) {
  const std::string s = "  $a = \"alpha\"\n  $b = \"beta\"";
  EXPECT_TRUE(cond(s, "$a and $b", "alpha beta"));
  EXPECT_FALSE(cond(s, "$a and $b", "alpha"));
  EXPECT_TRUE(cond(s, "$a or $b", "beta"));
  EXPECT_FALSE(cond(s, "$a or $b", "gamma"));
  EXPECT_TRUE(cond(s, "$a and not $b", "alpha"));
  EXPECT_FALSE(cond(s, "not ($a or $b)", "beta"));
  EXPECT_TRUE(cond(s, "($a or $b) and not ($a and $b)", "alpha"));
  EXPECT_TRUE(cond(s, "true or $a and $b", "nothing"));
  EXPECT_FALSE(cond(s, "false and ($a or $b)", "alpha beta"));
}

TEST(Scanner, CountComparisons) {
  const std::string s = "  $a = \"x\"";
  const std::string data = "x-x-x";
  EXPECT_TRUE(cond(s, "#a == 3", data));
  EXPECT_FALSE(cond(s, "#a == 2", data));
  EXPECT_TRUE(cond(s, "#a != 2", data));
  EXPECT_TRUE(cond(s, "#a < 4", data));
  EXPECT_FALSE(cond(s, "#a < 3", data));
  EXPECT_TRUE(cond(s, "#a <= 3", data));
  EXPECT_TRUE(cond(s, "#a > 2", data));
  EXPECT_FALSE(cond(s, "#a > 3", data));
  EXPECT_TRUE(cond(s, "#a >= 3", data));
  EXPECT_TRUE(cond(s, "#a == 0", "none here"));
}

TEST(Scanner, AtAndInUseExactOffsets) {
  const std::string s = "  $a = \"MZ\"";
  EXPECT_TRUE(cond(s, "$a at 0", "MZ...."));
  EXPECT_FALSE(cond(s, "$a at 0", ".MZ..."));
  EXPECT_TRUE(cond(s, "$a at 1", ".MZ..."));
  EXPECT_TRUE(cond(s, "$a at 0x4", "....MZ"));
  EXPECT_TRUE(cond(s, "$a in (2..4)", "....MZ"));
  EXPECT_TRUE(cond(s, "$a in (4..4)", "....MZ"));
  EXPECT_FALSE(cond(s, "$a in (0..3)", "....MZ"));
  EXPECT_FALSE(cond(s, "$a in (5..100)", "....MZ"));
  EXPECT_TRUE(cond(s, "$a in (5..100)", "....MZ..MZ"));
}

TEST(Scanner, FilesizeComparisonsWithSuffixes) {
  const std::string data(2048, 'z');
  EXPECT_TRUE(cond("", "filesize == 2KB", data));
  EXPECT_TRUE(cond("", "filesize < 1MB", data));
  EXPECT_FALSE(cond("", "filesize > 2KB", data));
  EXPECT_TRUE(cond("", "filesize >= 2048", data));
  EXPECT_TRUE(cond("", "filesize <= 2KB", data));
  EXPECT_TRUE(cond("", "filesize != 0", data));
  EXPECT_TRUE(cond("", "filesize == 0", ""));
}

TEST(Scanner, QuantifiersAndSets) {
  const std::string s = "  $p1 = \"one\"\n  $p2 = \"two\"\n  $q = \"three\"";
  EXPECT_TRUE(cond(s, "any of them", "two"));
  EXPECT_FALSE(cond(s, "any of them", "zzz"));
  EXPECT_TRUE(cond(s, "all of them", "one two three"));
  EXPECT_FALSE(cond(s, "all of them", "one two"));
  EXPECT_TRUE(cond(s, "2 of them", "one three"));
  EXPECT_FALSE(cond(s, "3 of them", "one three"));
  EXPECT_TRUE(cond(s, "all of ($p*)", "one two"));
  EXPECT_FALSE(cond(s, "all of ($p*)", "one three"));
  EXPECT_TRUE(cond(s, "any of ($p1, $q)", "three"));
  EXPECT_TRUE(cond(s, "2 of ($p*, $q)", "two three"));
  EXPECT_TRUE(cond(s, "all of ($*)", "one two three"));
}

TEST(Scanner, NocaseWideAndHexVerification) {
  EXPECT_TRUE(cond("  $a = \"Connect-Back\" nocase", "$a", "xx CONNECT-back xx"));
  EXPECT_FALSE(cond("  $a = \"Connect-Back\"", "$a", "xx CONNECT-back xx"));
  EXPECT_TRUE(cond("  $w = \"evil\" wide", "$w", utf16("an evil host")));
  EXPECT_FALSE(cond("  $w = \"evil\" wide", "$w", "an evil host"));
  EXPECT_TRUE(cond("  $w = \"evil\" wide ascii", "$w", "an evil host"));
  EXPECT_TRUE(cond("  $w = \"EVIL\" wide nocase", "$w", utf16("an Evil host")));
  EXPECT_TRUE(cond("  $h = { 4D 5A ?? 00 DE AD ?? EF }", "$h",
                   std::string("\x4D\x5A\x90\x00\xDE\xAD\xBE\xEF", 8)));
  EXPECT_FALSE(cond("  $h = { 4D 5A ?? 00 DE AD ?? EF }", "$h",
                    std::string("\x4D\x5A\x90\x01\xDE\xAD\xBE\xEF", 8)));
}

TEST(Scanner, AsciiAndWideAtSameOffsetCountOnce) {
  const auto rs = compile_or_fail("rule r { strings: $a = \"q\" ascii wide condition: #a == 1 }");
  ASSERT_NE(rs, nullptr);
  EXPECT_TRUE(matched(scan_text(rs, std::string("q\0", 2)), "r", *rs));
}

TEST(Scanner, OffsetCapKeepsCountsExact) {
  const auto rs = compile_or_fail("rule r { strings: $a = \"x\" condition: #a == 50 }");
  ASSERT_NE(rs, nullptr);
  ScanOptions options;
  options.max_matches_per_string = 10;
  const FileResult r = scan_text(rs, std::string(50, 'x'), options);
  ASSERT_EQ(r.matches.size(), 1U);
  EXPECT_EQ(r.matches[0].strings[0].hits.count, 50U);
  EXPECT_EQ(r.matches[0].strings[0].hits.matches.size(), 10U);
}

TEST(Scanner, SnippetsCarryContext) {
  const auto rs = compile_or_fail("rule r { strings: $a = \"KEY\" condition: $a }");
  ASSERT_NE(rs, nullptr);
  const FileResult r = scan_text(rs, "0123456789KEYabcdefghij");
  ASSERT_EQ(r.matches.size(), 1U);
  const MatchRecord& m = r.matches[0].strings[0].hits.matches[0];
  EXPECT_EQ(m.offset, 10U);
  EXPECT_EQ(m.length, 3U);
  EXPECT_EQ(m.context_offset, 6U);
  EXPECT_EQ(std::string(m.context.begin(), m.context.end()), "6789KEYabcd");
}

TEST(Scanner, WhyExplainsTheSpecExample) {
  const auto rs = compile_or_fail(R"(rule Demo : dropper {
    strings:
      $a = "SIGSCAN-DEMO-PAYLOAD"
      $b = "connect-back" nocase
      $c = { 4D 5A ?? 00 DE AD ?? EF }
      $d = "evil.example.net" wide
    condition:
      $a and (any of ($b, $c) or #d >= 2) and filesize < 5MB })");
  ASSERT_NE(rs, nullptr);
  std::string data(0x1a0, '.');
  data += "SIGSCAN-DEMO-PAYLOAD .. Connect-Back .. ";
  data += std::string("\x4D\x5A\x01\x00\xDE\xAD\x02\xEF", 8);
  data += std::string(4096, ' ');
  const FileResult r = scan_text(rs, data);
  ASSERT_EQ(r.matches.size(), 1U);
  EXPECT_EQ(r.matches[0].why,
            "matched because $a found at 0x1a0 and 2 of ($b, $c) found; "
            "filesize 4.5 KB < 5 MB");
}

TEST(Scanner, WhyForCountsNotAtInAndPartialSets) {
  const auto rs = compile_or_fail(R"(rule r {
    strings:
      $a = "aa"
      $b = "bb"
      $c = "cc"
      $z = "zz"
    condition:
      #a >= 2 and $b at 0x2 and $c in (0..64) and 1 of ($b, $z) and not $z })");
  ASSERT_NE(rs, nullptr);
  const FileResult r = scan_text(rs, "a bb cc aa aa");
  ASSERT_EQ(r.matches.size(), 1U);
  EXPECT_EQ(r.matches[0].why,
            "matched because #a is 2 (>= 2) and $b at 0x2 and $c found at 0x5 within (0..64) "
            "and 1 of ($b, $z) found ($b) and $z not found");
}

TEST(Scanner, OversizedFileIsSkippedNotFatal) {
  const auto rs = compile_or_fail("rule r { condition: true }");
  ASSERT_NE(rs, nullptr);
  test::TempDir dir;
  test::write_file(dir / "big.bin", std::string(5000, 'a'));
  ScanOptions options;
  options.max_filesize = 4096;
  const Scanner scanner(rs, options);
  const FileResult r = scanner.scan_file(dir / "big.bin", "big.bin", true);
  EXPECT_EQ(r.status, FileStatus::Skipped);
  EXPECT_EQ(r.message, "file is 4.9 KB, above the --max-filesize limit of 4.0 KB");
  EXPECT_TRUE(r.matches.empty());
}

TEST(Scanner, BufferLargerThanCapIsSkipped) {
  const auto rs = compile_or_fail("rule r { condition: true }");
  ASSERT_NE(rs, nullptr);
  ScanOptions options;
  options.max_filesize = 10;
  options.chunk_size = 4;
  const FileResult r = scan_text(rs, std::string(11, 'a'), options);
  EXPECT_EQ(r.status, FileStatus::Skipped);
  EXPECT_NE(r.message.find("grew while reading"), std::string::npos);
}

TEST(Scanner, MissingAndSpecialFilesAreErrors) {
  const auto rs = compile_or_fail("rule r { condition: true }");
  ASSERT_NE(rs, nullptr);
  const Scanner scanner(rs, ScanOptions{});
  const FileResult missing = scanner.scan_file("/nonexistent/sigscan.bin", "missing", true);
  EXPECT_EQ(missing.status, FileStatus::Error);
  EXPECT_NE(missing.message.find("cannot open"), std::string::npos);
  test::TempDir dir;
  const FileResult directory = scanner.scan_file(dir.path(), "dir", true);
  EXPECT_EQ(directory.status, FileStatus::Error);
}

TEST(Scanner, EmptyFileStillEvaluatesFilesizeRules) {
  const auto rs = compile_or_fail(
      "rule empty { condition: filesize == 0 } rule any_s { strings: $a = \"a\" condition: $a }");
  ASSERT_NE(rs, nullptr);
  const FileResult r = scan_text(rs, "");
  ASSERT_EQ(r.matches.size(), 1U);
  EXPECT_EQ(r.matches[0].why, "matched because filesize 0 bytes == 0 bytes");
}

TEST(Scanner, FormatSize) {
  EXPECT_EQ(format_size(0), "0 bytes");
  EXPECT_EQ(format_size(1), "1 byte");
  EXPECT_EQ(format_size(1023), "1023 bytes");
  EXPECT_EQ(format_size(1536), "1.5 KB");
  EXPECT_EQ(format_size(5ULL * 1024 * 1024), "5.0 MB");
  EXPECT_EQ(format_size(3ULL * 1024 * 1024 * 1024), "3.0 GB");
}

}  // namespace
}  // namespace sigscan
