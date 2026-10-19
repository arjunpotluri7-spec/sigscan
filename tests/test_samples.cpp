#include <gtest/gtest.h>

#include <map>
#include <set>
#include <string>

#include "sigscan/walker.hpp"
#include "test_util.hpp"

namespace sigscan {
namespace {

namespace fs = std::filesystem;

// Regression for the committed synthetic samples: exact rule matches per file, including the
// files that must not match anything.
TEST(Samples, ExpectedMatchesAndNonMatches) {
  RulesetBuilder builder;
  ASSERT_TRUE(builder.add_file(test::demo_rules()));
  const CompileResult compiled = builder.compile();
  ASSERT_NE(compiled.ruleset, nullptr);
  EXPECT_EQ(count_level(compiled.diagnostics, DiagLevel::Warning), 0U);

  const std::map<std::string, std::set<std::string>> expected = {
      {"archive/nested/beacon_copy.cfg", {"Demo_Beacon_Config"}},
      {"beacon.cfg", {"Demo_Beacon_Config"}},
      {"benign_allowlisted_note.txt", {}},
      {"benign_markers_partial.txt", {}},
      {"benign_near_miss.bin", {}},
      {"benign_random.bin", {}},
      {"benign_readme.txt", {}},
      {"dropper_note.txt", {"Demo_Dropper_Strings"}},
      {"dropper_stub.bin", {"Demo_Dropper_Strings"}},
      {"dropper_wide.bin", {"Demo_Dropper_Strings"}},
      {"markers.txt", {"Demo_Multi_Marker"}},
      {"packed_sample.bin", {"Demo_Packed_Header"}},
      {"ransom_note_utf16.txt", {"Demo_Ransom_Note_Text", "Demo_Unicode_Notice"}},
  };

  const fs::path root = test::sample_files();
  const WalkResult walked = collect_files({root}, WalkOptions{});
  ASSERT_EQ(walked.files.size(), expected.size());
  // Small chunks make the regression also exercise chunk-boundary handling on real files.
  for (const std::size_t chunk : {std::size_t{7}, std::size_t{1024 * 1024}}) {
    ScanOptions options;
    options.chunk_size = chunk;
    const Scanner scanner(compiled.ruleset, options);
    for (const WalkEntry& entry : walked.files) {
      const std::string rel = entry.path.lexically_relative(root).generic_string();
      const FileResult r = scanner.scan_file(entry.path, rel, false);
      ASSERT_EQ(r.status, FileStatus::Scanned) << rel << ": " << r.message;
      std::set<std::string> got;
      for (const auto& m : r.matches) {
        got.insert(compiled.ruleset->rules()[m.rule_index].name);
      }
      ASSERT_TRUE(expected.count(rel) == 1) << "unexpected sample file " << rel;
      EXPECT_EQ(got, expected.at(rel)) << rel << " (chunk " << chunk << ")";
    }
  }
}

TEST(Samples, DropperWideMatchesThroughTheCountBranch) {
  RulesetBuilder builder;
  ASSERT_TRUE(builder.add_file(test::demo_rules()));
  const CompileResult compiled = builder.compile();
  ASSERT_NE(compiled.ruleset, nullptr);
  const Scanner scanner(compiled.ruleset, ScanOptions{});
  const FileResult r =
      scanner.scan_file(fs::path(test::sample_files()) / "dropper_wide.bin", "w", false);
  ASSERT_EQ(r.matches.size(), 1U);
  EXPECT_EQ(r.matches[0].why,
            "matched because $a found at 0x0 and #d is 2 (>= 2); filesize 140 bytes < 5 MB");
}

}  // namespace
}  // namespace sigscan
