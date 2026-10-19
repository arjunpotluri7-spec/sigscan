#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "sigscan/walker.hpp"
#include "test_util.hpp"

namespace sigscan {
namespace {

namespace fs = std::filesystem;

std::vector<std::string> relative_names(const WalkResult& r, const fs::path& root) {
  std::vector<std::string> names;
  for (const auto& f : r.files) {
    names.push_back(f.path.lexically_relative(root).generic_string());
  }
  return names;
}

TEST(Glob, StarsQuestionMarksAndDoubleStars) {
  EXPECT_TRUE(glob_match("*.log", "app.log"));
  EXPECT_FALSE(glob_match("*.log", "dir/app.log"));
  EXPECT_TRUE(glob_match("**/*.log", "dir/sub/app.log"));
  EXPECT_TRUE(glob_match("**/*.log", "app.log"));
  EXPECT_TRUE(glob_match("build/**", "build/a/b/c.o"));
  EXPECT_TRUE(glob_match("a?c", "abc"));
  EXPECT_FALSE(glob_match("a?c", "a/c"));
  EXPECT_TRUE(glob_match("*", "anything"));
  EXPECT_FALSE(glob_match("*", "a/b"));
  EXPECT_TRUE(glob_match("**", "a/b"));
  EXPECT_TRUE(glob_match(".git", ".git"));
  EXPECT_FALSE(glob_match("abc", "abcd"));
  EXPECT_TRUE(glob_match("a*b*c", "aXXbYYc"));
  EXPECT_FALSE(glob_match("a*b*c", "aXXbYY"));
  EXPECT_TRUE(glob_match("", ""));
}

TEST(Walker, RecursesAndSortsDeterministically) {
  test::TempDir dir;
  test::write_file(dir / "b.txt", "b");
  test::write_file(dir / "a/z.txt", "z");
  test::write_file(dir / "a/deep/y.txt", "y");
  const WalkResult r = collect_files({dir.path()}, WalkOptions{});
  EXPECT_EQ(relative_names(r, dir.path()),
            (std::vector<std::string>{"a/deep/y.txt", "a/z.txt", "b.txt"}));
  EXPECT_TRUE(r.errors.empty());
  EXPECT_FALSE(r.truncated);
}

TEST(Walker, SymlinksAreNotFollowedByDefault) {
  test::TempDir dir;
  test::TempDir outside;
  test::write_file(dir / "real.txt", "r");
  test::write_file(outside / "secret.txt", "s");
  fs::create_symlink(outside / "secret.txt", dir / "link.txt");
  fs::create_directory_symlink(outside.path(), dir / "linkdir");
  const WalkResult r = collect_files({dir.path()}, WalkOptions{});
  EXPECT_EQ(relative_names(r, dir.path()), (std::vector<std::string>{"real.txt"}));
  EXPECT_EQ(r.skipped_symlinks, 2U);
}

TEST(Walker, FollowSymlinksIncludesFilesButNeverDirectories) {
  test::TempDir dir;
  test::TempDir outside;
  test::write_file(dir / "real.txt", "r");
  test::write_file(outside / "secret.txt", "s");
  fs::create_symlink(outside / "secret.txt", dir / "link.txt");
  fs::create_directory_symlink(outside.path(), dir / "linkdir");
  fs::create_directory_symlink(dir.path(), dir / "loop");
  WalkOptions options;
  options.follow_symlinks = true;
  const WalkResult r = collect_files({dir.path()}, options);
  EXPECT_EQ(relative_names(r, dir.path()), (std::vector<std::string>{"link.txt", "real.txt"}));
  EXPECT_EQ(r.skipped_symlinks, 2U);
}

TEST(Walker, SkipGlobsMatchNamesAndRelativePathsAndPruneDirectories) {
  test::TempDir dir;
  test::write_file(dir / "keep.txt", "k");
  test::write_file(dir / "drop.log", "d");
  test::write_file(dir / ".git/objects/x", "x");
  test::write_file(dir / "src/vendor/lib.c", "v");
  test::write_file(dir / "src/main.c", "m");
  WalkOptions options;
  options.skip_globs = {"*.log", ".git", "src/vendor"};
  const WalkResult r = collect_files({dir.path()}, options);
  EXPECT_EQ(relative_names(r, dir.path()), (std::vector<std::string>{"keep.txt", "src/main.c"}));
  EXPECT_EQ(r.skipped_by_glob, 3U);
}

TEST(Walker, MaxFilesTruncates) {
  test::TempDir dir;
  for (int i = 0; i < 5; ++i) {
    test::write_file(dir / ("f" + std::to_string(i)), "x");
  }
  WalkOptions options;
  options.max_files = 3;
  const WalkResult r = collect_files({dir.path()}, options);
  EXPECT_EQ(r.files.size(), 3U);
  EXPECT_TRUE(r.truncated);
}

TEST(Walker, NamedFilesAndMissingPaths) {
  test::TempDir dir;
  test::write_file(dir / "one.txt", "1");
  const WalkResult r =
      collect_files({dir / "one.txt", dir / "missing.txt", dir / "one.txt"}, WalkOptions{});
  ASSERT_EQ(r.files.size(), 1U);
  EXPECT_TRUE(r.files[0].named_directly);
  ASSERT_EQ(r.errors.size(), 1U);
  EXPECT_EQ(r.errors[0].message, "path not found");
}

TEST(Walker, ScannerRefusesSymlinkSwappedInAfterWalk) {
  // Simulates a race: the walker saw a regular file, which is then replaced by a symlink.
  test::TempDir dir;
  test::TempDir outside;
  test::write_file(outside / "target.txt", "SIGSCAN-DEMO-PAYLOAD");
  fs::create_symlink(outside / "target.txt", dir / "swapped.txt");
  const auto rs = test::compile_or_fail("rule r { condition: true }");
  ASSERT_NE(rs, nullptr);
  const Scanner scanner(rs, ScanOptions{});
  const FileResult r = scanner.scan_file(dir / "swapped.txt", "swapped.txt", false);
  EXPECT_EQ(r.status, FileStatus::Error);
  EXPECT_EQ(r.message, "refusing to follow symlink");
}

}  // namespace
}  // namespace sigscan
