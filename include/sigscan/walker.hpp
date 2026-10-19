#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sigscan {

struct WalkOptions {
  bool follow_symlinks = false;  // include symlinked files met during the walk
  std::vector<std::string> skip_globs;
  std::size_t max_files = 100000;
};

struct WalkEntry {
  std::filesystem::path path;
  std::string display;  // generic (forward slash) path as shown in reports
  bool named_directly = false;
};

struct WalkError {
  std::string path;
  std::string message;
};

struct WalkResult {
  std::vector<WalkEntry> files;  // sorted by display path, unique
  std::vector<WalkError> errors;
  std::size_t skipped_symlinks = 0;
  std::size_t skipped_by_glob = 0;
  std::size_t skipped_special = 0;  // sockets, FIFOs, devices
  bool truncated = false;           // max_files was reached
};

// Glob over '/'-separated paths: `*` and `?` stay within one path segment, `**` crosses them.
[[nodiscard]] bool glob_match(std::string_view pattern, std::string_view text);

// Expands files and directories into a deterministic file list. Directory symlinks are never
// descended into, which also rules out symlink loops.
[[nodiscard]] WalkResult collect_files(const std::vector<std::filesystem::path>& roots,
                                       const WalkOptions& options);

}  // namespace sigscan
