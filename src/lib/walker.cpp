#include "sigscan/walker.hpp"

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace sigscan {
namespace fs = std::filesystem;

bool glob_match(std::string_view pattern, std::string_view text) {
  // Bottom-up DP: ok[i][j] is true when pattern[i:] matches text[j:]. Paths and globs are short,
  // and this stays linear in their product however many stars the glob has.
  const std::size_t m = pattern.size();
  const std::size_t n = text.size();
  std::vector<std::vector<char>> ok(m + 1, std::vector<char>(n + 1, 0));
  ok[m][n] = 1;
  for (std::size_t i = m; i-- > 0;) {
    const bool double_star = pattern[i] == '*' && i + 1 < m && pattern[i + 1] == '*';
    for (std::size_t j = n + 1; j-- > 0;) {
      const bool more = j < n;
      bool v = false;
      if (double_star) {
        const std::size_t k = i + 2;
        v = ok[k][j] != 0 || (more && ok[i][j + 1] != 0);
        if (!v && k < m && pattern[k] == '/') {
          v = ok[k + 1][j] != 0;  // "**/" also matches zero directories
        }
      } else if (pattern[i] == '*') {
        v = ok[i + 1][j] != 0 || (more && text[j] != '/' && ok[i][j + 1] != 0);
      } else if (pattern[i] == '?') {
        v = more && text[j] != '/' && ok[i + 1][j + 1] != 0;
      } else {
        v = more && pattern[i] == text[j] && ok[i + 1][j + 1] != 0;
      }
      ok[i][j] = v ? 1 : 0;
    }
  }
  return ok[0][0] != 0;
}

namespace {

bool skipped_by_glob(const std::vector<std::string>& globs, const std::string& relative,
                     const std::string& name) {
  return std::any_of(globs.begin(), globs.end(), [&](const std::string& g) {
    return glob_match(g, relative) || glob_match(g, name);
  });
}

}  // namespace

WalkResult collect_files(const std::vector<fs::path>& roots, const WalkOptions& options) {
  WalkResult result;
  std::set<std::string> seen;
  auto add = [&](const fs::path& path, bool named) {
    if (result.files.size() >= options.max_files) {
      result.truncated = true;
      return false;
    }
    std::string display = path.generic_string();
    if (seen.insert(display).second) {
      result.files.push_back(WalkEntry{path, std::move(display), named});
    }
    return true;
  };

  for (const fs::path& root : roots) {
    if (result.truncated) {
      break;
    }
    std::error_code ec;
    const fs::file_status status = fs::status(root, ec);
    if (ec || !fs::exists(status)) {
      result.errors.push_back(WalkError{root.generic_string(), "path not found"});
      continue;
    }
    if (!fs::is_directory(status)) {
      if (fs::is_regular_file(status)) {
        add(root, true);
      } else {
        ++result.skipped_special;
        result.errors.push_back(WalkError{root.generic_string(), "not a regular file"});
      }
      continue;
    }

    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
      result.errors.push_back(WalkError{root.generic_string(), ec.message()});
      continue;
    }
    for (const fs::recursive_directory_iterator end; it != end; it.increment(ec)) {
      if (ec) {
        result.errors.push_back(WalkError{root.generic_string(), ec.message()});
        break;
      }
      const fs::directory_entry& entry = *it;
      const fs::path& path = entry.path();
      const std::string relative = path.lexically_relative(root).generic_string();
      const std::string name = path.filename().generic_string();
      std::error_code entry_ec;
      const bool is_link = entry.is_symlink(entry_ec);
      if (skipped_by_glob(options.skip_globs, relative, name)) {
        ++result.skipped_by_glob;
        if (!is_link && entry.is_directory(entry_ec)) {
          it.disable_recursion_pending();
        }
        continue;
      }
      if (is_link) {
        // Directory symlinks are never followed (the iterator does not descend into them).
        if (!options.follow_symlinks || !entry.is_regular_file(entry_ec)) {
          ++result.skipped_symlinks;
          continue;
        }
        if (!add(path, false)) {
          break;
        }
        continue;
      }
      if (entry.is_directory(entry_ec)) {
        continue;
      }
      if (!entry.is_regular_file(entry_ec)) {
        ++result.skipped_special;
        continue;
      }
      if (!add(path, false)) {
        break;
      }
    }
  }

  std::sort(result.files.begin(), result.files.end(),
            [](const WalkEntry& a, const WalkEntry& b) { return a.display < b.display; });
  return result;
}

}  // namespace sigscan
