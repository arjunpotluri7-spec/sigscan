#pragma once

#include <ostream>
#include <string>
#include <vector>

namespace sigscan::cli {

inline constexpr int kExitOk = 0;
inline constexpr int kExitFindings = 1;
inline constexpr int kExitUsage = 2;

// Runs the command line (without the program name). Reports go to `out`, logs and diagnostics
// to `err`. Returns the process exit code.
int run(const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

}  // namespace sigscan::cli
