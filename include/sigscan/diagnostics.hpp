#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sigscan {

inline constexpr const char* kVersion = "0.1.0";

struct SourceLocation {
  std::string file;
  std::uint32_t line = 0;    // 1-based
  std::uint32_t column = 0;  // 1-based, in bytes
};

enum class DiagLevel { Error, Warning };

struct Diagnostic {
  DiagLevel level = DiagLevel::Error;
  SourceLocation loc;
  std::string message;
  std::string source_line;  // the offending line without its newline, may be empty

  // "file:line:col: error: message" followed by the source line and a caret line.
  [[nodiscard]] std::string format() const;
};

[[nodiscard]] bool has_errors(const std::vector<Diagnostic>& diagnostics);
[[nodiscard]] std::size_t count_level(const std::vector<Diagnostic>& diagnostics, DiagLevel level);

}  // namespace sigscan
