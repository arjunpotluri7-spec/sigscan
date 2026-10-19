#include "sigscan/diagnostics.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "sigscan/ast.hpp"

namespace sigscan {

std::string Diagnostic::format() const {
  std::string out = loc.file;
  if (loc.line > 0) {
    out += ':';
    out += std::to_string(loc.line);
    out += ':';
    out += std::to_string(loc.column);
  }
  out += level == DiagLevel::Error ? ": error: " : ": warning: ";
  out += message;
  if (!source_line.empty()) {
    out += '\n';
    out += source_line;
    out += '\n';
    // Reuse tabs from the source so the caret lines up in any tab width.
    const std::size_t col = loc.column == 0 ? 0 : loc.column - 1;
    for (std::size_t i = 0; i < col && i < source_line.size(); ++i) {
      out += source_line[i] == '\t' ? '\t' : ' ';
    }
    out += '^';
  }
  return out;
}

bool has_errors(const std::vector<Diagnostic>& diagnostics) {
  return std::any_of(diagnostics.begin(), diagnostics.end(),
                     [](const Diagnostic& d) { return d.level == DiagLevel::Error; });
}

std::size_t count_level(const std::vector<Diagnostic>& diagnostics, DiagLevel level) {
  return static_cast<std::size_t>(
      std::count_if(diagnostics.begin(), diagnostics.end(),
                    [level](const Diagnostic& d) { return d.level == level; }));
}

const char* severity_name(Severity severity) {
  switch (severity) {
    case Severity::Low:
      return "low";
    case Severity::Medium:
      return "medium";
    case Severity::High:
      return "high";
    case Severity::Critical:
      return "critical";
  }
  return "medium";
}

std::optional<Severity> parse_severity(std::string_view text) {
  if (text == "low") {
    return Severity::Low;
  }
  if (text == "medium") {
    return Severity::Medium;
  }
  if (text == "high") {
    return Severity::High;
  }
  if (text == "critical") {
    return Severity::Critical;
  }
  return std::nullopt;
}

const char* cmp_op_text(CmpOp op) {
  switch (op) {
    case CmpOp::Eq:
      return "==";
    case CmpOp::Ne:
      return "!=";
    case CmpOp::Lt:
      return "<";
    case CmpOp::Le:
      return "<=";
    case CmpOp::Gt:
      return ">";
    case CmpOp::Ge:
      return ">=";
  }
  return "==";
}

bool compare(std::uint64_t lhs, CmpOp op, std::uint64_t rhs) {
  switch (op) {
    case CmpOp::Eq:
      return lhs == rhs;
    case CmpOp::Ne:
      return lhs != rhs;
    case CmpOp::Lt:
      return lhs < rhs;
    case CmpOp::Le:
      return lhs <= rhs;
    case CmpOp::Gt:
      return lhs > rhs;
    case CmpOp::Ge:
      return lhs >= rhs;
  }
  return false;
}

const MetaEntry* Rule::find_meta(std::string_view key) const {
  for (const MetaEntry& entry : meta) {
    if (entry.key == key) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace sigscan
