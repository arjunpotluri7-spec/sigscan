#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

#include "sigscan/ast.hpp"
#include "sigscan/diagnostics.hpp"

namespace sigscan {

inline constexpr std::size_t kMaxConditionDepth = 64;
inline constexpr std::size_t kMaxDiagnosticsPerFile = 50;

struct ParseOutput {
  std::vector<Rule> rules;  // only rules that parsed without errors
  std::vector<Diagnostic> diagnostics;
};

// Parses one rule source. Errors inside a rule drop that rule and parsing resumes at the next
// `rule` keyword, so one run reports several problems. Duplicate rule names across files are
// detected by RulesetBuilder, not here.
[[nodiscard]] ParseOutput parse_rules(std::string_view source, std::string_view filename);

}  // namespace sigscan
