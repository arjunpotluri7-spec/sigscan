#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "sigscan/ruleset.hpp"
#include "sigscan/scanner.hpp"

namespace sigscan {

inline constexpr int kJsonSchemaVersion = 1;

struct ScanSummary {
  std::size_t files_scanned = 0;
  std::size_t files_matched = 0;
  std::size_t matches = 0;
  std::size_t skipped = 0;
  std::size_t errors = 0;
  std::uint64_t bytes_scanned = 0;
};

struct ScanReport {
  std::vector<std::string> rule_files;
  std::vector<FileResult> files;  // deterministic order (sorted by path)
  bool truncated = false;         // --max-files was reached
};

[[nodiscard]] ScanSummary summarize(const ScanReport& report);

// Hex dump "53 49 47" and a printable rendering "SIG" ('.' for non-printable bytes).
[[nodiscard]] std::string hex_bytes(const std::vector<std::uint8_t>& bytes);
[[nodiscard]] std::string printable_bytes(const std::vector<std::uint8_t>& bytes);

void write_table(std::ostream& out, const ScanReport& report, const Ruleset& ruleset,
                 bool show_strings);
void write_json(std::ostream& out, const ScanReport& report, const Ruleset& ruleset,
                bool show_strings);
void write_sarif(std::ostream& out, const ScanReport& report, const Ruleset& ruleset);

}  // namespace sigscan
