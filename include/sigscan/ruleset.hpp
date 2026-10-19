#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "sigscan/aho_corasick.hpp"
#include "sigscan/ast.hpp"
#include "sigscan/diagnostics.hpp"
#include "sigscan/pattern.hpp"

namespace sigscan {

inline constexpr std::uint64_t kMaxRuleFileBytes = 4ULL * 1024 * 1024;

struct CompileOptions {
  std::size_t max_atom_length = 32;
  std::size_t max_table_bytes = 256ULL * 1024 * 1024;
};

struct CompiledString {
  std::string id;
  std::size_t rule_index = 0;
  std::size_t local_index = 0;
  std::vector<std::size_t> pattern_ids;
};

struct AtomRef {
  std::size_t pattern_id = 0;
  std::size_t offset_in_pattern = 0;
};

struct RulesetStats {
  std::size_t rules = 0;
  std::size_t strings = 0;
  std::size_t patterns = 0;
  std::size_t atoms = 0;
  std::size_t states = 0;
  std::size_t alphabet_classes = 0;
  std::size_t table_bytes = 0;
  std::size_t max_pattern_length = 0;
};

class Ruleset {
 public:
  [[nodiscard]] const std::vector<Rule>& rules() const { return rules_; }
  [[nodiscard]] const std::vector<CompiledString>& strings() const { return strings_; }
  [[nodiscard]] const std::vector<Pattern>& patterns() const { return patterns_; }
  [[nodiscard]] const AhoCorasick& automaton() const { return automaton_; }
  [[nodiscard]] const std::vector<AtomRef>& atom_refs(std::uint32_t atom) const {
    return atom_refs_[atom];
  }
  [[nodiscard]] std::size_t first_string(std::size_t rule_index) const {
    return rule_first_string_[rule_index];
  }
  [[nodiscard]] std::size_t max_pattern_length() const { return max_pattern_length_; }
  [[nodiscard]] RulesetStats stats() const;

  // Every verified pattern occurrence in one buffer, sorted. Same contract as naive_find_all,
  // which makes the two engines directly comparable.
  [[nodiscard]] std::vector<Hit> find_hits(std::span<const std::uint8_t> data) const;

  // Calls on_hit(pattern_id, start) for every verified occurrence in `data`.
  template <typename OnHit>
  void for_each_hit(std::span<const std::uint8_t> data, const OnHit& on_hit) const {
    automaton_.scan(data, [&](std::uint32_t atom, std::size_t end) {
      const std::size_t atom_len = automaton_.atom_length(atom);
      const std::size_t atom_start = end - atom_len;
      for (const AtomRef& ref : atom_refs_[atom]) {
        if (atom_start < ref.offset_in_pattern) {
          continue;
        }
        const std::size_t start = atom_start - ref.offset_in_pattern;
        const Pattern& pattern = patterns_[ref.pattern_id];
        if (pattern.size() > data.size() - start) {
          continue;
        }
        if (pattern.matches_at(data, start)) {
          on_hit(ref.pattern_id, start);
        }
      }
    });
  }

 private:
  friend class RulesetBuilder;

  std::vector<Rule> rules_;
  std::vector<std::size_t> rule_first_string_;
  std::vector<CompiledString> strings_;
  std::vector<Pattern> patterns_;
  std::vector<std::vector<AtomRef>> atom_refs_;
  AhoCorasick automaton_;
  std::size_t max_pattern_length_ = 0;
};

struct CompileResult {
  std::shared_ptr<const Ruleset> ruleset;  // null on error
  std::vector<Diagnostic> diagnostics;     // everything collected while loading and compiling
};

// Collects rule sources (possibly from several files), checks names are unique across them,
// then compiles everything into one automaton.
class RulesetBuilder {
 public:
  // Returns false if this source had errors (diagnostics are kept either way).
  bool add_source(std::string_view source, std::string_view filename);
  bool add_file(const std::filesystem::path& path);

  [[nodiscard]] const std::vector<Diagnostic>& diagnostics() const { return diagnostics_; }
  [[nodiscard]] bool has_errors() const { return sigscan::has_errors(diagnostics_); }
  [[nodiscard]] std::size_t rule_count() const { return rules_.size(); }

  // Consumes the collected rules. Fails if any source had errors.
  [[nodiscard]] CompileResult compile(const CompileOptions& options = {});

 private:
  std::vector<Rule> rules_;
  std::vector<Diagnostic> diagnostics_;
  std::map<std::string, SourceLocation, std::less<>> names_;
};

}  // namespace sigscan
