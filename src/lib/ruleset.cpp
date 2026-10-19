#include "sigscan/ruleset.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "sigscan/file_io.hpp"
#include "sigscan/lexer.hpp"
#include "sigscan/parser.hpp"

namespace sigscan {
namespace {

std::string format_loc(const SourceLocation& loc) {
  return loc.file + ":" + std::to_string(loc.line) + ":" + std::to_string(loc.column);
}

Pattern widen(const StringDef& def, std::size_t string_id) {
  Pattern p;
  p.nocase = def.nocase;
  p.wide = true;
  p.string_id = string_id;
  p.bytes.reserve(def.bytes.size() * 2);
  p.mask.reserve(def.bytes.size() * 2);
  for (std::size_t i = 0; i < def.bytes.size(); ++i) {
    p.bytes.push_back(def.bytes[i]);
    p.bytes.push_back(0);
    p.mask.push_back(def.mask[i]);
    p.mask.push_back(0xFF);
  }
  return p;
}

}  // namespace

RulesetStats Ruleset::stats() const {
  RulesetStats s;
  s.rules = rules_.size();
  s.strings = strings_.size();
  s.patterns = patterns_.size();
  s.atoms = automaton_.atom_count();
  s.states = automaton_.state_count();
  s.alphabet_classes = automaton_.alphabet_classes();
  s.table_bytes = automaton_.table_bytes();
  s.max_pattern_length = max_pattern_length_;
  return s;
}

std::vector<Hit> Ruleset::find_hits(std::span<const std::uint8_t> data) const {
  std::vector<Hit> hits;
  for_each_hit(
      data, [&](std::size_t pattern, std::size_t start) { hits.push_back(Hit{pattern, start}); });
  std::sort(hits.begin(), hits.end());
  return hits;
}

bool RulesetBuilder::add_source(std::string_view source, std::string_view filename) {
  ParseOutput parsed = parse_rules(source, filename);
  bool ok = !sigscan::has_errors(parsed.diagnostics);
  for (Diagnostic& d : parsed.diagnostics) {
    diagnostics_.push_back(std::move(d));
  }
  for (Rule& rule : parsed.rules) {
    const auto existing = names_.find(rule.name);
    if (existing != names_.end()) {
      Diagnostic d;
      d.level = DiagLevel::Error;
      d.loc = rule.loc;
      d.message = "duplicate rule name '" + rule.name + "' (first defined at " +
                  format_loc(existing->second) + ")";
      Lexer lexer(source);
      d.source_line = lexer.line_text(rule.loc.line);
      diagnostics_.push_back(std::move(d));
      ok = false;
      continue;
    }
    names_.emplace(rule.name, rule.loc);
    rules_.push_back(std::move(rule));
  }
  return ok;
}

bool RulesetBuilder::add_file(const std::filesystem::path& path) {
  const TextFile file = read_text_file(path, kMaxRuleFileBytes);
  if (!file.error.empty()) {
    Diagnostic d;
    d.level = DiagLevel::Error;
    d.loc.file = path.generic_string();
    d.message = "cannot read rule file: " + file.error;
    diagnostics_.push_back(std::move(d));
    return false;
  }
  return add_source(file.data, path.generic_string());
}

CompileResult RulesetBuilder::compile(const CompileOptions& options) {
  CompileResult result;
  if (has_errors()) {
    result.diagnostics = diagnostics_;
    return result;
  }
  auto rs = std::make_shared<Ruleset>();
  std::map<std::vector<std::uint8_t>, std::uint32_t> atom_ids;

  for (std::size_t r = 0; r < rules_.size(); ++r) {
    const Rule& rule = rules_[r];
    rs->rule_first_string_.push_back(rs->strings_.size());
    for (std::size_t i = 0; i < rule.strings.size(); ++i) {
      const StringDef& def = rule.strings[i];
      const std::size_t string_id = rs->strings_.size();
      CompiledString cs;
      cs.id = def.id;
      cs.rule_index = r;
      cs.local_index = i;

      std::vector<Pattern> forms;
      if (def.ascii) {
        Pattern p;
        p.bytes = def.bytes;
        p.mask = def.mask;
        p.nocase = def.nocase;
        p.string_id = string_id;
        forms.push_back(std::move(p));
      }
      if (def.wide) {
        forms.push_back(widen(def, string_id));
      }
      for (Pattern& p : forms) {
        const AtomChoice atom = choose_atom(p, options.max_atom_length);
        // The parser rejects patterns without literal bytes, so length is never 0 here.
        if (atom.length == 0) {
          continue;
        }
        if (atom.length == 1) {
          Diagnostic d;
          d.level = DiagLevel::Warning;
          d.loc = def.loc;
          d.message = "string '" + def.id + "' in rule '" + rule.name +
                      "' is anchored on a single byte, which makes scanning slower";
          diagnostics_.push_back(std::move(d));
        }
        std::vector<std::uint8_t> key(
            p.bytes.begin() + static_cast<std::ptrdiff_t>(atom.offset),
            p.bytes.begin() + static_cast<std::ptrdiff_t>(atom.offset + atom.length));
        for (std::uint8_t& b : key) {
          b = fold_byte(b);
        }
        auto [it, inserted] =
            atom_ids.try_emplace(key, static_cast<std::uint32_t>(rs->atom_refs_.size()));
        if (inserted) {
          rs->automaton_.add(key);
          rs->atom_refs_.emplace_back();
        }
        const std::size_t pattern_id = rs->patterns_.size();
        rs->atom_refs_[it->second].push_back(AtomRef{pattern_id, atom.offset});
        rs->max_pattern_length_ = std::max(rs->max_pattern_length_, p.size());
        cs.pattern_ids.push_back(pattern_id);
        rs->patterns_.push_back(std::move(p));
      }
      rs->strings_.push_back(std::move(cs));
    }
  }

  try {
    rs->automaton_.build(options.max_table_bytes);
  } catch (const AutomatonTooLarge& e) {
    Diagnostic d;
    d.level = DiagLevel::Error;
    d.loc.file = "<ruleset>";
    d.message = e.what();
    diagnostics_.push_back(std::move(d));
    result.diagnostics = diagnostics_;
    return result;
  }
  rs->rules_ = std::move(rules_);
  rules_.clear();
  names_.clear();
  result.diagnostics = diagnostics_;
  result.ruleset = std::move(rs);
  return result;
}

}  // namespace sigscan
