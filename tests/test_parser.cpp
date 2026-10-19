#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "sigscan/parser.hpp"
#include "sigscan/ruleset.hpp"

namespace sigscan {
namespace {

constexpr const char* kSpecRule = R"(rule Demo_Dropper_Strings : dropper demo
{
  meta:
    author = "Sigscan samples"
    description = "Fictional dropper marker strings used in the synthetic samples"
    severity = "high"          // low|medium|high|critical
  strings:
    $a = "SIGSCAN-DEMO-PAYLOAD"            // text, case-sensitive
    $b = "connect-back" nocase             // case-insensitive ASCII
    $c = { 4D 5A ?? 00 DE AD ?? EF }        // hex with ?? wildcards (single-byte)
    $d = "evil.example.net" wide           // UTF-16LE
  condition:
    $a and (any of ($b, $c) or #d >= 2) and filesize < 5MB
}
)";

ParseOutput parse(std::string_view src) {
  return parse_rules(src, "t.sig");
}

// The only (first) error diagnostic, formatted.
std::string first_error(std::string_view src) {
  const ParseOutput out = parse(src);
  for (const auto& d : out.diagnostics) {
    if (d.level == DiagLevel::Error) {
      return d.format();
    }
  }
  return "<no error>";
}

std::string wrap(std::string_view strings, std::string_view condition) {
  return "rule r {\n strings:\n" + std::string(strings) + "\n condition:\n  " +
         std::string(condition) + "\n}\n";
}

TEST(Parser, SpecExampleParsesCompletely) {
  const ParseOutput out = parse(kSpecRule);
  ASSERT_TRUE(out.diagnostics.empty()) << out.diagnostics.front().format();
  ASSERT_EQ(out.rules.size(), 1U);
  const Rule& r = out.rules.front();
  EXPECT_EQ(r.name, "Demo_Dropper_Strings");
  EXPECT_EQ(r.tags, (std::vector<std::string>{"dropper", "demo"}));
  EXPECT_EQ(r.severity, Severity::High);
  ASSERT_EQ(r.meta.size(), 3U);
  EXPECT_EQ(r.meta[0].key, "author");
  EXPECT_EQ(r.meta[0].value.text, "Sigscan samples");
  ASSERT_EQ(r.strings.size(), 4U);
  EXPECT_FALSE(r.strings[0].nocase);
  EXPECT_TRUE(r.strings[1].nocase);
  EXPECT_TRUE(r.strings[2].is_hex);
  EXPECT_EQ(r.strings[2].mask,
            (std::vector<std::uint8_t>{0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0, 0xFF}));
  EXPECT_TRUE(r.strings[3].wide);
  EXPECT_FALSE(r.strings[3].ascii);
  EXPECT_EQ(r.condition_text, "$a and (any of ($b, $c) or #d >= 2) and filesize < 5MB");
  ASSERT_EQ(r.condition->kind, ExprKind::And);
  EXPECT_EQ(r.condition->children.size(), 3U);
  EXPECT_EQ(r.condition->children[1]->kind, ExprKind::Or);
  EXPECT_EQ(r.condition->children[2]->kind, ExprKind::Filesize);
  EXPECT_EQ(r.condition->children[2]->value, 5U * 1024 * 1024);
  EXPECT_EQ(r.loc.line, 1U);
  EXPECT_EQ(r.loc.column, 6U);
}

TEST(Parser, MetaValueTypes) {
  const ParseOutput out =
      parse("rule r { meta: n = 0x10 ok = true no = false s = \"x\" condition: true }");
  ASSERT_EQ(out.rules.size(), 1U);
  const Rule& r = out.rules.front();
  EXPECT_EQ(r.meta[0].value.type, MetaValue::Type::Integer);
  EXPECT_EQ(r.meta[0].value.integer, 16U);
  EXPECT_EQ(r.meta[1].value.type, MetaValue::Type::Boolean);
  EXPECT_TRUE(r.meta[1].value.boolean);
  EXPECT_FALSE(r.meta[2].value.boolean);
  EXPECT_EQ(r.meta[3].value.text, "x");
  EXPECT_EQ(r.severity, Severity::Medium);  // default
}

TEST(Parser, ModifiersAsciiWideCombination) {
  const ParseOutput out = parse(wrap("  $a = \"x\" wide ascii nocase", "$a"));
  ASSERT_EQ(out.rules.size(), 1U);
  const StringDef& s = out.rules.front().strings.front();
  EXPECT_TRUE(s.wide);
  EXPECT_TRUE(s.ascii);
  EXPECT_TRUE(s.nocase);
}

TEST(Parser, OperatorPrecedenceAndBindsTighterThanOr) {
  const ParseOutput out =
      parse(wrap("  $a = \"a\"\n  $b = \"b\"\n  $c = \"c\"", "$a or $b and not $c"));
  ASSERT_EQ(out.rules.size(), 1U);
  const Expr& e = *out.rules.front().condition;
  ASSERT_EQ(e.kind, ExprKind::Or);
  ASSERT_EQ(e.children.size(), 2U);
  EXPECT_EQ(e.children[0]->kind, ExprKind::Present);
  ASSERT_EQ(e.children[1]->kind, ExprKind::And);
  EXPECT_EQ(e.children[1]->children[1]->kind, ExprKind::Not);
}

TEST(Parser, EveryConditionConstruct) {
  const std::string strings = "  $a = \"a\"\n  $b1 = \"b\"\n  $b2 = { 41 ?? 42 }";
  const std::vector<std::pair<std::string, ExprKind>> cases = {
      {"$a", ExprKind::Present},
      {"#a == 2", ExprKind::Count},
      {"#a != 2", ExprKind::Count},
      {"#a < 2", ExprKind::Count},
      {"#a <= 2", ExprKind::Count},
      {"#a > 2", ExprKind::Count},
      {"#a >= 2", ExprKind::Count},
      {"$a at 0x10", ExprKind::At},
      {"$a in (0..100)", ExprKind::In},
      {"any of them", ExprKind::Of},
      {"all of them", ExprKind::Of},
      {"2 of them", ExprKind::Of},
      {"any of ($a, $b2)", ExprKind::Of},
      {"2 of ($b*)", ExprKind::Of},
      {"all of ($*)", ExprKind::Of},
      {"filesize < 5MB", ExprKind::Filesize},
      {"filesize >= 10KB", ExprKind::Filesize},
      {"true", ExprKind::Bool},
      {"not false", ExprKind::Not},
      {"($a)", ExprKind::Present},
  };
  for (const auto& [cond, kind] : cases) {
    const ParseOutput out = parse(wrap(strings, cond + " or ($a and $b1 and $b2)"));
    ASSERT_EQ(out.rules.size(), 1U) << cond << ": " << out.diagnostics.front().format();
    EXPECT_EQ(out.rules.front().condition->children.front()->kind, kind) << cond;
  }
}

TEST(Parser, WildcardSetsExpandAndDeduplicate) {
  const ParseOutput out =
      parse(wrap("  $cfg1 = \"a\"\n  $cfg2 = \"b\"\n  $x = \"c\"", "2 of ($cfg*, $cfg1) and $x"));
  ASSERT_EQ(out.rules.size(), 1U);
  const Expr& of = *out.rules.front().condition->children.front();
  EXPECT_EQ(of.set, (std::vector<std::size_t>{0, 1}));
  EXPECT_EQ(of.set_text, "($cfg*, $cfg1)");
}

TEST(Parser, ErrorFormatHasFileLineColumnAndCaret) {
  const std::string src = wrap("  $a = \"a\"", "$a and $z");
  EXPECT_EQ(first_error(src),
            "t.sig:5:10: error: unknown string identifier '$z' in rule 'r'\n"
            "  $a and $z\n"
            "         ^");
}

TEST(Parser, UnknownIdentifierInCondition) {
  EXPECT_EQ(first_error("rule r { condition: foo }"),
            "t.sig:1:21: error: unknown identifier 'foo'\n"
            "rule r { condition: foo }\n"
            "                    ^");
}

TEST(Parser, UnknownCountIdentifierShowsHash) {
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "#q > 1")).find("unknown string identifier '#q'"),
            std::string::npos);
}

TEST(Parser, StructuralErrors) {
  EXPECT_NE(first_error("strings").find("1:1: error: expected 'rule' but found 'strings'"),
            std::string::npos);
  EXPECT_NE(first_error("rule { condition: true }")
                .find("expected a rule name after 'rule' but found '{'"),
            std::string::npos);
  EXPECT_NE(first_error("rule and { condition: true }")
                .find("'and' is a reserved word and cannot be used as a rule name"),
            std::string::npos);
  EXPECT_NE(first_error("rule r : { condition: true }").find("expected at least one tag after ':'"),
            std::string::npos);
  EXPECT_NE(first_error("rule r : a a { condition: true }").find("duplicate tag 'a'"),
            std::string::npos);
  EXPECT_NE(first_error("rule r condition: true }").find("expected '{' to open the body"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { strings: $a = \"a\" }").find("expected 'condition:'"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { condition: true").find("expected 'and', 'or' or '}'"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { condition: true true }").find("unexpected 'true' in condition"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { condition: }").find("expected an expression but found '}'"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { condition: (true }").find("expected ')'"), std::string::npos);
  EXPECT_NE(first_error("rule r { condition:").find("unexpected end of file in condition"),
            std::string::npos);
}

TEST(Parser, MetaErrors) {
  EXPECT_NE(first_error("rule r { meta: severity = \"urgent\" condition: true }")
                .find("1:27: error: invalid severity 'urgent'"),
            std::string::npos);
  EXPECT_NE(
      first_error("rule r { meta: severity = 3 condition: true }").find("invalid severity '3'"),
      std::string::npos);
  EXPECT_NE(
      first_error("rule r { meta: a = 1 a = 2 condition: true }").find("duplicate meta key 'a'"),
      std::string::npos);
  EXPECT_NE(first_error("rule r { meta: a = $x condition: true }").find("expected a meta value"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { strings: $a = \"a\" meta: x = 1 condition: $a }")
                .find("sections must appear as meta, strings, condition"),
            std::string::npos);
}

TEST(Parser, StringDefinitionErrors) {
  EXPECT_NE(first_error(wrap("  $a = \"a\"\n  $a = \"b\"", "$a"))
                .find("4:3: error: duplicate string identifier '$a' in rule 'r'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\" fullword", "$a"))
                .find("unknown string modifier 'fullword' (supported: nocase, wide, ascii)"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\" nocase nocase", "$a"))
                .find("duplicate modifier 'nocase' on '$a'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = { 41 } nocase", "$a"))
                .find("modifier 'nocase' is not allowed on hex string '$a'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = 12", "$a"))
                .find("expected a text string or hex string after '$a ='"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { strings: condition: true }")
                .find("expected a string definition such as $a = \"text\""),
            std::string::npos);
}

TEST(Parser, AllWildcardHexStringIsRejected) {
  EXPECT_EQ(first_error(wrap("  $w = { ?? ?? ?? }", "$w")),
            "t.sig:3:8: error: hex string '$w' contains only wildcards; at least one literal "
            "byte is needed to anchor the matcher\n"
            "  $w = { ?? ?? ?? }\n"
            "       ^");
}

TEST(Parser, SetAndQuantifierErrors) {
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "3 of ($a)"))
                .find("3 of a set of 1 string(s) can never be true"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "0 of them")).find("quantity must be at least 1"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "any of ($q*)"))
                .find("'$q*' does not match any string in rule 'r'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "$a*"))
                .find("string wildcards like '$a*' are only allowed inside a set"),
            std::string::npos);
  EXPECT_NE(first_error("rule r { condition: any of them }")
                .find("'them' used in rule 'r', which has no strings"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "any $a")).find("expected 'of' after 'any'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "any of $a")).find("expected 'them' or a string set"),
            std::string::npos);
}

TEST(Parser, ComparisonAndRangeErrors) {
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "#a = 2")).find("use '==' for comparison, not '='"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "#a")).find("expected a comparison such as '#a >= 2'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "filesize $a"))
                .find("expected a comparison such as 'filesize < 5MB'"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "$a in (10..5)"))
                .find("range start is greater than range end"),
            std::string::npos);
  EXPECT_NE(first_error(wrap("  $a = \"a\"", "$a at x")).find("expected an offset after 'at'"),
            std::string::npos);
}

TEST(Parser, NestingDepthIsLimited) {
  const std::string deep = std::string(200, '(') + "true" + std::string(200, ')');
  EXPECT_NE(first_error("rule r { condition: " + deep + " }")
                .find("condition is nested too deeply (limit 64)"),
            std::string::npos);
  std::string nots;
  for (int i = 0; i < 100; ++i) {
    nots += "not ";
  }
  EXPECT_NE(first_error("rule r { condition: " + nots + "true }").find("nested too deeply"),
            std::string::npos);
  const std::string ok = std::string(30, '(') + "true" + std::string(30, ')');
  EXPECT_EQ(parse("rule r { condition: " + ok + " }").rules.size(), 1U);
}

TEST(Parser, UnusedStringIsAWarningNotAnError) {
  const ParseOutput out = parse(wrap("  $a = \"a\"\n  $b = \"b\"", "$a"));
  ASSERT_EQ(out.rules.size(), 1U);
  ASSERT_EQ(out.diagnostics.size(), 1U);
  EXPECT_EQ(out.diagnostics[0].level, DiagLevel::Warning);
  EXPECT_EQ(out.diagnostics[0].format(),
            "t.sig:4:3: warning: string '$b' in rule 'r' is not used in the condition\n"
            "  $b = \"b\"\n"
            "  ^");
}

TEST(Parser, RecoversAndReportsSeveralErrors) {
  const std::string src =
      "rule bad1 { condition: nope }\n"
      "rule good { condition: true }\n"
      "rule bad2 { strings: $a = \"x\\q\" condition: $a }\n"
      "rule good2 { condition: false }\n";
  const ParseOutput out = parse(src);
  ASSERT_EQ(out.rules.size(), 2U);
  EXPECT_EQ(out.rules[0].name, "good");
  EXPECT_EQ(out.rules[1].name, "good2");
  ASSERT_EQ(count_level(out.diagnostics, DiagLevel::Error), 2U);
  EXPECT_EQ(out.diagnostics[0].loc.line, 1U);
  EXPECT_EQ(out.diagnostics[1].loc.line, 3U);
  EXPECT_EQ(out.diagnostics[1].loc.column, 29U);
}

TEST(Parser, DuplicateRuleNamesAcrossSources) {
  RulesetBuilder builder;
  EXPECT_TRUE(builder.add_source("rule same { condition: true }", "a.sig"));
  EXPECT_FALSE(builder.add_source("\nrule same { condition: false }", "b.sig"));
  ASSERT_TRUE(builder.has_errors());
  EXPECT_EQ(builder.diagnostics().back().format(),
            "b.sig:2:6: error: duplicate rule name 'same' (first defined at a.sig:1:6)\n"
            "rule same { condition: false }\n"
            "     ^");
  EXPECT_EQ(builder.compile().ruleset, nullptr);
}

TEST(Parser, MissingRuleFileIsReported) {
  RulesetBuilder builder;
  EXPECT_FALSE(builder.add_file("/nonexistent/sigscan/rules.sig"));
  ASSERT_EQ(builder.diagnostics().size(), 1U);
  EXPECT_NE(builder.diagnostics()[0].format().find(
                "/nonexistent/sigscan/rules.sig: error: cannot read rule file:"),
            std::string::npos);
}

TEST(Parser, ConditionTextDropsComments) {
  const ParseOutput out =
      parse("rule r { condition:\n  true // first\n  and /* inline */ not false\n}");
  ASSERT_EQ(out.rules.size(), 1U);
  EXPECT_EQ(out.rules.front().condition_text, "true and not false");
}

}  // namespace
}  // namespace sigscan
