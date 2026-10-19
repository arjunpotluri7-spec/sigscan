#include "sigscan/parser.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sigscan/lexer.hpp"

namespace sigscan {
namespace {

constexpr std::array<std::string_view, 19> kKeywords = {
    "rule", "meta", "strings", "condition", "and",  "or",    "not",    "any",  "all",   "of",
    "them", "at",   "in",      "filesize",  "true", "false", "nocase", "wide", "ascii",
};

bool is_keyword(std::string_view text) {
  return std::find(kKeywords.begin(), kKeywords.end(), text) != kKeywords.end();
}

struct ParseFailure : std::exception {
  ParseFailure(std::uint32_t l, std::uint32_t c, std::string m)
      : line(l), column(c), message(std::move(m)) {}
  [[nodiscard]] const char* what() const noexcept override { return message.c_str(); }
  std::uint32_t line = 0;
  std::uint32_t column = 0;
  std::string message;
};

// Collapses whitespace and drops comments so the condition reads well in reports.
std::string collapse_condition(std::string_view text) {
  std::string out;
  bool pending_space = false;
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    if (c == '/' && i + 1 < text.size() && text[i + 1] == '/') {
      while (i < text.size() && text[i] != '\n') {
        ++i;
      }
      pending_space = true;
      continue;
    }
    if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') {
      i += 2;
      while (i + 1 < text.size() && (text[i] != '*' || text[i + 1] != '/')) {
        ++i;
      }
      ++i;
      pending_space = true;
      continue;
    }
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      pending_space = true;
      continue;
    }
    if (pending_space && !out.empty()) {
      out += ' ';
    }
    pending_space = false;
    out += c;
  }
  return out;
}

class Parser {
 public:
  Parser(std::string_view source, std::string_view filename)
      : lexer_(source), src_(source), file_(filename) {}

  ParseOutput run() {
    cur_ = lexer_.next();
    while (cur_.kind != TokenKind::End) {
      if (out_.diagnostics.size() >= kMaxDiagnosticsPerFile) {
        add_diag(DiagLevel::Error, cur_.line, cur_.column,
                 "too many errors; stopping after " + std::to_string(kMaxDiagnosticsPerFile));
        break;
      }
      try {
        if (cur_.kind == TokenKind::Error) {
          fail_here(cur_.text);
        }
        if (!is_word("rule")) {
          fail_here("expected 'rule' but found " + describe(cur_));
        }
        Rule rule = parse_rule();
        out_.rules.push_back(std::move(rule));
      } catch (const ParseFailure& failure) {
        add_diag(DiagLevel::Error, failure.line, failure.column, failure.message);
        recover();
      }
    }
    return std::move(out_);
  }

 private:
  // --- token helpers -------------------------------------------------------------------------

  void advance() {
    cur_ = lexer_.next();
    if (cur_.kind == TokenKind::Error) {
      fail_here(cur_.text);
    }
  }

  void recover() {
    // Skip to the next `rule` keyword; lexer errors on the way are part of the broken rule.
    while (cur_.kind != TokenKind::End && !is_word("rule")) {
      cur_ = lexer_.next();
    }
  }

  [[nodiscard]] bool is_word(std::string_view word) const {
    return cur_.kind == TokenKind::Identifier && cur_.text == word;
  }

  [[noreturn]] void fail_at(const Token& tok, std::string message) const {
    throw ParseFailure{tok.line, tok.column, std::move(message)};
  }

  [[noreturn]] void fail_here(std::string message) const { fail_at(cur_, std::move(message)); }

  static std::string describe(const Token& tok) {
    switch (tok.kind) {
      case TokenKind::Identifier:
      case TokenKind::StringId:
      case TokenKind::CountId:
      case TokenKind::Number:
        return "'" + (tok.kind == TokenKind::CountId ? "#" + tok.text.substr(1) : tok.text) + "'";
      case TokenKind::StringWildcard:
        return "'" + tok.text + "*'";
      default:
        return token_kind_name(tok.kind);
    }
  }

  void expect(TokenKind kind, const std::string& message) {
    if (cur_.kind != kind) {
      fail_here(message + " but found " + describe(cur_));
    }
    advance();
  }

  void expect_word(std::string_view word, const std::string& message) {
    if (!is_word(word)) {
      fail_here(message + " but found " + describe(cur_));
    }
    advance();
  }

  void add_diag(DiagLevel level, std::uint32_t line, std::uint32_t column, std::string message) {
    Diagnostic d;
    d.level = level;
    d.loc = SourceLocation{std::string(file_), line, column};
    d.message = std::move(message);
    d.source_line = lexer_.line_text(line);
    out_.diagnostics.push_back(std::move(d));
  }

  [[nodiscard]] SourceLocation loc_of(const Token& tok) const {
    return SourceLocation{std::string(file_), tok.line, tok.column};
  }

  // --- rules ---------------------------------------------------------------------------------

  Rule parse_rule() {
    Rule rule;
    rule.loc = loc_of(cur_);
    advance();  // 'rule'
    if (cur_.kind != TokenKind::Identifier) {
      fail_here("expected a rule name after 'rule' but found " + describe(cur_));
    }
    if (is_keyword(cur_.text)) {
      fail_here("'" + cur_.text + "' is a reserved word and cannot be used as a rule name");
    }
    rule.name = cur_.text;
    rule.loc = loc_of(cur_);
    advance();

    if (cur_.kind == TokenKind::Colon) {
      advance();
      if (cur_.kind != TokenKind::Identifier || is_keyword(cur_.text)) {
        fail_here("expected at least one tag after ':' but found " + describe(cur_));
      }
      while (cur_.kind == TokenKind::Identifier && !is_keyword(cur_.text)) {
        if (std::find(rule.tags.begin(), rule.tags.end(), cur_.text) != rule.tags.end()) {
          fail_here("duplicate tag '" + cur_.text + "'");
        }
        rule.tags.push_back(cur_.text);
        advance();
      }
    }
    expect(TokenKind::LBrace, "expected '{' to open the body of rule '" + rule.name + "'");

    if (is_word("meta")) {
      advance();
      expect(TokenKind::Colon, "expected ':' after 'meta'");
      parse_meta(rule);
    }
    used_.clear();
    if (is_word("strings")) {
      advance();
      expect(TokenKind::Colon, "expected ':' after 'strings'");
      parse_strings(rule);
    }
    used_.assign(rule.strings.size(), false);

    if (!is_word("condition")) {
      if (is_word("meta")) {
        fail_here("the 'meta' section must come before 'strings'");
      }
      fail_here("expected 'condition:' in rule '" + rule.name + "' but found " + describe(cur_));
    }
    advance();
    expect(TokenKind::Colon, "expected ':' after 'condition'");
    const std::size_t cond_start = cur_.offset;
    rule.condition = parse_or(rule, 0);
    const std::size_t cond_end = cur_.offset;
    if (cur_.kind != TokenKind::RBrace) {
      fail_here("unexpected " + describe(cur_) +
                " in condition; expected 'and', 'or' or '}' to close rule '" + rule.name + "'");
    }
    rule.condition_text = collapse_condition(src_.substr(cond_start, cond_end - cond_start));
    // Consume '}' without throwing on a lexer error in the next rule: that error belongs there.
    cur_ = lexer_.next();

    for (std::size_t i = 0; i < rule.strings.size(); ++i) {
      if (!used_[i]) {
        const StringDef& s = rule.strings[i];
        add_diag(DiagLevel::Warning, s.loc.line, s.loc.column,
                 "string '" + s.id + "' in rule '" + rule.name + "' is not used in the condition");
      }
    }
    return rule;
  }

  void parse_meta(Rule& rule) {
    while (cur_.kind == TokenKind::Identifier && !is_word("strings") && !is_word("condition")) {
      MetaEntry entry;
      entry.key = cur_.text;
      if (rule.find_meta(entry.key) != nullptr) {
        fail_here("duplicate meta key '" + entry.key + "'");
      }
      advance();
      expect(TokenKind::Assign, "expected '=' after meta key '" + entry.key + "'");
      const Token value_tok = cur_;
      if (cur_.kind == TokenKind::Text) {
        entry.value.type = MetaValue::Type::String;
        entry.value.text.assign(cur_.bytes.begin(), cur_.bytes.end());
      } else if (cur_.kind == TokenKind::Number) {
        entry.value.type = MetaValue::Type::Integer;
        entry.value.integer = cur_.number;
        entry.value.text = std::to_string(cur_.number);
      } else if (is_word("true") || is_word("false")) {
        entry.value.type = MetaValue::Type::Boolean;
        entry.value.boolean = is_word("true");
        entry.value.text = cur_.text;
      } else {
        fail_here("expected a meta value (\"text\", a number, true or false) but found " +
                  describe(cur_));
      }
      if (entry.key == "severity") {
        const auto severity = entry.value.type == MetaValue::Type::String
                                  ? parse_severity(entry.value.text)
                                  : std::nullopt;
        if (!severity) {
          fail_at(value_tok, "invalid severity '" + entry.value.text +
                                 "' (expected \"low\", \"medium\", \"high\" or \"critical\")");
        }
        rule.severity = *severity;
      }
      rule.meta.push_back(std::move(entry));
      advance();
    }
    if (cur_.kind != TokenKind::Identifier) {
      fail_here("expected a meta entry such as author = \"name\" but found " + describe(cur_));
    }
  }

  void parse_strings(Rule& rule) {
    if (cur_.kind != TokenKind::StringId) {
      fail_here("expected a string definition such as $a = \"text\" but found " + describe(cur_));
    }
    while (cur_.kind == TokenKind::StringId) {
      StringDef def;
      def.id = cur_.text;
      def.loc = loc_of(cur_);
      for (const StringDef& existing : rule.strings) {
        if (existing.id == def.id) {
          fail_here("duplicate string identifier '" + def.id + "' in rule '" + rule.name + "'");
        }
      }
      advance();
      expect(TokenKind::Assign, "expected '=' after '" + def.id + "'");
      if (cur_.kind == TokenKind::Text) {
        def.bytes = cur_.bytes;
        def.mask = cur_.mask;
        advance();
        bool ascii_given = false;
        while (is_word("nocase") || is_word("wide") || is_word("ascii")) {
          bool& flag = is_word("nocase") ? def.nocase : (is_word("wide") ? def.wide : ascii_given);
          if (flag) {
            fail_here("duplicate modifier '" + cur_.text + "' on '" + def.id + "'");
          }
          flag = true;
          advance();
        }
        def.ascii = ascii_given || !def.wide;
      } else if (cur_.kind == TokenKind::Hex) {
        def.is_hex = true;
        def.bytes = cur_.bytes;
        def.mask = cur_.mask;
        if (std::none_of(def.mask.begin(), def.mask.end(), [](std::uint8_t m) { return m != 0; })) {
          fail_at(cur_, "hex string '" + def.id +
                            "' contains only wildcards; at least one literal byte is needed to "
                            "anchor the matcher");
        }
        advance();
        if (is_word("nocase") || is_word("wide") || is_word("ascii")) {
          fail_here("modifier '" + cur_.text + "' is not allowed on hex string '" + def.id + "'");
        }
        def.ascii = true;
      } else {
        fail_here("expected a text string or hex string after '" + def.id + " =' but found " +
                  describe(cur_));
      }
      if (cur_.kind == TokenKind::Identifier && !is_word("condition")) {
        if (is_word("meta") || is_word("strings")) {
          fail_here("unexpected '" + cur_.text + "'; sections must appear as meta, strings, " +
                    "condition");
        }
        fail_here("unknown string modifier '" + cur_.text + "' (supported: nocase, wide, ascii)");
      }
      rule.strings.push_back(std::move(def));
    }
  }

  // --- conditions ----------------------------------------------------------------------------

  void check_depth(std::size_t depth) const {
    if (depth >= kMaxConditionDepth) {
      fail_here("condition is nested too deeply (limit " + std::to_string(kMaxConditionDepth) +
                ")");
    }
  }

  static std::unique_ptr<Expr> make_expr(ExprKind kind, SourceLocation loc) {
    auto e = std::make_unique<Expr>();
    e->kind = kind;
    e->loc = std::move(loc);
    return e;
  }

  std::unique_ptr<Expr> parse_or(const Rule& rule, std::size_t depth) {
    check_depth(depth);
    auto left = parse_and(rule, depth);
    if (!is_word("or")) {
      return left;
    }
    auto node = make_expr(ExprKind::Or, left->loc);
    node->children.push_back(std::move(left));
    while (is_word("or")) {
      advance();
      node->children.push_back(parse_and(rule, depth));
    }
    return node;
  }

  std::unique_ptr<Expr> parse_and(const Rule& rule, std::size_t depth) {
    auto left = parse_not(rule, depth);
    if (!is_word("and")) {
      return left;
    }
    auto node = make_expr(ExprKind::And, left->loc);
    node->children.push_back(std::move(left));
    while (is_word("and")) {
      advance();
      node->children.push_back(parse_not(rule, depth));
    }
    return node;
  }

  std::unique_ptr<Expr> parse_not(const Rule& rule, std::size_t depth) {
    if (is_word("not")) {
      check_depth(depth + 1);
      auto node = make_expr(ExprKind::Not, loc_of(cur_));
      advance();
      node->children.push_back(parse_not(rule, depth + 1));
      return node;
    }
    return parse_primary(rule, depth);
  }

  std::size_t resolve(const Rule& rule, const Token& tok) {
    for (std::size_t i = 0; i < rule.strings.size(); ++i) {
      if (rule.strings[i].id == tok.text) {
        used_[i] = true;
        return i;
      }
    }
    const std::string shown = tok.kind == TokenKind::CountId ? "#" + tok.text.substr(1) : tok.text;
    if (rule.strings.empty()) {
      fail_at(tok, "unknown string identifier '" + shown + "' (rule '" + rule.name +
                       "' has no strings section)");
    }
    fail_at(tok, "unknown string identifier '" + shown + "' in rule '" + rule.name + "'");
  }

  CmpOp parse_cmp(const std::string& hint) {
    CmpOp op = CmpOp::Eq;
    switch (cur_.kind) {
      case TokenKind::Eq:
        op = CmpOp::Eq;
        break;
      case TokenKind::Ne:
        op = CmpOp::Ne;
        break;
      case TokenKind::Lt:
        op = CmpOp::Lt;
        break;
      case TokenKind::Le:
        op = CmpOp::Le;
        break;
      case TokenKind::Gt:
        op = CmpOp::Gt;
        break;
      case TokenKind::Ge:
        op = CmpOp::Ge;
        break;
      case TokenKind::Assign:
        fail_here("use '==' for comparison, not '='");
      default:
        fail_here("expected a comparison such as '" + hint + "' but found " + describe(cur_));
    }
    advance();
    return op;
  }

  std::uint64_t parse_number(const std::string& what) {
    if (cur_.kind != TokenKind::Number) {
      fail_here("expected " + what + " but found " + describe(cur_));
    }
    const std::uint64_t value = cur_.number;
    advance();
    return value;
  }

  std::unique_ptr<Expr> parse_primary(const Rule& rule, std::size_t depth) {
    const Token tok = cur_;
    switch (tok.kind) {
      case TokenKind::LParen: {
        check_depth(depth + 1);
        advance();
        auto inner = parse_or(rule, depth + 1);
        expect(TokenKind::RParen, "expected ')'");
        return inner;
      }
      case TokenKind::StringId: {
        const std::size_t index = resolve(rule, tok);
        advance();
        if (is_word("at")) {
          advance();
          auto node = make_expr(ExprKind::At, loc_of(tok));
          node->string_index = index;
          node->value = parse_number("an offset after 'at'");
          return node;
        }
        if (is_word("in")) {
          advance();
          expect(TokenKind::LParen, "expected '(' to start a range such as (0..1024)");
          auto node = make_expr(ExprKind::In, loc_of(tok));
          node->string_index = index;
          const Token start_tok = cur_;
          node->value = parse_number("a range start");
          expect(TokenKind::DotDot, "expected '..' in range");
          node->value2 = parse_number("a range end");
          expect(TokenKind::RParen, "expected ')' to close the range");
          if (node->value > node->value2) {
            fail_at(start_tok, "range start is greater than range end");
          }
          return node;
        }
        auto node = make_expr(ExprKind::Present, loc_of(tok));
        node->string_index = index;
        return node;
      }
      case TokenKind::CountId: {
        const std::size_t index = resolve(rule, tok);
        advance();
        auto node = make_expr(ExprKind::Count, loc_of(tok));
        node->string_index = index;
        node->op = parse_cmp("#" + tok.text.substr(1) + " >= 2");
        node->value = parse_number("a count");
        return node;
      }
      case TokenKind::StringWildcard:
        fail_here("string wildcards like '" + tok.text +
                  "*' are only allowed inside a set, for example any of (" + tok.text + "*)");
      case TokenKind::Number:
        return parse_of(rule, tok);
      case TokenKind::Identifier:
        break;
      case TokenKind::End:
        fail_here("unexpected end of file in condition");
      default:
        fail_here("expected an expression but found " + describe(tok));
    }

    if (tok.text == "true" || tok.text == "false") {
      auto node = make_expr(ExprKind::Bool, loc_of(tok));
      node->bool_value = tok.text == "true";
      advance();
      return node;
    }
    if (tok.text == "filesize") {
      advance();
      auto node = make_expr(ExprKind::Filesize, loc_of(tok));
      node->op = parse_cmp("filesize < 5MB");
      node->value = parse_number("a size such as 5MB");
      return node;
    }
    if (tok.text == "any" || tok.text == "all") {
      return parse_of(rule, tok);
    }
    if (is_keyword(tok.text)) {
      fail_here("expected an expression but found '" + tok.text + "'");
    }
    fail_here("unknown identifier '" + tok.text + "'");
  }

  std::unique_ptr<Expr> parse_of(const Rule& rule, const Token& quant_tok) {
    auto node = make_expr(ExprKind::Of, loc_of(quant_tok));
    if (quant_tok.kind == TokenKind::Number) {
      node->quantifier = Quantifier::Number;
      node->quantity = quant_tok.number;
    } else {
      node->quantifier = quant_tok.text == "all" ? Quantifier::All : Quantifier::Any;
    }
    const std::string quant_text = quant_tok.text;
    advance();
    expect_word("of", "expected 'of' after '" + quant_text + "'");

    if (is_word("them")) {
      if (rule.strings.empty()) {
        fail_here("'them' used in rule '" + rule.name + "', which has no strings");
      }
      for (std::size_t i = 0; i < rule.strings.size(); ++i) {
        node->set.push_back(i);
        used_[i] = true;
      }
      node->set_text = "them";
      advance();
    } else if (cur_.kind == TokenKind::LParen) {
      advance();
      std::string text = "(";
      for (bool first = true;; first = false) {
        if (!first) {
          text += ", ";
        }
        if (cur_.kind == TokenKind::StringId) {
          node->set.push_back(resolve(rule, cur_));
          text += cur_.text;
        } else if (cur_.kind == TokenKind::StringWildcard) {
          bool any = false;
          for (std::size_t i = 0; i < rule.strings.size(); ++i) {
            if (rule.strings[i].id.starts_with(cur_.text)) {
              node->set.push_back(i);
              used_[i] = true;
              any = true;
            }
          }
          if (!any) {
            fail_here("'" + cur_.text + "*' does not match any string in rule '" + rule.name + "'");
          }
          text += cur_.text + "*";
        } else {
          fail_here("expected a string identifier in set but found " + describe(cur_));
        }
        advance();
        if (cur_.kind == TokenKind::Comma) {
          advance();
          continue;
        }
        expect(TokenKind::RParen, "expected ',' or ')' in string set");
        break;
      }
      node->set_text = text + ")";
    } else {
      fail_here("expected 'them' or a string set such as ($a, $b*) but found " + describe(cur_));
    }
    std::sort(node->set.begin(), node->set.end());
    node->set.erase(std::unique(node->set.begin(), node->set.end()), node->set.end());
    if (node->quantifier == Quantifier::Number) {
      if (node->quantity == 0) {
        fail_at(quant_tok, "quantity must be at least 1");
      }
      if (node->quantity > node->set.size()) {
        fail_at(quant_tok, std::to_string(node->quantity) + " of a set of " +
                               std::to_string(node->set.size()) + " string(s) can never be true");
      }
    }
    return node;
  }

  Lexer lexer_;
  std::string_view src_;
  std::string_view file_;
  Token cur_;
  ParseOutput out_;
  std::vector<bool> used_;
};

}  // namespace

ParseOutput parse_rules(std::string_view source, std::string_view filename) {
  Parser parser(source, filename);
  return parser.run();
}

}  // namespace sigscan
