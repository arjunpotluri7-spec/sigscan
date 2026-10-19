#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "sigscan/lexer.hpp"

namespace sigscan {
namespace {

std::vector<Token> lex_all(std::string_view src) {
  Lexer lexer(src);
  std::vector<Token> tokens;
  for (;;) {
    Token t = lexer.next();
    const bool stop = t.kind == TokenKind::End || t.kind == TokenKind::Error;
    tokens.push_back(std::move(t));
    if (stop) {
      return tokens;
    }
  }
}

Token first_error(std::string_view src) {
  for (Token& t : lex_all(src)) {
    if (t.kind == TokenKind::Error) {
      return t;
    }
  }
  return {};
}

TEST(Lexer, IdentifiersPunctuationAndOperators) {
  const auto t = lex_all("rule x : tag { ( ) , .. == != < <= > >= = }");
  const std::vector<TokenKind> kinds = {
      TokenKind::Identifier, TokenKind::Identifier, TokenKind::Colon,  TokenKind::Identifier,
      TokenKind::LBrace,     TokenKind::LParen,     TokenKind::RParen, TokenKind::Comma,
      TokenKind::DotDot,     TokenKind::Eq,         TokenKind::Ne,     TokenKind::Lt,
      TokenKind::Le,         TokenKind::Gt,         TokenKind::Ge,     TokenKind::Assign,
      TokenKind::RBrace,     TokenKind::End};
  ASSERT_EQ(t.size(), kinds.size());
  for (std::size_t i = 0; i < kinds.size(); ++i) {
    EXPECT_EQ(t[i].kind, kinds[i]) << "token " << i;
  }
  EXPECT_EQ(t[0].text, "rule");
}

TEST(Lexer, NumbersWithSuffixesAndHex) {
  const auto t = lex_all("42 0x1A 5KB 2MB 0");
  ASSERT_EQ(t.size(), 6U);
  EXPECT_EQ(t[0].number, 42U);
  EXPECT_EQ(t[1].number, 0x1AU);
  EXPECT_EQ(t[2].number, 5U * 1024);
  EXPECT_EQ(t[3].number, 2U * 1024 * 1024);
  EXPECT_EQ(t[4].number, 0U);
}

TEST(Lexer, NumberErrors) {
  EXPECT_EQ(first_error("18446744073709551616").text, "number does not fit in 64 bits");
  EXPECT_EQ(first_error("99999999999999999999MB").text, "number does not fit in 64 bits");
  EXPECT_EQ(first_error("5GB").text, "invalid number suffix 'GB' (expected KB or MB)");
  EXPECT_EQ(first_error("0x").text, "expected hex digits after '0x'");
}

TEST(Lexer, TextEscapesDecodeToBytes) {
  const auto t = lex_all(R"("a\n\t\r\\\"\x41\x00z")");
  ASSERT_EQ(t[0].kind, TokenKind::Text);
  const std::vector<std::uint8_t> expected = {'a', '\n', '\t', '\r', '\\', '"', 'A', 0, 'z'};
  EXPECT_EQ(t[0].bytes, expected);
  EXPECT_EQ(t[0].mask, std::vector<std::uint8_t>(expected.size(), 0xFF));
}

TEST(Lexer, TextErrorsHaveLocations) {
  const Token bad_escape = first_error("rule\n  \"ab\\qc\"");
  EXPECT_EQ(bad_escape.line, 2U);
  EXPECT_EQ(bad_escape.column, 6U);
  EXPECT_NE(bad_escape.text.find("unknown escape sequence '\\q'"), std::string::npos);

  const Token bad_hex = first_error("\"\\xZ1\"");
  EXPECT_EQ(bad_hex.text, "invalid \\x escape; expected two hex digits");
  EXPECT_EQ(bad_hex.column, 2U);

  const Token unterminated = first_error("x = \"abc\nrest");
  EXPECT_EQ(unterminated.text, "unterminated string (missing closing '\"')");
  EXPECT_EQ(unterminated.line, 1U);
  EXPECT_EQ(unterminated.column, 5U);

  EXPECT_EQ(first_error("\"\"").text, "empty text string");
  EXPECT_EQ(first_error("\"" + std::string(4097, 'a') + "\"").text,
            "string is longer than 4096 bytes");
}

TEST(Lexer, HexStringsOnlyAfterAssign) {
  const auto t = lex_all("$c = { 4D 5a ?? 00 }");
  ASSERT_EQ(t.size(), 4U);
  EXPECT_EQ(t[0].kind, TokenKind::StringId);
  EXPECT_EQ(t[2].kind, TokenKind::Hex);
  EXPECT_EQ(t[2].bytes, (std::vector<std::uint8_t>{0x4D, 0x5A, 0x00, 0x00}));
  EXPECT_EQ(t[2].mask, (std::vector<std::uint8_t>{0xFF, 0xFF, 0x00, 0xFF}));

  const auto braces = lex_all("rule x { }");
  EXPECT_EQ(braces[2].kind, TokenKind::LBrace);
}

TEST(Lexer, HexStringErrors) {
  EXPECT_EQ(first_error("$a = { 4D [2-4] 5A }").text,
            "jumps like [2-4] are not supported in hex strings (v1)");
  EXPECT_EQ(first_error("$a = { ( 4D | 5A ) }").text,
            "alternatives like (AA | BB) are not supported in hex strings (v1)");
  EXPECT_EQ(first_error("$a = { 4? }").text,
            "nibble wildcards like 'A?' are not supported; use '?\?' for a whole byte");
  EXPECT_EQ(first_error("$a = { ?4 }").text,
            "nibble wildcards like '?A' are not supported; use '?\?' for a whole byte");
  EXPECT_EQ(first_error("$a = { ~4D }").text,
            "negated bytes like ~AA are not supported in hex strings (v1)");
  EXPECT_EQ(first_error("$a = { 4 }").text, "hex bytes need two digits");
  EXPECT_EQ(first_error("$a = { 4D").text, "unterminated hex string (missing '}')");
  EXPECT_EQ(first_error("$a = { }").text, "empty hex string");
  const Token jump = first_error("$a = {\n  4D [2] }");
  EXPECT_EQ(jump.line, 2U);
  EXPECT_EQ(jump.column, 6U);
}

TEST(Lexer, StringIdentifiersWildcardsAndCounts) {
  const auto t = lex_all("$a $cfg* $* #a");
  ASSERT_EQ(t.size(), 5U);
  EXPECT_EQ(t[0].kind, TokenKind::StringId);
  EXPECT_EQ(t[0].text, "$a");
  EXPECT_EQ(t[1].kind, TokenKind::StringWildcard);
  EXPECT_EQ(t[1].text, "$cfg");
  EXPECT_EQ(t[2].kind, TokenKind::StringWildcard);
  EXPECT_EQ(t[2].text, "$");
  EXPECT_EQ(t[3].kind, TokenKind::CountId);
  EXPECT_EQ(t[3].text, "$a");
  EXPECT_EQ(first_error("$ ").text, "anonymous strings ('$' without a name) are not supported");
  EXPECT_EQ(first_error("# ").text, "expected a string name after '#'");
}

TEST(Lexer, CommentsAreSkippedAndLinesCounted) {
  const auto t = lex_all("// line one\n/* block\n comment */ rule");
  ASSERT_EQ(t.size(), 2U);
  EXPECT_EQ(t[0].text, "rule");
  EXPECT_EQ(t[0].line, 3U);
  EXPECT_EQ(t[0].column, 13U);
  EXPECT_EQ(first_error("/* never closed").text, "unterminated block comment");
}

TEST(Lexer, UnexpectedCharacters) {
  EXPECT_EQ(first_error("@").text, "unexpected character '@'");
  EXPECT_EQ(first_error("\x01").text, "unexpected character byte 0x01");
  EXPECT_EQ(first_error("!x").text, "unexpected '!'; use 'not' for negation");
  EXPECT_EQ(first_error(". ").text, "unexpected '.'; ranges are written as (START..END)");
  EXPECT_EQ(first_error(std::string(129, 'a')).text, "identifier is longer than 128 characters");
}

TEST(Lexer, LineTextStripsCarriageReturn) {
  const Lexer lexer("one\r\ntwo\nthree");
  EXPECT_EQ(lexer.line_text(1), "one");
  EXPECT_EQ(lexer.line_text(2), "two");
  EXPECT_EQ(lexer.line_text(3), "three");
  EXPECT_EQ(lexer.line_text(4), "");
  EXPECT_EQ(lexer.line_text(0), "");
}

}  // namespace
}  // namespace sigscan
