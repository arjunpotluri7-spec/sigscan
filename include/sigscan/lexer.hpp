#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sigscan {

enum class TokenKind {
  End,
  Error,           // text holds the message
  Identifier,      // keywords are identifiers too; the parser decides
  StringId,        // $name
  StringWildcard,  // $name* or $*  (text holds "$name" or "$")
  CountId,         // #name (text holds "$name" so it can be looked up directly)
  Text,            // "..." with escapes decoded into bytes
  Hex,             // { .. } decoded into bytes + mask
  Number,
  LBrace,
  RBrace,
  LParen,
  RParen,
  Comma,
  Colon,
  Assign,
  DotDot,
  Eq,
  Ne,
  Lt,
  Le,
  Gt,
  Ge,
};

[[nodiscard]] const char* token_kind_name(TokenKind kind);

struct Token {
  TokenKind kind = TokenKind::End;
  std::string text;
  std::vector<std::uint8_t> bytes;  // Text and Hex
  std::vector<std::uint8_t> mask;   // Hex: 0xFF = literal byte, 0x00 = ?? wildcard
  std::uint64_t number = 0;
  std::uint32_t line = 1;
  std::uint32_t column = 1;
  std::size_t offset = 0;      // byte offset of the first character
  std::size_t end_offset = 0;  // byte offset one past the last character
};

inline constexpr std::size_t kMaxStringBytes = 4096;
inline constexpr std::size_t kMaxIdentifierLength = 128;

// Pull lexer over a rule source. A '{' directly after '=' starts a hex string, which is the only
// context where hex bytes can appear, so the grammar needs no lexer modes beyond that.
class Lexer {
 public:
  explicit Lexer(std::string_view source);

  Token next();

  // The text of a 1-based line, without the newline. Empty if out of range.
  [[nodiscard]] std::string line_text(std::uint32_t line) const;

 private:
  [[nodiscard]] bool at_end() const { return pos_ >= src_.size(); }
  [[nodiscard]] char peek(std::size_t ahead = 0) const;
  char advance();
  bool skip_whitespace_and_comments(Token& error);
  Token make(TokenKind kind, std::size_t start, std::uint32_t line, std::uint32_t col) const;
  [[nodiscard]] Token error_at(std::string message, std::size_t start, std::uint32_t line,
                               std::uint32_t col) const;
  Token lex_number(std::size_t start, std::uint32_t line, std::uint32_t col);
  Token lex_text(std::size_t start, std::uint32_t line, std::uint32_t col);
  Token lex_hex(std::size_t start, std::uint32_t line, std::uint32_t col);
  Token lex_dollar(std::size_t start, std::uint32_t line, std::uint32_t col);
  void skip_line();

  std::string_view src_;
  std::size_t pos_ = 0;
  std::uint32_t line_ = 1;
  std::uint32_t col_ = 1;
  TokenKind prev_ = TokenKind::End;
  std::vector<std::size_t> line_starts_;
};

}  // namespace sigscan
