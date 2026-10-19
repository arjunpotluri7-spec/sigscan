#include "sigscan/lexer.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

namespace sigscan {
namespace {

bool is_ident_start(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool is_digit(char c) {
  return c >= '0' && c <= '9';
}

bool is_ident_char(char c) {
  return is_ident_start(c) || is_digit(c);
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

std::string describe_char(char c) {
  const auto byte = static_cast<unsigned char>(c);
  if (byte >= 0x21 && byte < 0x7F) {
    return std::string("'") + c + "'";
  }
  static constexpr const char* kDigits = "0123456789abcdef";
  std::string out = "byte 0x";
  out += kDigits[byte >> 4U];
  out += kDigits[byte & 0x0FU];
  return out;
}

}  // namespace

const char* token_kind_name(TokenKind kind) {
  switch (kind) {
    case TokenKind::End:
      return "end of file";
    case TokenKind::Error:
      return "invalid token";
    case TokenKind::Identifier:
      return "identifier";
    case TokenKind::StringId:
      return "string identifier";
    case TokenKind::StringWildcard:
      return "string wildcard";
    case TokenKind::CountId:
      return "string count";
    case TokenKind::Text:
      return "text string";
    case TokenKind::Hex:
      return "hex string";
    case TokenKind::Number:
      return "number";
    case TokenKind::LBrace:
      return "'{'";
    case TokenKind::RBrace:
      return "'}'";
    case TokenKind::LParen:
      return "'('";
    case TokenKind::RParen:
      return "')'";
    case TokenKind::Comma:
      return "','";
    case TokenKind::Colon:
      return "':'";
    case TokenKind::Assign:
      return "'='";
    case TokenKind::DotDot:
      return "'..'";
    case TokenKind::Eq:
      return "'=='";
    case TokenKind::Ne:
      return "'!='";
    case TokenKind::Lt:
      return "'<'";
    case TokenKind::Le:
      return "'<='";
    case TokenKind::Gt:
      return "'>'";
    case TokenKind::Ge:
      return "'>='";
  }
  return "token";
}

Lexer::Lexer(std::string_view source) : src_(source) {
  line_starts_.push_back(0);
  for (std::size_t i = 0; i < src_.size(); ++i) {
    if (src_[i] == '\n') {
      line_starts_.push_back(i + 1);
    }
  }
}

std::string Lexer::line_text(std::uint32_t line) const {
  if (line == 0 || line > line_starts_.size()) {
    return {};
  }
  const std::size_t start = line_starts_[line - 1];
  std::size_t end = src_.find('\n', start);
  if (end == std::string_view::npos) {
    end = src_.size();
  }
  if (end > start && src_[end - 1] == '\r') {
    --end;
  }
  return std::string(src_.substr(start, end - start));
}

char Lexer::peek(std::size_t ahead) const {
  return pos_ + ahead < src_.size() ? src_[pos_ + ahead] : '\0';
}

char Lexer::advance() {
  const char c = src_[pos_++];
  if (c == '\n') {
    ++line_;
    col_ = 1;
  } else {
    ++col_;
  }
  return c;
}

void Lexer::skip_line() {
  while (!at_end() && peek() != '\n') {
    advance();
  }
}

bool Lexer::skip_whitespace_and_comments(Token& error) {
  while (!at_end()) {
    const char c = peek();
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      advance();
    } else if (c == '/' && peek(1) == '/') {
      skip_line();
    } else if (c == '/' && peek(1) == '*') {
      const std::size_t start = pos_;
      const std::uint32_t line = line_;
      const std::uint32_t col = col_;
      advance();
      advance();
      bool closed = false;
      while (!at_end()) {
        if (peek() == '*' && peek(1) == '/') {
          advance();
          advance();
          closed = true;
          break;
        }
        advance();
      }
      if (!closed) {
        error = error_at("unterminated block comment", start, line, col);
        return false;
      }
    } else {
      break;
    }
  }
  return true;
}

Token Lexer::make(TokenKind kind, std::size_t start, std::uint32_t line, std::uint32_t col) const {
  Token tok;
  tok.kind = kind;
  tok.line = line;
  tok.column = col;
  tok.offset = start;
  tok.end_offset = pos_;
  tok.text = std::string(src_.substr(start, pos_ - start));
  return tok;
}

Token Lexer::error_at(std::string message, std::size_t start, std::uint32_t line,
                      std::uint32_t col) const {
  Token tok;
  tok.kind = TokenKind::Error;
  tok.text = std::move(message);
  tok.line = line;
  tok.column = col;
  tok.offset = start;
  tok.end_offset = pos_;
  return tok;
}

Token Lexer::next() {
  Token comment_error;
  if (!skip_whitespace_and_comments(comment_error)) {
    prev_ = TokenKind::Error;
    return comment_error;
  }
  const std::size_t start = pos_;
  const std::uint32_t line = line_;
  const std::uint32_t col = col_;
  if (at_end()) {
    Token tok = make(TokenKind::End, start, line, col);
    prev_ = TokenKind::End;
    return tok;
  }

  Token tok;
  const char c = peek();
  if (c == '{' && prev_ == TokenKind::Assign) {
    tok = lex_hex(start, line, col);
  } else if (is_ident_start(c)) {
    while (!at_end() && is_ident_char(peek())) {
      advance();
    }
    if (pos_ - start > kMaxIdentifierLength) {
      tok = error_at("identifier is longer than 128 characters", start, line, col);
    } else {
      tok = make(TokenKind::Identifier, start, line, col);
    }
  } else if (is_digit(c)) {
    tok = lex_number(start, line, col);
  } else if (c == '"') {
    tok = lex_text(start, line, col);
  } else if (c == '$') {
    tok = lex_dollar(start, line, col);
  } else if (c == '#') {
    advance();
    while (!at_end() && is_ident_char(peek())) {
      advance();
    }
    if (pos_ - start == 1) {
      tok = error_at("expected a string name after '#'", start, line, col);
    } else if (pos_ - start - 1 > kMaxIdentifierLength) {
      tok = error_at("identifier is longer than 128 characters", start, line, col);
    } else {
      tok = make(TokenKind::CountId, start, line, col);
      tok.text = "$" + tok.text.substr(1);
    }
  } else {
    advance();
    switch (c) {
      case '{':
        tok = make(TokenKind::LBrace, start, line, col);
        break;
      case '}':
        tok = make(TokenKind::RBrace, start, line, col);
        break;
      case '(':
        tok = make(TokenKind::LParen, start, line, col);
        break;
      case ')':
        tok = make(TokenKind::RParen, start, line, col);
        break;
      case ',':
        tok = make(TokenKind::Comma, start, line, col);
        break;
      case ':':
        tok = make(TokenKind::Colon, start, line, col);
        break;
      case '.':
        if (peek() == '.') {
          advance();
          tok = make(TokenKind::DotDot, start, line, col);
        } else {
          tok = error_at("unexpected '.'; ranges are written as (START..END)", start, line, col);
        }
        break;
      case '=':
        if (peek() == '=') {
          advance();
          tok = make(TokenKind::Eq, start, line, col);
        } else {
          tok = make(TokenKind::Assign, start, line, col);
        }
        break;
      case '!':
        if (peek() == '=') {
          advance();
          tok = make(TokenKind::Ne, start, line, col);
        } else {
          tok = error_at("unexpected '!'; use 'not' for negation", start, line, col);
        }
        break;
      case '<':
        if (peek() == '=') {
          advance();
          tok = make(TokenKind::Le, start, line, col);
        } else {
          tok = make(TokenKind::Lt, start, line, col);
        }
        break;
      case '>':
        if (peek() == '=') {
          advance();
          tok = make(TokenKind::Ge, start, line, col);
        } else {
          tok = make(TokenKind::Gt, start, line, col);
        }
        break;
      default:
        tok = error_at("unexpected character " + describe_char(c), start, line, col);
        break;
    }
  }
  prev_ = tok.kind;
  return tok;
}

Token Lexer::lex_number(std::size_t start, std::uint32_t line, std::uint32_t col) {
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t value = 0;
  bool overflow = false;
  if (peek() == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
    advance();
    advance();
    std::size_t digits = 0;
    while (!at_end() && hex_value(peek()) >= 0) {
      const auto d = static_cast<std::uint64_t>(hex_value(advance()));
      if (value > (kMax >> 4U)) {
        overflow = true;
      } else {
        value = (value << 4U) | d;
      }
      ++digits;
    }
    if (digits == 0) {
      return error_at("expected hex digits after '0x'", start, line, col);
    }
  } else {
    while (!at_end() && is_digit(peek())) {
      const auto d = static_cast<std::uint64_t>(advance() - '0');
      if (value > (kMax - d) / 10) {
        overflow = true;
      } else {
        value = (value * 10) + d;
      }
    }
  }
  if (!at_end() && is_ident_start(peek())) {
    const std::size_t suffix_start = pos_;
    while (!at_end() && is_ident_char(peek())) {
      advance();
    }
    const std::string_view suffix = src_.substr(suffix_start, pos_ - suffix_start);
    std::uint64_t factor = 0;
    if (suffix == "KB") {
      factor = 1024;
    } else if (suffix == "MB") {
      factor = 1024ULL * 1024;
    } else {
      return error_at("invalid number suffix '" + std::string(suffix) + "' (expected KB or MB)",
                      start, line, col);
    }
    if (value > kMax / factor) {
      overflow = true;
    } else {
      value *= factor;
    }
  }
  if (overflow) {
    return error_at("number does not fit in 64 bits", start, line, col);
  }
  Token tok = make(TokenKind::Number, start, line, col);
  tok.number = value;
  return tok;
}

Token Lexer::lex_text(std::size_t start, std::uint32_t line, std::uint32_t col) {
  advance();  // opening quote
  std::vector<std::uint8_t> bytes;
  Token first_error;
  bool failed = false;
  auto fail = [&](std::string message, std::size_t at, std::uint32_t l, std::uint32_t c) {
    if (!failed) {
      first_error = error_at(std::move(message), at, l, c);
      failed = true;
    }
  };
  for (;;) {
    if (at_end() || peek() == '\n') {
      return error_at("unterminated string (missing closing '\"')", start, line, col);
    }
    const std::size_t esc_pos = pos_;
    const std::uint32_t esc_line = line_;
    const std::uint32_t esc_col = col_;
    const char c = advance();
    if (c == '"') {
      break;
    }
    if (c != '\\') {
      bytes.push_back(static_cast<std::uint8_t>(c));
      continue;
    }
    if (at_end() || peek() == '\n') {
      return error_at("unterminated string (missing closing '\"')", start, line, col);
    }
    const char e = advance();
    switch (e) {
      case 'n':
        bytes.push_back('\n');
        break;
      case 't':
        bytes.push_back('\t');
        break;
      case 'r':
        bytes.push_back('\r');
        break;
      case '\\':
        bytes.push_back('\\');
        break;
      case '"':
        bytes.push_back('"');
        break;
      case 'x': {
        const int hi = hex_value(peek());
        const int lo = hi >= 0 ? hex_value(peek(1)) : -1;
        if (hi < 0 || lo < 0) {
          fail("invalid \\x escape; expected two hex digits", esc_pos, esc_line, esc_col);
        } else {
          advance();
          advance();
          bytes.push_back(static_cast<std::uint8_t>((static_cast<unsigned>(hi) << 4U) |
                                                    static_cast<unsigned>(lo)));
        }
        break;
      }
      default:
        fail("unknown escape sequence '\\" + std::string(1, e) +
                 "' (supported: \\n \\t \\r \\\\ \\\" \\xHH)",
             esc_pos, esc_line, esc_col);
        break;
    }
  }
  if (failed) {
    return first_error;
  }
  if (bytes.empty()) {
    return error_at("empty text string", start, line, col);
  }
  if (bytes.size() > kMaxStringBytes) {
    return error_at("string is longer than 4096 bytes", start, line, col);
  }
  Token tok = make(TokenKind::Text, start, line, col);
  tok.bytes = std::move(bytes);
  tok.mask.assign(tok.bytes.size(), 0xFF);
  return tok;
}

Token Lexer::lex_hex(std::size_t start, std::uint32_t line, std::uint32_t col) {
  advance();  // '{'
  std::vector<std::uint8_t> bytes;
  std::vector<std::uint8_t> mask;
  Token first_error;
  bool failed = false;
  auto fail = [&](std::string message, std::size_t at, std::uint32_t l, std::uint32_t c) {
    if (!failed) {
      first_error = error_at(std::move(message), at, l, c);
      failed = true;
    }
  };
  for (;;) {
    while (!at_end() && (peek() == ' ' || peek() == '\t' || peek() == '\r' || peek() == '\n')) {
      advance();
    }
    if (at_end()) {
      return error_at("unterminated hex string (missing '}')", start, line, col);
    }
    if (peek() == '/' && peek(1) == '/') {
      skip_line();
      continue;
    }
    const std::size_t at = pos_;
    const std::uint32_t l = line_;
    const std::uint32_t c = col_;
    const char ch = advance();
    if (ch == '}') {
      break;
    }
    if (failed) {
      continue;  // resynchronise on the closing brace
    }
    if (ch == '?') {
      if (peek() == '?') {
        advance();
        bytes.push_back(0);
        mask.push_back(0);
      } else {
        fail("nibble wildcards like '?A' are not supported; use '?\?' for a whole byte", at, l, c);
      }
    } else if (hex_value(ch) >= 0) {
      const char second = peek();
      if (hex_value(second) >= 0) {
        advance();
        bytes.push_back(static_cast<std::uint8_t>((static_cast<unsigned>(hex_value(ch)) << 4U) |
                                                  static_cast<unsigned>(hex_value(second))));
        mask.push_back(0xFF);
      } else if (second == '?') {
        fail("nibble wildcards like 'A?' are not supported; use '?\?' for a whole byte", at, l, c);
      } else {
        fail("hex bytes need two digits", at, l, c);
      }
    } else if (ch == '[') {
      fail("jumps like [2-4] are not supported in hex strings (v1)", at, l, c);
    } else if (ch == '(' || ch == '|') {
      fail("alternatives like (AA | BB) are not supported in hex strings (v1)", at, l, c);
    } else if (ch == '~') {
      fail("negated bytes like ~AA are not supported in hex strings (v1)", at, l, c);
    } else {
      fail("unexpected character " + describe_char(ch) + " in hex string", at, l, c);
    }
  }
  if (failed) {
    return first_error;
  }
  if (bytes.empty()) {
    return error_at("empty hex string", start, line, col);
  }
  if (bytes.size() > kMaxStringBytes) {
    return error_at("hex string is longer than 4096 bytes", start, line, col);
  }
  Token tok = make(TokenKind::Hex, start, line, col);
  tok.bytes = std::move(bytes);
  tok.mask = std::move(mask);
  return tok;
}

Token Lexer::lex_dollar(std::size_t start, std::uint32_t line, std::uint32_t col) {
  advance();  // '$'
  while (!at_end() && is_ident_char(peek())) {
    advance();
  }
  if (pos_ - start - 1 > kMaxIdentifierLength) {
    return error_at("identifier is longer than 128 characters", start, line, col);
  }
  if (peek() == '*') {
    advance();
    Token tok = make(TokenKind::StringWildcard, start, line, col);
    tok.text.pop_back();
    return tok;
  }
  if (pos_ - start == 1) {
    return error_at("anonymous strings ('$' without a name) are not supported", start, line, col);
  }
  return make(TokenKind::StringId, start, line, col);
}

}  // namespace sigscan
