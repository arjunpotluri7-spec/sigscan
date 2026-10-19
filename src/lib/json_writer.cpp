#include "sigscan/json_writer.hpp"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>

namespace sigscan {
namespace {

// Length of the valid UTF-8 sequence starting at text[i], or 0 if it is invalid.
std::size_t utf8_sequence_length(std::string_view text, std::size_t i) {
  const auto b0 = static_cast<unsigned char>(text[i]);
  std::size_t len = 0;
  std::uint32_t min = 0;
  std::uint32_t cp = 0;
  if (b0 < 0x80) {
    return 1;
  }
  if ((b0 & 0xE0U) == 0xC0U) {
    len = 2;
    min = 0x80;
    cp = b0 & 0x1FU;
  } else if ((b0 & 0xF0U) == 0xE0U) {
    len = 3;
    min = 0x800;
    cp = b0 & 0x0FU;
  } else if ((b0 & 0xF8U) == 0xF0U) {
    len = 4;
    min = 0x10000;
    cp = b0 & 0x07U;
  } else {
    return 0;
  }
  if (i + len > text.size()) {
    return 0;
  }
  for (std::size_t k = 1; k < len; ++k) {
    const auto b = static_cast<unsigned char>(text[i + k]);
    if ((b & 0xC0U) != 0x80U) {
      return 0;
    }
    cp = (cp << 6U) | (b & 0x3FU);
  }
  if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
    return 0;
  }
  return len;
}

}  // namespace

std::string json_quote(std::string_view text) {
  static constexpr const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(text.size() + 2);
  out += '"';
  for (std::size_t i = 0; i < text.size();) {
    const auto c = static_cast<unsigned char>(text[i]);
    if (c >= 0x80) {
      const std::size_t len = utf8_sequence_length(text, i);
      if (len == 0) {
        out += "\\ufffd";
        ++i;
      } else {
        out.append(text.substr(i, len));
        i += len;
      }
      continue;
    }
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        if (c < 0x20 || c == 0x7F) {
          out += "\\u00";
          out += kHex[c >> 4U];
          out += kHex[c & 0x0FU];
        } else {
          out += static_cast<char>(c);
        }
        break;
    }
    ++i;
  }
  out += '"';
  return out;
}

JsonWriter::JsonWriter(std::ostream& out, int indent) : out_(out), indent_(indent) {}

void JsonWriter::newline() {
  if (indent_ <= 0) {
    return;
  }
  out_ << '\n';
  for (std::size_t i = 0; i < stack_.size() * static_cast<std::size_t>(indent_); ++i) {
    out_ << ' ';
  }
}

void JsonWriter::before_value() {
  if (after_key_) {
    after_key_ = false;
    return;
  }
  if (!stack_.empty()) {
    if (!stack_.back().empty) {
      out_ << ',';
    }
    stack_.back().empty = false;
    newline();
  }
}

void JsonWriter::begin_object() {
  before_value();
  out_ << '{';
  stack_.push_back(Frame{true, true});
}

void JsonWriter::end_object() {
  const bool empty = stack_.back().empty;
  stack_.pop_back();
  if (!empty) {
    newline();
  }
  out_ << '}';
  if (stack_.empty() && indent_ > 0) {
    out_ << '\n';
  }
}

void JsonWriter::begin_array() {
  before_value();
  out_ << '[';
  stack_.push_back(Frame{false, true});
}

void JsonWriter::end_array() {
  const bool empty = stack_.back().empty;
  stack_.pop_back();
  if (!empty) {
    newline();
  }
  out_ << ']';
  if (stack_.empty() && indent_ > 0) {
    out_ << '\n';
  }
}

void JsonWriter::key(std::string_view name) {
  before_value();
  out_ << json_quote(name) << (indent_ > 0 ? ": " : ":");
  after_key_ = true;
}

void JsonWriter::string(std::string_view text) {
  before_value();
  out_ << json_quote(text);
}

void JsonWriter::number(std::uint64_t value) {
  before_value();
  out_ << value;
}

void JsonWriter::number_signed(std::int64_t value) {
  before_value();
  out_ << value;
}

void JsonWriter::number_double(double value) {
  before_value();
  if (!std::isfinite(value)) {
    out_ << "null";
    return;
  }
  std::ostringstream tmp;
  tmp << std::setprecision(6) << value;
  out_ << tmp.str();
}

void JsonWriter::boolean(bool value) {
  before_value();
  out_ << (value ? "true" : "false");
}

void JsonWriter::null() {
  before_value();
  out_ << "null";
}

void JsonWriter::field(std::string_view name, std::string_view text) {
  key(name);
  string(text);
}

void JsonWriter::field_number(std::string_view name, std::uint64_t value) {
  key(name);
  number(value);
}

void JsonWriter::field_bool(std::string_view name, bool value) {
  key(name);
  boolean(value);
}

}  // namespace sigscan
