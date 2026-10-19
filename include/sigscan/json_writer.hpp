#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace sigscan {

// Quoted JSON string. Invalid UTF-8 (common in file names and binary snippets) becomes U+FFFD.
[[nodiscard]] std::string json_quote(std::string_view text);

// Minimal pretty-printing JSON writer that tracks commas for the caller.
class JsonWriter {
 public:
  explicit JsonWriter(std::ostream& out, int indent = 2);

  void begin_object();
  void end_object();
  void begin_array();
  void end_array();
  void key(std::string_view name);
  void string(std::string_view text);
  void number(std::uint64_t value);
  void number_signed(std::int64_t value);
  void number_double(double value);
  void boolean(bool value);
  void null();

  // key + value shorthands
  void field(std::string_view name, std::string_view text);
  void field_number(std::string_view name, std::uint64_t value);
  void field_bool(std::string_view name, bool value);

 private:
  struct Frame {
    bool object = false;
    bool empty = true;
  };
  void before_value();
  void newline();

  std::ostream& out_;
  int indent_;
  std::vector<Frame> stack_;
  bool after_key_ = false;
};

}  // namespace sigscan
