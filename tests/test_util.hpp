#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "cli.hpp"
#include "sigscan/ruleset.hpp"
#include "sigscan/scanner.hpp"

namespace sigscan::test {

inline std::filesystem::path source_dir() {
  return SIGSCAN_SOURCE_DIR;
}

inline std::shared_ptr<const Ruleset> compile_or_fail(std::string_view source) {
  RulesetBuilder builder;
  builder.add_source(source, "test.sig");
  CompileResult result = builder.compile();
  std::string diags;
  for (const auto& d : result.diagnostics) {
    diags += d.format() + "\n";
  }
  EXPECT_NE(result.ruleset, nullptr) << diags;
  return result.ruleset;
}

inline std::vector<std::uint8_t> bytes_of(std::string_view text) {
  return {text.begin(), text.end()};
}

inline FileResult scan_text(const std::shared_ptr<const Ruleset>& rs, std::string_view text,
                            ScanOptions options = {}) {
  const Scanner scanner(rs, options);
  const auto data = bytes_of(text);
  return scanner.scan_buffer(data);
}

inline bool matched(const FileResult& r, std::string_view rule_name, const Ruleset& rs) {
  for (const auto& m : r.matches) {
    if (rs.rules()[m.rule_index].name == rule_name) {
      return true;
    }
  }
  return false;
}

// Scratch directory removed at scope exit.
class TempDir {
 public:
  TempDir() {
    static std::atomic<unsigned> counter{0};
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    path_ = std::filesystem::temp_directory_path() /
            ("sigscan-test-" + std::to_string(stamp) + "-" + std::to_string(counter++));
    std::filesystem::create_directories(path_);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }
  [[nodiscard]] std::filesystem::path operator/(std::string_view rel) const { return path_ / rel; }

 private:
  std::filesystem::path path_;
};

inline void write_file(const std::filesystem::path& path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary);
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

inline std::string read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

struct CliResult {
  int code = -1;
  std::string out;
  std::string err;
};

inline CliResult run_cli(const std::vector<std::string>& args) {
  std::ostringstream out;
  std::ostringstream err;
  CliResult r;
  r.code = cli::run(args, out, err);
  r.out = out.str();
  r.err = err.str();
  return r;
}

inline std::string demo_rules() {
  return (source_dir() / "samples/rules/demo.sig").string();
}
inline std::string sample_files() {
  return (source_dir() / "samples/files").string();
}

// --- minimal JSON parser for schema tests ------------------------------------------------------

struct Json;
using JsonArray = std::vector<Json>;
using JsonObject = std::map<std::string, Json>;

struct Json {
  std::variant<std::nullptr_t, bool, double, std::string, JsonArray, JsonObject> v;

  [[nodiscard]] bool is_object() const { return std::holds_alternative<JsonObject>(v); }
  [[nodiscard]] bool is_array() const { return std::holds_alternative<JsonArray>(v); }
  [[nodiscard]] bool is_string() const { return std::holds_alternative<std::string>(v); }
  [[nodiscard]] bool is_number() const { return std::holds_alternative<double>(v); }
  [[nodiscard]] bool is_bool() const { return std::holds_alternative<bool>(v); }
  [[nodiscard]] const JsonObject& obj() const { return std::get<JsonObject>(v); }
  [[nodiscard]] const JsonArray& arr() const { return std::get<JsonArray>(v); }
  [[nodiscard]] const std::string& str() const { return std::get<std::string>(v); }
  [[nodiscard]] double num() const { return std::get<double>(v); }
  [[nodiscard]] bool has(const std::string& k) const { return is_object() && obj().count(k) > 0; }
  [[nodiscard]] const Json& operator[](const std::string& k) const { return obj().at(k); }
  [[nodiscard]] const Json& operator[](std::size_t i) const { return arr().at(i); }
};

class JsonParser {
 public:
  explicit JsonParser(std::string_view text) : s_(text) {}

  Json parse() {
    Json value = parse_value();
    skip_ws();
    if (pos_ != s_.size()) {
      throw std::runtime_error("trailing characters in JSON");
    }
    return value;
  }

 private:
  void skip_ws() {
    while (pos_ < s_.size() &&
           (s_[pos_] == ' ' || s_[pos_] == '\n' || s_[pos_] == '\t' || s_[pos_] == '\r')) {
      ++pos_;
    }
  }
  char take() {
    if (pos_ >= s_.size()) {
      throw std::runtime_error("unexpected end of JSON");
    }
    return s_[pos_++];
  }
  void expect(char c) {
    if (take() != c) {
      throw std::runtime_error(std::string("expected '") + c + "' in JSON");
    }
  }
  Json parse_value() {
    skip_ws();
    const char c = pos_ < s_.size() ? s_[pos_] : '\0';
    if (c == '{') {
      ++pos_;
      JsonObject o;
      skip_ws();
      if (pos_ < s_.size() && s_[pos_] == '}') {
        ++pos_;
        return Json{o};
      }
      for (;;) {
        skip_ws();
        std::string key = parse_string();
        skip_ws();
        expect(':');
        o[key] = parse_value();
        skip_ws();
        const char d = take();
        if (d == '}') {
          return Json{o};
        }
        if (d != ',') {
          throw std::runtime_error("expected ',' or '}' in JSON object");
        }
      }
    }
    if (c == '[') {
      ++pos_;
      JsonArray a;
      skip_ws();
      if (pos_ < s_.size() && s_[pos_] == ']') {
        ++pos_;
        return Json{a};
      }
      for (;;) {
        a.push_back(parse_value());
        skip_ws();
        const char d = take();
        if (d == ']') {
          return Json{a};
        }
        if (d != ',') {
          throw std::runtime_error("expected ',' or ']' in JSON array");
        }
      }
    }
    if (c == '"') {
      return Json{parse_string()};
    }
    if (s_.substr(pos_, 4) == "true") {
      pos_ += 4;
      return Json{true};
    }
    if (s_.substr(pos_, 5) == "false") {
      pos_ += 5;
      return Json{false};
    }
    if (s_.substr(pos_, 4) == "null") {
      pos_ += 4;
      return Json{nullptr};
    }
    const std::size_t start = pos_;
    while (pos_ < s_.size() &&
           (std::isdigit(static_cast<unsigned char>(s_[pos_])) != 0 || s_[pos_] == '-' ||
            s_[pos_] == '.' || s_[pos_] == 'e' || s_[pos_] == 'E' || s_[pos_] == '+')) {
      ++pos_;
    }
    if (start == pos_) {
      throw std::runtime_error("invalid JSON value");
    }
    return Json{std::stod(std::string(s_.substr(start, pos_ - start)))};
  }
  std::string parse_string() {
    expect('"');
    std::string out;
    for (;;) {
      const char c = take();
      if (c == '"') {
        return out;
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        throw std::runtime_error("raw control character in JSON string");
      }
      if (c != '\\') {
        out += c;
        continue;
      }
      const char e = take();
      switch (e) {
        case 'n':
          out += '\n';
          break;
        case 't':
          out += '\t';
          break;
        case 'r':
          out += '\r';
          break;
        case 'b':
          out += '\b';
          break;
        case 'f':
          out += '\f';
          break;
        case 'u': {
          const std::string hex(s_.substr(pos_, 4));
          pos_ += 4;
          const auto cp = static_cast<unsigned>(std::stoul(hex, nullptr, 16));
          if (cp < 0x80) {
            out += static_cast<char>(cp);
          } else {
            out += "\xEF\xBF\xBD";  // good enough for tests: non-ASCII escapes are U+FFFD here
          }
          break;
        }
        default:
          out += e;
          break;
      }
    }
  }

  std::string_view s_;
  std::size_t pos_ = 0;
};

inline Json parse_json(std::string_view text) {
  return JsonParser(text).parse();
}

}  // namespace sigscan::test
