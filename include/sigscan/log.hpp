#pragma once

#include <mutex>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sigscan {

enum class LogLevel { Error = 0, Warn = 1, Info = 2, Debug = 3 };
enum class LogFormat { Text, Json };

[[nodiscard]] std::optional<LogLevel> parse_log_level(std::string_view text);
[[nodiscard]] std::optional<LogFormat> parse_log_format(std::string_view text);

using LogFields = std::vector<std::pair<std::string, std::string>>;

// Structured logger for stderr. Text: "sigscan: warn: message key=value". JSON: one object per
// line with "level", "msg" and the fields.
class Logger {
 public:
  Logger(std::ostream& out, LogLevel level, LogFormat format);

  [[nodiscard]] bool enabled(LogLevel level) const { return level <= level_; }
  void log(LogLevel level, std::string_view message, const LogFields& fields = {});

  void error(std::string_view m, const LogFields& f = {}) { log(LogLevel::Error, m, f); }
  void warn(std::string_view m, const LogFields& f = {}) { log(LogLevel::Warn, m, f); }
  void info(std::string_view m, const LogFields& f = {}) { log(LogLevel::Info, m, f); }
  void debug(std::string_view m, const LogFields& f = {}) { log(LogLevel::Debug, m, f); }

  void set_level(LogLevel level) { level_ = level; }
  void set_format(LogFormat format) { format_ = format; }

 private:
  std::ostream& out_;
  LogLevel level_;
  LogFormat format_;
  std::mutex mutex_;
};

}  // namespace sigscan
