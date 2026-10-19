#include "sigscan/log.hpp"

#include <mutex>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

#include "sigscan/json_writer.hpp"

namespace sigscan {
namespace {

const char* level_name(LogLevel level) {
  switch (level) {
    case LogLevel::Error:
      return "error";
    case LogLevel::Warn:
      return "warn";
    case LogLevel::Info:
      return "info";
    case LogLevel::Debug:
      return "debug";
  }
  return "info";
}

bool needs_quotes(std::string_view value) {
  return value.empty() || value.find_first_of(" \t\"=\n") != std::string_view::npos;
}

}  // namespace

std::optional<LogLevel> parse_log_level(std::string_view text) {
  if (text == "error") {
    return LogLevel::Error;
  }
  if (text == "warn" || text == "warning") {
    return LogLevel::Warn;
  }
  if (text == "info") {
    return LogLevel::Info;
  }
  if (text == "debug") {
    return LogLevel::Debug;
  }
  return std::nullopt;
}

std::optional<LogFormat> parse_log_format(std::string_view text) {
  if (text == "text") {
    return LogFormat::Text;
  }
  if (text == "json") {
    return LogFormat::Json;
  }
  return std::nullopt;
}

Logger::Logger(std::ostream& out, LogLevel level, LogFormat format)
    : out_(out), level_(level), format_(format) {}

void Logger::log(LogLevel level, std::string_view message, const LogFields& fields) {
  if (!enabled(level)) {
    return;
  }
  std::string line;
  if (format_ == LogFormat::Json) {
    line = "{\"level\":" + json_quote(level_name(level)) + ",\"msg\":" + json_quote(message);
    for (const auto& [key, value] : fields) {
      line += "," + json_quote(key) + ":" + json_quote(value);
    }
    line += '}';
  } else {
    line = std::string("sigscan: ") + level_name(level) + ": " + std::string(message);
    for (const auto& [key, value] : fields) {
      line += " " + key + "=" + (needs_quotes(value) ? json_quote(value) : value);
    }
  }
  const std::lock_guard<std::mutex> lock(mutex_);
  out_ << line << '\n';
  out_.flush();
}

}  // namespace sigscan
