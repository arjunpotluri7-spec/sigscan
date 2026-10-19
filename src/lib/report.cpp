#include "sigscan/report.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "sigscan/json_writer.hpp"

namespace sigscan {
namespace {

constexpr std::size_t kSarifLocationsPerResult = 10;
constexpr std::size_t kSnippetsShown = 8;  // per string, in the table and in JSON

std::string hex_offset(std::uint64_t value) {
  std::ostringstream out;
  out << "0x" << std::hex << value;
  return out.str();
}

std::string join(const std::vector<std::string>& items, const char* sep) {
  std::string out;
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      out += sep;
    }
    out += items[i];
  }
  return out;
}

std::string pad(const std::string& text, std::size_t width) {
  return text.size() >= width ? text + "  " : text + std::string(width - text.size() + 2, ' ');
}

const char* sarif_level(Severity s) {
  switch (s) {
    case Severity::Critical:
    case Severity::High:
      return "error";
    case Severity::Medium:
      return "warning";
    case Severity::Low:
      return "note";
  }
  return "warning";
}

const char* security_severity(Severity s) {
  switch (s) {
    case Severity::Critical:
      return "9.5";
    case Severity::High:
      return "8.0";
    case Severity::Medium:
      return "5.0";
    case Severity::Low:
      return "2.0";
  }
  return "5.0";
}

std::string meta_text(const Rule& rule, const char* key) {
  const MetaEntry* entry = rule.find_meta(key);
  return entry == nullptr ? std::string() : entry->value.text;
}

// RFC 3986 percent-encoding for a relative or absolute file path.
std::string to_uri(const std::string& path) {
  static constexpr const char* kHex = "0123456789ABCDEF";
  std::string out;
  if (!path.empty() && path.front() == '/') {
    out = "file://";
  }
  for (const char ch : path) {
    const auto c = static_cast<unsigned char>(ch);
    const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' ||
                            c == '~' || c == '/';
    if (unreserved) {
      out += static_cast<char>(c);
    } else {
      out += '%';
      out += kHex[c >> 4U];
      out += kHex[c & 0x0FU];
    }
  }
  return out;
}

void write_meta(JsonWriter& w, const Rule& rule) {
  w.begin_object();
  for (const MetaEntry& entry : rule.meta) {
    w.key(entry.key);
    switch (entry.value.type) {
      case MetaValue::Type::String:
        w.string(entry.value.text);
        break;
      case MetaValue::Type::Integer:
        w.number(entry.value.integer);
        break;
      case MetaValue::Type::Boolean:
        w.boolean(entry.value.boolean);
        break;
    }
  }
  w.end_object();
}

void write_strings(JsonWriter& w, const RuleMatch& match, bool show_strings,
                   std::size_t snippet_limit) {
  w.begin_array();
  for (const StringReport& s : match.strings) {
    w.begin_object();
    w.field("id", s.id);
    w.field_number("count", s.hits.count);
    w.key("offsets");
    w.begin_array();
    for (const MatchRecord& m : s.hits.matches) {
      w.number(m.offset);
    }
    w.end_array();
    w.field_bool("offsets_truncated", s.hits.count > s.hits.matches.size());
    if (show_strings) {
      w.key("snippets");
      w.begin_array();
      for (std::size_t i = 0; i < s.hits.matches.size() && i < snippet_limit; ++i) {
        const MatchRecord& m = s.hits.matches[i];
        w.begin_object();
        w.field_number("offset", m.offset);
        w.field_number("length", m.length);
        w.field_number("context_offset", m.context_offset);
        w.field("hex", hex_bytes(m.context));
        w.field("ascii", printable_bytes(m.context));
        w.end_object();
      }
      w.end_array();
    }
    w.end_object();
  }
  w.end_array();
}

}  // namespace

ScanSummary summarize(const ScanReport& report) {
  ScanSummary s;
  for (const FileResult& f : report.files) {
    switch (f.status) {
      case FileStatus::Scanned:
        ++s.files_scanned;
        s.bytes_scanned += f.size;
        if (!f.matches.empty()) {
          ++s.files_matched;
          s.matches += f.matches.size();
        }
        break;
      case FileStatus::Skipped:
        ++s.skipped;
        break;
      case FileStatus::Error:
        ++s.errors;
        break;
    }
  }
  return s;
}

std::string hex_bytes(const std::vector<std::uint8_t>& bytes) {
  static constexpr const char* kHex = "0123456789abcdef";
  std::string out;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      out += ' ';
    }
    out += kHex[bytes[i] >> 4U];
    out += kHex[bytes[i] & 0x0FU];
  }
  return out;
}

std::string printable_bytes(const std::vector<std::uint8_t>& bytes) {
  std::string out;
  out.reserve(bytes.size());
  for (const std::uint8_t b : bytes) {
    out += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
  }
  return out;
}

void write_table(std::ostream& out, const ScanReport& report, const Ruleset& ruleset,
                 bool show_strings) {
  const auto& rules = ruleset.rules();
  constexpr std::size_t sev_w = 8;
  std::size_t rule_w = 4;
  for (const FileResult& f : report.files) {
    for (const RuleMatch& m : f.matches) {
      rule_w = std::max(rule_w, rules[m.rule_index].name.size());
    }
  }
  const std::string indent(sev_w + 2, ' ');
  const ScanSummary summary = summarize(report);

  if (summary.matches == 0) {
    out << "No matches.\n";
  } else {
    out << pad("SEVERITY", sev_w) << pad("RULE", rule_w) << "FILE\n";
    for (const FileResult& f : report.files) {
      for (const RuleMatch& m : f.matches) {
        const Rule& rule = rules[m.rule_index];
        out << pad(severity_name(rule.severity), sev_w) << pad(rule.name, rule_w) << f.path << '\n';
        if (!rule.tags.empty()) {
          out << indent << "tags: " << join(rule.tags, ", ") << '\n';
        }
        out << indent << "why:  " << m.why << '\n';
        std::vector<std::string> summary_parts;
        for (const StringReport& s : m.strings) {
          std::string part = s.id + " x" + std::to_string(s.hits.count);
          if (!s.hits.matches.empty()) {
            part += " @" + hex_offset(s.hits.matches.front().offset);
          }
          summary_parts.push_back(part);
        }
        if (!summary_parts.empty() && !show_strings) {
          out << indent << "hits: " << join(summary_parts, ", ") << '\n';
        }
        if (show_strings) {
          for (const StringReport& s : m.strings) {
            const std::size_t limit = kSnippetsShown;
            for (std::size_t i = 0; i < s.hits.matches.size() && i < limit; ++i) {
              const MatchRecord& rec = s.hits.matches[i];
              out << indent << s.id << " @" << hex_offset(rec.offset) << " len " << rec.length
                  << "  " << hex_bytes(rec.context) << "  |" << printable_bytes(rec.context)
                  << "|\n";
            }
            if (s.hits.count > std::min<std::uint64_t>(s.hits.matches.size(), limit)) {
              out << indent << s.id << " ... " << s.hits.count << " hits in total\n";
            }
          }
        }
      }
    }
  }

  bool printed_header = false;
  for (const FileResult& f : report.files) {
    if (f.status == FileStatus::Scanned) {
      continue;
    }
    if (!printed_header) {
      out << "\nNot scanned:\n";
      printed_header = true;
    }
    out << "  " << (f.status == FileStatus::Skipped ? "skipped " : "error   ") << f.path << ": "
        << f.message << '\n';
  }
  if (report.truncated) {
    out << "\nWarning: the --max-files limit was reached; some files were not scanned.\n";
  }
  out << "\nScanned " << summary.files_scanned << (summary.files_scanned == 1 ? " file" : " files")
      << " (" << format_size(summary.bytes_scanned) << "): " << summary.matches
      << (summary.matches == 1 ? " match" : " matches") << " in " << summary.files_matched
      << (summary.files_matched == 1 ? " file" : " files") << ", " << summary.skipped
      << " skipped, " << summary.errors << (summary.errors == 1 ? " error" : " errors") << ".\n";
}

void write_json(std::ostream& out, const ScanReport& report, const Ruleset& ruleset,
                bool show_strings) {
  const auto& rules = ruleset.rules();
  const ScanSummary summary = summarize(report);
  JsonWriter w(out);
  w.begin_object();
  w.field("tool", "sigscan");
  w.field("version", kVersion);
  w.field_number("schema_version", kJsonSchemaVersion);
  w.key("rule_files");
  w.begin_array();
  for (const std::string& f : report.rule_files) {
    w.string(f);
  }
  w.end_array();
  w.key("summary");
  w.begin_object();
  w.field_number("files_scanned", summary.files_scanned);
  w.field_number("files_matched", summary.files_matched);
  w.field_number("matches", summary.matches);
  w.field_number("skipped", summary.skipped);
  w.field_number("errors", summary.errors);
  w.field_number("bytes_scanned", summary.bytes_scanned);
  w.field_bool("truncated", report.truncated);
  w.end_object();

  w.key("matches");
  w.begin_array();
  for (const FileResult& f : report.files) {
    for (const RuleMatch& m : f.matches) {
      const Rule& rule = rules[m.rule_index];
      w.begin_object();
      w.field("file", f.path);
      w.field_number("file_size", f.size);
      w.field("rule", rule.name);
      w.key("tags");
      w.begin_array();
      for (const std::string& t : rule.tags) {
        w.string(t);
      }
      w.end_array();
      w.field("severity", severity_name(rule.severity));
      w.key("meta");
      write_meta(w, rule);
      w.field("condition", rule.condition_text);
      w.field("why", m.why);
      w.key("strings");
      write_strings(w, m, show_strings, kSnippetsShown);
      w.end_object();
    }
  }
  w.end_array();

  w.key("skipped");
  w.begin_array();
  for (const FileResult& f : report.files) {
    if (f.status == FileStatus::Skipped) {
      w.begin_object();
      w.field("file", f.path);
      w.field("reason", f.message);
      w.end_object();
    }
  }
  w.end_array();
  w.key("errors");
  w.begin_array();
  for (const FileResult& f : report.files) {
    if (f.status == FileStatus::Error) {
      w.begin_object();
      w.field("file", f.path);
      w.field("message", f.message);
      w.end_object();
    }
  }
  w.end_array();
  w.end_object();
}

void write_sarif(std::ostream& out, const ScanReport& report, const Ruleset& ruleset) {
  const auto& rules = ruleset.rules();
  JsonWriter w(out);
  w.begin_object();
  w.field("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
  w.field("version", "2.1.0");
  w.key("runs");
  w.begin_array();
  w.begin_object();

  w.key("tool");
  w.begin_object();
  w.key("driver");
  w.begin_object();
  w.field("name", "sigscan");
  w.field("version", kVersion);
  w.field("semanticVersion", kVersion);
  w.key("rules");
  w.begin_array();
  for (const Rule& rule : rules) {
    w.begin_object();
    w.field("id", rule.name);
    w.field("name", rule.name);
    const std::string description = meta_text(rule, "description");
    w.key("shortDescription");
    w.begin_object();
    w.field("text", description.empty() ? rule.name : description);
    w.end_object();
    w.key("fullDescription");
    w.begin_object();
    w.field("text", "Condition: " + rule.condition_text);
    w.end_object();
    w.key("defaultConfiguration");
    w.begin_object();
    w.field("level", sarif_level(rule.severity));
    w.end_object();
    w.key("properties");
    w.begin_object();
    w.key("tags");
    w.begin_array();
    for (const std::string& t : rule.tags) {
      w.string(t);
    }
    w.end_array();
    w.field("severity", severity_name(rule.severity));
    w.field("security-severity", security_severity(rule.severity));
    w.end_object();
    w.end_object();
  }
  w.end_array();
  w.end_object();  // driver
  w.end_object();  // tool

  w.key("results");
  w.begin_array();
  for (const FileResult& f : report.files) {
    for (const RuleMatch& m : f.matches) {
      const Rule& rule = rules[m.rule_index];
      w.begin_object();
      w.field("ruleId", rule.name);
      w.field_number("ruleIndex", m.rule_index);
      w.field("level", sarif_level(rule.severity));
      w.key("message");
      w.begin_object();
      w.field("text", rule.name + " " + m.why);
      w.end_object();
      w.key("locations");
      w.begin_array();
      std::size_t emitted = 0;
      auto location = [&](const MatchRecord* rec) {
        w.begin_object();
        w.key("physicalLocation");
        w.begin_object();
        w.key("artifactLocation");
        w.begin_object();
        w.field("uri", to_uri(f.path));
        w.end_object();
        if (rec != nullptr) {
          w.key("region");
          w.begin_object();
          w.field_number("byteOffset", rec->offset);
          w.field_number("byteLength", rec->length);
          w.end_object();
        }
        w.end_object();
        w.end_object();
      };
      for (const StringReport& s : m.strings) {
        if (!s.hits.matches.empty() && emitted < kSarifLocationsPerResult) {
          location(&s.hits.matches.front());
          ++emitted;
        }
      }
      if (emitted == 0) {
        location(nullptr);
      }
      w.end_array();
      w.key("properties");
      w.begin_object();
      w.key("tags");
      w.begin_array();
      for (const std::string& t : rule.tags) {
        w.string(t);
      }
      w.end_array();
      w.key("strings");
      w.begin_object();
      for (const StringReport& s : m.strings) {
        w.field_number(s.id, s.hits.count);
      }
      w.end_object();
      w.end_object();
      w.end_object();
    }
  }
  w.end_array();

  w.key("invocations");
  w.begin_array();
  w.begin_object();
  w.field_bool("executionSuccessful", true);
  w.key("toolExecutionNotifications");
  w.begin_array();
  for (const FileResult& f : report.files) {
    if (f.status == FileStatus::Scanned) {
      continue;
    }
    w.begin_object();
    w.field("level", f.status == FileStatus::Error ? "error" : "warning");
    w.key("message");
    w.begin_object();
    w.field("text", f.path + ": " + f.message);
    w.end_object();
    w.end_object();
  }
  w.end_array();
  w.end_object();
  w.end_array();

  w.end_object();  // run
  w.end_array();
  w.end_object();
}

}  // namespace sigscan
