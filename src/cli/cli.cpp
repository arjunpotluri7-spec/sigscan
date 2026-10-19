#include "cli.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "sigscan/diagnostics.hpp"
#include "sigscan/file_io.hpp"
#include "sigscan/log.hpp"
#include "sigscan/report.hpp"
#include "sigscan/ruleset.hpp"
#include "sigscan/scanner.hpp"
#include "sigscan/walker.hpp"
#include "sigscan/worker_pool.hpp"

#ifdef _WIN32
#include <fstream>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace sigscan::cli {
namespace {

namespace fs = std::filesystem;

constexpr std::uint64_t kMaxConfigBytes = 1024ULL * 1024;
constexpr std::uint64_t kMaxBenchBytes = 1024ULL * 1024 * 1024;

constexpr const char* kMainHelp = R"(sigscan - explainable signature scanner for files

Usage:
  sigscan scan  -r RULES [-r RULES ...] PATH... [options]
  sigscan check RULES...
  sigscan bench -r RULES PATH [--iterations N]
  sigscan --version | --help

Commands:
  scan    Scan files and directories with one or more .sig rule files
  check   Validate and compile rule files, then print automaton statistics
  bench   Compare the Aho-Corasick engine with a naive per-pattern scanner

Global options:
  --log-level LEVEL    error, warn, info (default) or debug; logs go to stderr
  --log-format FORMAT  text (default) or json
  -h, --help           Show help (also: sigscan COMMAND --help)
  -V, --version        Show the version

Exit codes:
  0  ran fine, no match at or above --fail-on
  1  at least one match at or above --fail-on
  2  usage, configuration, rule or input error
)";

constexpr const char* kScanHelp = R"(Usage: sigscan scan -r RULES [-r RULES ...] PATH... [options]

Scans files and directories (recursively) and reports which rules match, where, and why.
Files are only read; they are never executed or modified.

Options:
  -r, --rules FILE         Rule file (.sig); repeatable, at least one required
  -f, --format FORMAT      table (default), json or sarif
  -o, --output FILE        Write the report to FILE (created 0600) instead of stdout
      --force              Allow --output to overwrite an existing file
      --fail-on SEVERITY   low (default), medium, high, critical or none
      --show-strings       Include hex/ASCII snippets of every matched string
      --max-filesize SIZE  Skip larger files (default 64MB; suffixes KB, MB, GB)
      --max-matches N      Offsets kept per string (default 1000; counts stay exact)
      --max-files N        Stop after N files (default 100000)
      --skip GLOB          Skip paths matching GLOB (repeatable; ** crosses directories)
      --follow-symlinks    Scan symlinked files found while walking (directory symlinks
                           are never followed)
  -j, --threads N          Worker threads (default: CPU count, at most 8); output order is
                           always sorted by path
      --config FILE        Read defaults from a key = value config file
)";

constexpr const char* kCheckHelp = R"(Usage: sigscan check RULES...

Parses and compiles rule files. Prints errors and warnings as file:line:col diagnostics and,
on success, statistics about the compiled automaton. Exit code 0 if valid, 2 on any error.
)";

constexpr const char* kBenchHelp = R"(Usage: sigscan bench -r RULES [-r RULES ...] PATH [options]

Loads the files under PATH into memory, then times the Aho-Corasick engine and the naive
per-pattern scanner on exactly the same bytes and checks that both find the same hits.

Options:
  -r, --rules FILE         Rule file (.sig); repeatable
      --iterations N       Timed passes per engine (default 3)
      --max-filesize SIZE  Skip larger files (default 64MB)
)";

// --- small parsing helpers ----------------------------------------------------------------------

std::optional<std::uint64_t> parse_uint(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    const auto d = static_cast<std::uint64_t>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - d) / 10) {
      return std::nullopt;
    }
    value = (value * 10) + d;
  }
  return value;
}

std::string lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
  });
  return out;
}

std::optional<std::uint64_t> parse_size(std::string_view text) {
  std::size_t digits = 0;
  while (digits < text.size() && text[digits] >= '0' && text[digits] <= '9') {
    ++digits;
  }
  const auto number = parse_uint(text.substr(0, digits));
  if (!number) {
    return std::nullopt;
  }
  const std::string suffix = lower(text.substr(digits));
  std::uint64_t factor = 0;
  if (suffix.empty() || suffix == "b") {
    factor = 1;
  } else if (suffix == "k" || suffix == "kb" || suffix == "kib") {
    factor = 1024;
  } else if (suffix == "m" || suffix == "mb" || suffix == "mib") {
    factor = 1024ULL * 1024;
  } else if (suffix == "g" || suffix == "gb" || suffix == "gib") {
    factor = 1024ULL * 1024 * 1024;
  } else {
    return std::nullopt;
  }
  if (*number > std::numeric_limits<std::uint64_t>::max() / factor) {
    return std::nullopt;
  }
  return *number * factor;
}

std::optional<bool> parse_bool(std::string_view text) {
  const std::string v = lower(text);
  if (v == "true" || v == "yes" || v == "1" || v == "on") {
    return true;
  }
  if (v == "false" || v == "no" || v == "0" || v == "off") {
    return false;
  }
  return std::nullopt;
}

std::string trim(std::string_view text) {
  const auto start = text.find_first_not_of(" \t\r");
  if (start == std::string_view::npos) {
    return {};
  }
  const auto end = text.find_last_not_of(" \t\r");
  return std::string(text.substr(start, end - start + 1));
}

struct UsageError {
  std::string message;
};

// Iterates over arguments, splitting "--name=value" and fetching separate values.
class ArgReader {
 public:
  explicit ArgReader(const std::vector<std::string>& args) : args_(args) {}

  [[nodiscard]] bool done() const { return pos_ >= args_.size(); }

  // Returns the next argument; for "--name=value" returns "--name" and keeps the value.
  std::string next() {
    std::string arg = args_[pos_++];
    inline_value_.reset();
    if (arg.starts_with("--")) {
      const auto eq = arg.find('=');
      if (eq != std::string::npos) {
        inline_value_ = arg.substr(eq + 1);
        arg.resize(eq);
      }
    }
    return arg;
  }

  std::string value(const std::string& option) {
    if (inline_value_) {
      std::string v = *inline_value_;
      inline_value_.reset();
      return v;
    }
    if (done()) {
      throw UsageError{"option " + option + " needs a value"};
    }
    return args_[pos_++];
  }

  void no_value(const std::string& option) {
    if (inline_value_) {
      throw UsageError{"option " + option + " does not take a value"};
    }
  }

 private:
  const std::vector<std::string>& args_;
  std::size_t pos_ = 0;
  std::optional<std::string> inline_value_;
};

std::uint64_t require_size(const std::string& option, const std::string& text) {
  const auto v = parse_size(text);
  if (!v || *v == 0) {
    throw UsageError{"invalid size for " + option + ": '" + text + "' (examples: 512KB, 64MB)"};
  }
  return *v;
}

std::uint64_t require_count(const std::string& option, const std::string& text, std::uint64_t max) {
  const auto v = parse_uint(text);
  if (!v || *v == 0 || *v > max) {
    throw UsageError{"invalid value for " + option + ": '" + text + "' (expected 1.." +
                     std::to_string(max) + ")"};
  }
  return *v;
}

// --- shared setup --------------------------------------------------------------------------------

struct Globals {
  LogLevel level = LogLevel::Info;
  LogFormat format = LogFormat::Text;
  bool help = false;
  bool version = false;
  std::vector<std::string> rest;
};

Globals extract_globals(const std::vector<std::string>& args) {
  Globals g;
  bool command_seen = false;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& arg = args[i];
    std::string value;
    auto take = [&](const std::string& name) {
      if (arg == name) {
        if (i + 1 >= args.size()) {
          throw UsageError{"option " + name + " needs a value"};
        }
        value = args[++i];
        return true;
      }
      if (arg.starts_with(name + "=")) {
        value = arg.substr(name.size() + 1);
        return true;
      }
      return false;
    };
    if (take("--log-level")) {
      const auto level = parse_log_level(value);
      if (!level) {
        throw UsageError{"invalid --log-level '" + value +
                         "' (expected error, warn, info or debug)"};
      }
      g.level = *level;
    } else if (take("--log-format")) {
      const auto format = parse_log_format(value);
      if (!format) {
        throw UsageError{"invalid --log-format '" + value + "' (expected text or json)"};
      }
      g.format = *format;
    } else if (arg == "-h" || arg == "--help") {
      g.help = true;
    } else if (!command_seen && (arg == "-V" || arg == "--version")) {
      g.version = true;
    } else {
      g.rest.push_back(arg);
      if (!arg.starts_with("-")) {
        command_seen = true;
      }
    }
  }
  return g;
}

void print_diagnostics(const std::vector<Diagnostic>& diagnostics, std::ostream& err) {
  for (const Diagnostic& d : diagnostics) {
    err << d.format() << '\n';
  }
}

struct LoadedRules {
  std::shared_ptr<const Ruleset> ruleset;
  std::vector<std::string> files;
};

std::optional<LoadedRules> load_rules(const std::vector<std::string>& files, Logger& log,
                                      std::ostream& err) {
  RulesetBuilder builder;
  for (const std::string& f : files) {
    builder.add_file(f);
  }
  CompileResult compiled = builder.compile();
  print_diagnostics(compiled.diagnostics, err);
  if (!compiled.ruleset) {
    log.error("rules failed to load",
              {{"errors", std::to_string(count_level(compiled.diagnostics, DiagLevel::Error))}});
    return std::nullopt;
  }
  const RulesetStats stats = compiled.ruleset->stats();
  log.debug("rules compiled", {{"rules", std::to_string(stats.rules)},
                               {"atoms", std::to_string(stats.atoms)},
                               {"states", std::to_string(stats.states)}});
  return LoadedRules{compiled.ruleset, files};
}

std::optional<std::string> write_report_file(const std::string& path, const std::string& content,
                                             bool force) {
#ifdef _WIN32
  std::error_code ec;
  if (!force && fs::exists(path, ec)) {
    return "refusing to overwrite existing file (use --force)";
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return "cannot open for writing";
  }
  out << content;
  return out ? std::nullopt : std::optional<std::string>("write failed");
#else
  int flags = O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC;
  flags |= force ? O_TRUNC : O_EXCL;
  const int fd = ::open(path.c_str(), flags, 0600);  // NOLINT(cppcoreguidelines-pro-type-vararg)
  if (fd < 0) {
    const int e = errno;
    if (e == EEXIST) {
      return "refusing to overwrite existing file (use --force)";
    }
    if (e == ELOOP) {
      return "refusing to write through a symlink";
    }
    return "cannot open for writing: " + std::generic_category().message(e);
  }
  (void)::fchmod(fd, 0600);
  std::size_t written = 0;
  while (written < content.size()) {
    const ssize_t n = ::write(fd, content.data() + written, content.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      const int e = errno;
      ::close(fd);
      return "write failed: " + std::generic_category().message(e);
    }
    written += static_cast<std::size_t>(n);
  }
  if (::close(fd) != 0) {
    return "close failed: " + std::generic_category().message(errno);
  }
  return std::nullopt;
#endif
}

// --- scan
// ------------------------------------------------------------------------------------------

struct ScanSettings {
  std::vector<std::string> rules;
  std::vector<std::string> paths;
  std::string format = "table";
  std::optional<std::string> output;
  bool force = false;
  std::string fail_on = "low";
  bool show_strings = false;
  std::uint64_t max_filesize = kDefaultMaxFilesize;
  std::size_t max_matches = 1000;
  std::size_t max_files = 100000;
  std::vector<std::string> skip;
  bool follow_symlinks = false;
  unsigned threads = default_thread_count();
};

constexpr std::uint64_t kMaxThreads = 64;
constexpr std::uint64_t kMaxMatchesLimit = 1000000;
constexpr std::uint64_t kMaxFilesLimit = 10000000;

void validate_format(const std::string& v) {
  if (v != "table" && v != "json" && v != "sarif") {
    throw UsageError{"invalid --format '" + v + "' (expected table, json or sarif)"};
  }
}

void validate_fail_on(const std::string& v) {
  if (v != "none" && !parse_severity(v)) {
    throw UsageError{"invalid --fail-on '" + v +
                     "' (expected low, medium, high, critical or none)"};
  }
}

// Applies one "key = value" config entry. Throws UsageError with a message (no location).
void apply_config_entry(ScanSettings& s, const std::string& key, const std::string& value) {
  if (key == "rules") {
    s.rules.push_back(value);
  } else if (key == "format") {
    validate_format(value);
    s.format = value;
  } else if (key == "fail_on") {
    validate_fail_on(value);
    s.fail_on = value;
  } else if (key == "max_filesize") {
    s.max_filesize = require_size(key, value);
  } else if (key == "threads") {
    s.threads = static_cast<unsigned>(require_count(key, value, kMaxThreads));
  } else if (key == "max_matches_per_string") {
    s.max_matches = static_cast<std::size_t>(require_count(key, value, kMaxMatchesLimit));
  } else if (key == "max_files") {
    s.max_files = static_cast<std::size_t>(require_count(key, value, kMaxFilesLimit));
  } else if (key == "skip") {
    s.skip.push_back(value);
  } else if (key == "follow_symlinks" || key == "show_strings") {
    const auto b = parse_bool(value);
    if (!b) {
      throw UsageError{"invalid boolean for " + key + ": '" + value + "'"};
    }
    (key == "follow_symlinks" ? s.follow_symlinks : s.show_strings) = *b;
  } else {
    throw UsageError{"unknown key '" + key + "'"};
  }
}

void load_config(const std::string& path, ScanSettings& s) {
  const TextFile file = read_text_file(path, kMaxConfigBytes);
  if (!file.error.empty()) {
    throw UsageError{"cannot read config " + path + ": " + file.error};
  }
  std::istringstream in(file.data);
  std::string line;
  std::size_t number = 0;
  while (std::getline(in, line)) {
    ++number;
    const std::string t = trim(line);
    if (t.empty() || t.front() == '#' || t.front() == ';') {
      continue;
    }
    const auto eq = t.find('=');
    if (eq == std::string::npos) {
      throw UsageError{path + ":" + std::to_string(number) + ": expected 'key = value'"};
    }
    const std::string key = trim(std::string_view(t).substr(0, eq));
    std::string value = trim(std::string_view(t).substr(eq + 1));
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
      value = value.substr(1, value.size() - 2);
    }
    try {
      apply_config_entry(s, key, value);
    } catch (const UsageError& e) {
      throw UsageError{path + ":" + std::to_string(number) + ": " + e.message};
    }
  }
}

ScanSettings parse_scan_args(const std::vector<std::string>& args, bool& help) {
  // Two passes: --config first so that command-line flags override the file.
  ScanSettings s;
  {
    ArgReader reader(args);
    while (!reader.done()) {
      const std::string arg = reader.next();
      if (arg == "--config") {
        load_config(reader.value(arg), s);
      }
    }
  }
  std::vector<std::string> cli_rules;
  std::vector<std::string> cli_skip;
  ArgReader reader(args);
  while (!reader.done()) {
    const std::string arg = reader.next();
    if (arg == "-h" || arg == "--help") {
      help = true;
    } else if (arg == "--config") {
      (void)reader.value(arg);
    } else if (arg == "-r" || arg == "--rules") {
      cli_rules.push_back(reader.value(arg));
    } else if (arg == "-f" || arg == "--format") {
      s.format = reader.value(arg);
      validate_format(s.format);
    } else if (arg == "-o" || arg == "--output") {
      s.output = reader.value(arg);
    } else if (arg == "--force") {
      reader.no_value(arg);
      s.force = true;
    } else if (arg == "--fail-on") {
      s.fail_on = reader.value(arg);
      validate_fail_on(s.fail_on);
    } else if (arg == "--show-strings") {
      reader.no_value(arg);
      s.show_strings = true;
    } else if (arg == "--max-filesize") {
      s.max_filesize = require_size(arg, reader.value(arg));
    } else if (arg == "--max-matches") {
      s.max_matches =
          static_cast<std::size_t>(require_count(arg, reader.value(arg), kMaxMatchesLimit));
    } else if (arg == "--max-files") {
      s.max_files = static_cast<std::size_t>(require_count(arg, reader.value(arg), kMaxFilesLimit));
    } else if (arg == "--skip") {
      cli_skip.push_back(reader.value(arg));
    } else if (arg == "--follow-symlinks") {
      reader.no_value(arg);
      s.follow_symlinks = true;
    } else if (arg == "-j" || arg == "--threads") {
      s.threads = static_cast<unsigned>(require_count(arg, reader.value(arg), kMaxThreads));
    } else if (arg.starts_with("-") && arg != "-") {
      throw UsageError{"unknown option '" + arg + "' for scan"};
    } else {
      s.paths.push_back(arg);
    }
  }
  s.rules.insert(s.rules.end(), cli_rules.begin(), cli_rules.end());
  s.skip.insert(s.skip.end(), cli_skip.begin(), cli_skip.end());
  return s;
}

int compute_exit(const ScanReport& report, const Ruleset& ruleset, const std::string& fail_on) {
  if (fail_on == "none") {
    return kExitOk;
  }
  const Severity threshold = parse_severity(fail_on).value_or(Severity::Low);
  for (const FileResult& f : report.files) {
    for (const RuleMatch& m : f.matches) {
      if (ruleset.rules()[m.rule_index].severity >= threshold) {
        return kExitFindings;
      }
    }
  }
  return kExitOk;
}

int cmd_scan(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
             Logger& log) {
  bool help = false;
  const ScanSettings s = parse_scan_args(args, help);
  if (help) {
    out << kScanHelp;
    return kExitOk;
  }
  if (s.rules.empty()) {
    throw UsageError{"scan needs at least one rule file (-r RULES)"};
  }
  if (s.paths.empty()) {
    throw UsageError{"scan needs at least one file or directory to scan"};
  }
  if (s.output && !s.force) {
    std::error_code ec;
    if (fs::exists(fs::symlink_status(*s.output, ec))) {
      log.error("refusing to overwrite existing file (use --force)", {{"path", *s.output}});
      return kExitUsage;
    }
  }
  for (const std::string& p : s.paths) {
    std::error_code ec;
    if (!fs::exists(p, ec)) {
      log.error("path not found", {{"path", p}});
      return kExitUsage;
    }
  }

  const auto rules = load_rules(s.rules, log, err);
  if (!rules) {
    return kExitUsage;
  }

  const auto started = std::chrono::steady_clock::now();
  WalkOptions walk;
  walk.follow_symlinks = s.follow_symlinks;
  walk.skip_globs = s.skip;
  walk.max_files = s.max_files;
  std::vector<fs::path> roots(s.paths.begin(), s.paths.end());
  const WalkResult walked = collect_files(roots, walk);
  if (walked.truncated) {
    log.warn("max-files limit reached; remaining files were not scanned",
             {{"max_files", std::to_string(s.max_files)}});
  }
  log.debug("walk complete", {{"files", std::to_string(walked.files.size())},
                              {"skipped_symlinks", std::to_string(walked.skipped_symlinks)},
                              {"skipped_by_glob", std::to_string(walked.skipped_by_glob)}});

  ScanOptions options;
  options.max_filesize = s.max_filesize;
  options.max_matches_per_string = s.max_matches;
  options.follow_symlinks = s.follow_symlinks;
  const Scanner scanner(rules->ruleset, options);

  ScanReport report;
  report.rule_files = rules->files;
  report.truncated = walked.truncated;
  report.files.resize(walked.files.size());
  run_parallel(walked.files.size(), s.threads, [&](std::size_t i) {
    const WalkEntry& entry = walked.files[i];
    report.files[i] = scanner.scan_file(entry.path, entry.display, entry.named_directly);
  });
  for (const WalkError& e : walked.errors) {
    FileResult r;
    r.path = e.path;
    r.status = FileStatus::Error;
    r.message = e.message;
    report.files.push_back(std::move(r));
  }
  for (const FileResult& f : report.files) {
    if (f.status == FileStatus::Skipped) {
      log.warn("file skipped", {{"path", f.path}, {"reason", f.message}});
    } else if (f.status == FileStatus::Error) {
      log.warn("file not scanned", {{"path", f.path}, {"reason", f.message}});
    }
  }

  std::ostringstream rendered;
  if (s.format == "json") {
    write_json(rendered, report, *rules->ruleset, s.show_strings);
  } else if (s.format == "sarif") {
    write_sarif(rendered, report, *rules->ruleset);
  } else {
    write_table(rendered, report, *rules->ruleset, s.show_strings);
  }
  if (s.output) {
    if (auto problem = write_report_file(*s.output, rendered.str(), s.force)) {
      log.error(*problem, {{"path", *s.output}});
      return kExitUsage;
    }
  } else {
    out << rendered.str();
    out.flush();
  }

  const ScanSummary summary = summarize(report);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - started);
  log.info("scan complete", {{"files", std::to_string(summary.files_scanned)},
                             {"matches", std::to_string(summary.matches)},
                             {"skipped", std::to_string(summary.skipped)},
                             {"errors", std::to_string(summary.errors)},
                             {"elapsed_ms", std::to_string(elapsed.count())}});
  return compute_exit(report, *rules->ruleset, s.fail_on);
}

// --- check -------------------------------------------------------------------------------------

int cmd_check(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
              Logger& log) {
  std::vector<std::string> files;
  ArgReader reader(args);
  while (!reader.done()) {
    const std::string arg = reader.next();
    if (arg == "-h" || arg == "--help") {
      out << kCheckHelp;
      return kExitOk;
    }
    if (arg.starts_with("-")) {
      throw UsageError{"unknown option '" + arg + "' for check"};
    }
    files.push_back(arg);
  }
  if (files.empty()) {
    throw UsageError{"check needs at least one rule file"};
  }
  RulesetBuilder builder;
  std::vector<std::string> per_file;
  for (const std::string& f : files) {
    const std::size_t before = builder.rule_count();
    const bool ok = builder.add_file(f);
    const std::size_t added = builder.rule_count() - before;
    per_file.push_back(f + (ok ? ": ok, " : ": errors, ") + std::to_string(added) +
                       (added == 1 ? " rule" : " rules"));
  }
  CompileResult compiled = builder.compile();
  print_diagnostics(compiled.diagnostics, err);
  for (const std::string& line : per_file) {
    out << line << '\n';
  }
  const std::size_t errors = count_level(compiled.diagnostics, DiagLevel::Error);
  const std::size_t warnings = count_level(compiled.diagnostics, DiagLevel::Warning);
  if (!compiled.ruleset) {
    out << "check failed: " << errors << (errors == 1 ? " error" : " errors") << ", " << warnings
        << (warnings == 1 ? " warning" : " warnings") << '\n';
    log.debug("check failed");
    return kExitUsage;
  }
  const RulesetStats st = compiled.ruleset->stats();
  out << "compiled " << st.rules << " rules: " << st.strings << " strings, " << st.patterns
      << " patterns, " << st.atoms << " atoms\n";
  out << "automaton: " << st.states << " states x " << st.alphabet_classes
      << " alphabet classes = " << format_size(st.table_bytes)
      << " transition table; longest pattern " << st.max_pattern_length << " bytes\n";
  out << warnings << (warnings == 1 ? " warning" : " warnings") << '\n';
  return kExitOk;
}

// --- bench -------------------------------------------------------------------------------------

int cmd_bench(const std::vector<std::string>& args, std::ostream& out, std::ostream& err,
              Logger& log) {
  std::vector<std::string> rule_files;
  std::vector<std::string> paths;
  std::uint64_t iterations = 3;
  std::uint64_t max_filesize = kDefaultMaxFilesize;
  ArgReader reader(args);
  while (!reader.done()) {
    const std::string arg = reader.next();
    if (arg == "-h" || arg == "--help") {
      out << kBenchHelp;
      return kExitOk;
    }
    if (arg == "-r" || arg == "--rules") {
      rule_files.push_back(reader.value(arg));
    } else if (arg == "--iterations") {
      iterations = require_count(arg, reader.value(arg), 1000);
    } else if (arg == "--max-filesize") {
      max_filesize = require_size(arg, reader.value(arg));
    } else if (arg.starts_with("-")) {
      throw UsageError{"unknown option '" + arg + "' for bench"};
    } else {
      paths.push_back(arg);
    }
  }
  if (rule_files.empty() || paths.empty()) {
    throw UsageError{"bench needs -r RULES and a PATH"};
  }
  for (const std::string& p : paths) {
    std::error_code ec;
    if (!fs::exists(p, ec)) {
      log.error("path not found", {{"path", p}});
      return kExitUsage;
    }
  }
  const auto rules = load_rules(rule_files, log, err);
  if (!rules) {
    return kExitUsage;
  }
  const Ruleset& rs = *rules->ruleset;

  std::vector<fs::path> roots(paths.begin(), paths.end());
  const WalkResult walked = collect_files(roots, WalkOptions{});
  std::vector<std::vector<std::uint8_t>> buffers;
  std::uint64_t total_bytes = 0;
  for (const WalkEntry& entry : walked.files) {
    InputFile file;
    if (auto e = file.open(entry.path, entry.named_directly)) {
      log.warn(*e, {{"path", entry.display}});
      continue;
    }
    if (file.size() > max_filesize || total_bytes + file.size() > kMaxBenchBytes) {
      log.warn("file skipped (size limit)", {{"path", entry.display}});
      continue;
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(file.size()));
    std::size_t filled = 0;
    while (filled < data.size()) {
      const std::size_t n = file.read(std::span<std::uint8_t>(data).subspan(filled));
      if (n == 0) {
        break;
      }
      filled += n;
    }
    data.resize(filled);
    total_bytes += filled;
    buffers.push_back(std::move(data));
  }
  if (buffers.empty() || total_bytes == 0) {
    log.error("no input bytes to benchmark");
    return kExitUsage;
  }

  // Warm-up pass doubles as the correctness check.
  std::size_t hits_per_pass = 0;
  for (const auto& buf : buffers) {
    const std::vector<Hit> fast = rs.find_hits(buf);
    const std::vector<Hit> slow = naive_find_all(rs.patterns(), buf);
    if (fast != slow) {
      log.error("engines disagree; please report this as a bug");
      return kExitUsage;
    }
    hits_per_pass += fast.size();
  }

  using Clock = std::chrono::steady_clock;
  auto time_engine = [&](bool fast) {
    std::size_t sink = 0;
    const auto start = Clock::now();
    for (std::uint64_t it = 0; it < iterations; ++it) {
      for (const auto& buf : buffers) {
        sink += fast ? rs.find_hits(buf).size() : naive_find_all(rs.patterns(), buf).size();
      }
    }
    const std::chrono::duration<double> elapsed = Clock::now() - start;
    if (sink != hits_per_pass * iterations) {
      throw std::runtime_error("hit count changed between passes");
    }
    return elapsed.count();
  };
  const double ac_seconds = time_engine(true);
  const double naive_seconds = time_engine(false);

  const double mib =
      static_cast<double>(total_bytes) * static_cast<double>(iterations) / (1024.0 * 1024.0);
  const RulesetStats st = rs.stats();
  out << std::fixed << std::setprecision(1);
  out << "rules:       " << st.rules << " rules, " << st.patterns << " patterns, " << st.atoms
      << " atoms, " << st.states << " automaton states\n";
  out << "input:       " << buffers.size() << (buffers.size() == 1 ? " file, " : " files, ")
      << format_size(total_bytes) << ", " << iterations << " timed passes per engine\n\n";
  out << "engine          time (ms)   throughput (MB/s)   hits/pass\n";
  auto row = [&](const char* name, double seconds) {
    const double throughput = seconds > 0 ? mib / seconds : 0.0;
    std::ostringstream t;
    t << std::fixed << std::setprecision(1) << seconds * 1000.0;
    std::ostringstream m;
    m << std::fixed << std::setprecision(1) << throughput;
    out << std::left << std::setw(16) << name << std::setw(12) << t.str() << std::setw(20)
        << m.str() << hits_per_pass << '\n';
  };
  row("aho-corasick", ac_seconds);
  row("naive", naive_seconds);
  out << std::right;
  const double speedup = ac_seconds > 0 ? naive_seconds / ac_seconds : 0.0;
  out << "\nspeedup: " << speedup
      << "x (1 MB = 1048576 bytes); both engines found identical hits\n";
  return kExitOk;
}

}  // namespace

int run(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
  Logger log(err, LogLevel::Info, LogFormat::Text);
  try {
    const Globals g = extract_globals(args);
    log.set_level(g.level);
    log.set_format(g.format);
    if (g.version) {
      out << "sigscan " << kVersion << '\n';
      return kExitOk;
    }
    if (g.rest.empty()) {
      if (g.help) {
        out << kMainHelp;
        return kExitOk;
      }
      err << kMainHelp;
      return kExitUsage;
    }
    const std::string command = g.rest.front();
    std::vector<std::string> sub(g.rest.begin() + 1, g.rest.end());
    if (g.help) {
      sub.emplace_back("--help");
    }
    if (command == "scan") {
      return cmd_scan(sub, out, err, log);
    }
    if (command == "check") {
      return cmd_check(sub, out, err, log);
    }
    if (command == "bench") {
      return cmd_bench(sub, out, err, log);
    }
    if (command == "help") {
      out << kMainHelp;
      return kExitOk;
    }
    throw UsageError{"unknown command '" + command + "' (expected scan, check or bench)"};
  } catch (const UsageError& e) {
    log.error(e.message);
    err << "Run 'sigscan --help' for usage.\n";
    return kExitUsage;
  } catch (const std::exception& e) {
    log.error(std::string("internal error: ") + e.what());
    return kExitUsage;
  }
}

}  // namespace sigscan::cli
