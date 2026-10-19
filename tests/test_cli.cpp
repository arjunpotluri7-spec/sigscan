#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

#include "test_util.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace sigscan {
namespace {

using test::demo_rules;
using test::run_cli;
using test::sample_files;

std::string sample(std::string_view name) {
  return sample_files() + "/" + std::string(name);
}

TEST(Cli, VersionAndHelp) {
  auto r = run_cli({"--version"});
  EXPECT_EQ(r.code, 0);
  EXPECT_EQ(r.out, "sigscan 0.1.0\n");
  r = run_cli({"--help"});
  EXPECT_EQ(r.code, 0);
  EXPECT_NE(r.out.find("Exit codes:"), std::string::npos);
  r = run_cli({"scan", "--help"});
  EXPECT_EQ(r.code, 0);
  EXPECT_NE(r.out.find("--fail-on SEVERITY"), std::string::npos);
  EXPECT_EQ(run_cli({"check", "-h"}).code, 0);
  EXPECT_EQ(run_cli({"bench", "--help"}).code, 0);
}

TEST(Cli, UsageErrorsExitTwo) {
  EXPECT_EQ(run_cli({}).code, 2);
  auto r = run_cli({"frobnicate"});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("sigscan: error: unknown command 'frobnicate'"), std::string::npos);
  r = run_cli({"scan", "-r", demo_rules(), "--bogus", sample_files()});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("unknown option '--bogus' for scan"), std::string::npos);
  EXPECT_EQ(run_cli({"scan", sample_files()}).code, 2);      // no rules
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules()}).code, 2);  // no paths
  EXPECT_EQ(run_cli({"scan", "-r"}).code, 2);                // missing value
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--format", "xml", sample_files()}).code, 2);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--fail-on", "severe", sample_files()}).code, 2);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--threads", "0", sample_files()}).code, 2);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--max-filesize", "lots", sample_files()}).code,
            2);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--force=yes", sample_files()}).code, 2);
  EXPECT_EQ(run_cli({"--log-level", "loud", "scan"}).code, 2);
}

TEST(Cli, MissingPathExitsTwo) {
  const auto r = run_cli({"scan", "-r", demo_rules(), "/nonexistent/sigscan/path"});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("path not found"), std::string::npos);
}

TEST(Cli, BadRulesExitTwoWithDiagnostics) {
  test::TempDir dir;
  test::write_file(dir / "bad.sig", "rule r {\n  condition: $nope\n}\n");
  const auto r = run_cli({"scan", "-r", (dir / "bad.sig").string(), sample_files()});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("bad.sig:2:14: error: unknown string identifier '$nope'"),
            std::string::npos);
  EXPECT_NE(r.err.find("rules failed to load"), std::string::npos);
}

TEST(Cli, MatchesExitOneBenignExitsZero) {
  auto r = run_cli({"scan", "-r", demo_rules(), sample("dropper_note.txt")});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.out.find("Demo_Dropper_Strings"), std::string::npos);
  EXPECT_NE(r.out.find("why:  matched because $a found at 0x49"), std::string::npos);
  r = run_cli({"scan", "-r", demo_rules(), sample("benign_readme.txt")});
  EXPECT_EQ(r.code, 0);
  EXPECT_NE(r.out.find("No matches."), std::string::npos);
}

TEST(Cli, FailOnThreshold) {
  // dropper_note matches only a high-severity rule.
  EXPECT_EQ(
      run_cli({"scan", "-r", demo_rules(), "--fail-on", "high", sample("dropper_note.txt")}).code,
      1);
  EXPECT_EQ(
      run_cli({"scan", "-r", demo_rules(), "--fail-on=critical", sample("dropper_note.txt")}).code,
      0);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--fail-on", "none", sample_files()}).code, 0);
  EXPECT_EQ(run_cli({"scan", "-r", demo_rules(), "--fail-on", "critical", sample_files()}).code, 1);
}

TEST(Cli, JsonSchema) {
  const auto r = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "--format", "json",
                          "--show-strings", sample_files()});
  ASSERT_EQ(r.code, 1) << r.err;
  const test::Json doc = test::parse_json(r.out);
  EXPECT_EQ(doc["tool"].str(), "sigscan");
  EXPECT_EQ(doc["version"].str(), "0.1.0");
  EXPECT_EQ(doc["schema_version"].num(), 1);
  ASSERT_TRUE(doc["rule_files"].is_array());
  const test::Json& summary = doc["summary"];
  for (const char* key :
       {"files_scanned", "files_matched", "matches", "skipped", "errors", "bytes_scanned"}) {
    EXPECT_TRUE(summary[key].is_number()) << key;
  }
  EXPECT_EQ(summary["files_scanned"].num(), 13);
  EXPECT_FALSE(std::get<bool>(summary["truncated"].v));
  ASSERT_TRUE(doc["matches"].is_array());
  ASSERT_FALSE(doc["matches"].arr().empty());
  for (const test::Json& m : doc["matches"].arr()) {
    EXPECT_TRUE(m["file"].is_string());
    EXPECT_TRUE(m["file_size"].is_number());
    EXPECT_TRUE(m["rule"].is_string());
    EXPECT_TRUE(m["tags"].is_array());
    EXPECT_TRUE(m["severity"].is_string());
    EXPECT_TRUE(m["meta"].is_object());
    EXPECT_TRUE(m["condition"].is_string());
    EXPECT_EQ(m["why"].str().rfind("matched because ", 0), 0U);
    for (const test::Json& s : m["strings"].arr()) {
      EXPECT_EQ(s["id"].str().front(), '$');
      EXPECT_GE(s["count"].num(), 1);
      EXPECT_TRUE(s["offsets"].is_array());
      EXPECT_TRUE(s["offsets_truncated"].is_bool());
      ASSERT_TRUE(s["snippets"].is_array());
      const test::Json& snip = s["snippets"][0];
      EXPECT_TRUE(snip["hex"].is_string());
      EXPECT_TRUE(snip["ascii"].is_string());
      EXPECT_TRUE(snip["offset"].is_number());
    }
  }
  EXPECT_TRUE(doc["skipped"].is_array());
  EXPECT_TRUE(doc["errors"].is_array());
  // Typed meta values survive.
  bool saw_beacon = false;
  for (const test::Json& m : doc["matches"].arr()) {
    if (m["rule"].str() == "Demo_Beacon_Config") {
      saw_beacon = true;
      EXPECT_EQ(m["meta"]["version"].num(), 2);
      EXPECT_TRUE(std::get<bool>(m["meta"]["reviewed"].v));
    }
  }
  EXPECT_TRUE(saw_beacon);
}

TEST(Cli, SarifStructure) {
  const auto r = run_cli(
      {"--log-level", "error", "scan", "-r", demo_rules(), "--format", "sarif", sample_files()});
  ASSERT_EQ(r.code, 1) << r.err;
  const test::Json doc = test::parse_json(r.out);
  EXPECT_EQ(doc["version"].str(), "2.1.0");
  EXPECT_NE(doc["$schema"].str().find("sarif-2.1.0"), std::string::npos);
  ASSERT_EQ(doc["runs"].arr().size(), 1U);
  const test::Json& run = doc["runs"][0];
  const test::Json& driver = run["tool"]["driver"];
  EXPECT_EQ(driver["name"].str(), "sigscan");
  ASSERT_EQ(driver["rules"].arr().size(), 6U);
  for (const test::Json& rule : driver["rules"].arr()) {
    EXPECT_TRUE(rule["id"].is_string());
    EXPECT_TRUE(rule["shortDescription"]["text"].is_string());
    const std::string level = rule["defaultConfiguration"]["level"].str();
    EXPECT_TRUE(level == "error" || level == "warning" || level == "note") << level;
    EXPECT_TRUE(rule["properties"]["security-severity"].is_string());
  }
  ASSERT_FALSE(run["results"].arr().empty());
  for (const test::Json& res : run["results"].arr()) {
    const auto index = static_cast<std::size_t>(res["ruleIndex"].num());
    EXPECT_EQ(driver["rules"][index]["id"].str(), res["ruleId"].str());
    EXPECT_FALSE(res["message"]["text"].str().empty());
    const test::Json& loc = res["locations"][0]["physicalLocation"];
    EXPECT_TRUE(loc["artifactLocation"]["uri"].is_string());
    EXPECT_TRUE(loc["region"]["byteOffset"].is_number());
    EXPECT_GE(loc["region"]["byteLength"].num(), 1);
  }
  EXPECT_TRUE(std::get<bool>(run["invocations"][0]["executionSuccessful"].v));
}

TEST(Cli, OutputFileIsPrivateAndNotOverwrittenWithoutForce) {
  test::TempDir dir;
  const std::string out = (dir / "report.json").string();
  auto r = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "-f", "json", "-o", out,
                    sample("dropper_note.txt")});
  EXPECT_EQ(r.code, 1);
  EXPECT_TRUE(r.out.empty());
  EXPECT_NO_THROW(test::parse_json(test::read_file(out)));
#ifndef _WIN32
  struct stat st{};
  ASSERT_EQ(::stat(out.c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600);
#endif
  r = run_cli({"scan", "-r", demo_rules(), "-o", out, sample("dropper_note.txt")});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("refusing to overwrite existing file (use --force)"), std::string::npos);
  r = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "-o", out, "--force",
               sample("benign_readme.txt")});
  EXPECT_EQ(r.code, 0);
  EXPECT_NE(test::read_file(out).find("No matches."), std::string::npos);
}

TEST(Cli, ThreadCountDoesNotChangeOutput) {
  const auto one = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "-f", "json", "-j",
                            "1", sample_files()});
  const auto many = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "-f", "json",
                             "--threads", "8", sample_files()});
  EXPECT_EQ(one.code, 1);
  EXPECT_EQ(one.out, many.out);
}

TEST(Cli, SkipGlobAndMaxFiles) {
  auto r = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "--skip", "archive",
                    "--skip", "dropper_*", "-f", "json", sample_files()});
  const test::Json doc = test::parse_json(r.out);
  EXPECT_EQ(doc["summary"]["files_scanned"].num(), 9);
  for (const test::Json& m : doc["matches"].arr()) {
    EXPECT_EQ(m["file"].str().find("dropper_"), std::string::npos);
    EXPECT_EQ(m["file"].str().find("archive"), std::string::npos);
  }
  r = run_cli({"scan", "-r", demo_rules(), "--max-files", "2", "-f", "json", sample_files()});
  EXPECT_TRUE(std::get<bool>(test::parse_json(r.out)["summary"]["truncated"].v));
  EXPECT_NE(r.err.find("max-files limit reached"), std::string::npos);
}

TEST(Cli, OversizedFilesAreReportedAsSkipped) {
  const auto r = run_cli({"--log-level", "error", "scan", "-r", demo_rules(), "--max-filesize",
                          "1KB", "-f", "json", sample_files()});
  const test::Json doc = test::parse_json(r.out);
  EXPECT_EQ(doc["summary"]["skipped"].num(), 3);  // the three 2-4 KiB binaries
  EXPECT_EQ(doc["skipped"].arr().size(), 3U);
}

TEST(Cli, ConfigFileProvidesDefaultsAndFlagsOverride) {
  test::TempDir dir;
  const auto cfg = dir / "sigscan.ini";
  test::write_file(cfg, "# test config\nrules = " + demo_rules() +
                            "\nformat = json\nfail_on = critical\nthreads = 2\n");
  auto r = run_cli(
      {"--log-level", "error", "scan", "--config", cfg.string(), sample("dropper_note.txt")});
  EXPECT_EQ(r.code, 0);  // high match, but fail_on = critical
  EXPECT_NO_THROW(test::parse_json(r.out));
  r = run_cli({"--log-level", "error", "scan", "--config", cfg.string(), "--fail-on", "high",
               "--format", "table", sample("dropper_note.txt")});
  EXPECT_EQ(r.code, 1);
  EXPECT_NE(r.out.find("SEVERITY"), std::string::npos);

  test::write_file(dir / "bad.ini", "rules = x.sig\ncolour = blue\n");
  r = run_cli({"scan", "--config", (dir / "bad.ini").string(), sample_files()});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("bad.ini:2: unknown key 'colour'"), std::string::npos);
}

TEST(Cli, ExampleConfigIsValid) {
  const auto cfg = test::source_dir() / "config.example.ini";
  const auto r = run_cli({"--log-level", "error", "scan", "--config", cfg.string(), "-r",
                          demo_rules(), "--fail-on", "none", sample_files()});
  EXPECT_EQ(r.code, 0) << r.err;
}

TEST(Cli, JsonLogFormat) {
  const auto r = run_cli({"--log-format", "json", "scan", "-r", demo_rules(), "-o", "/dev/null",
                          sample("benign_readme.txt")});
  // /dev/null exists, so this is refused without --force; the error is a JSON log line.
  EXPECT_EQ(r.code, 2);
  const std::string first_line = r.err.substr(0, r.err.find('\n'));
  const test::Json line = test::parse_json(first_line);
  EXPECT_EQ(line["level"].str(), "error");
  EXPECT_EQ(line["path"].str(), "/dev/null");
}

TEST(Cli, CheckPrintsStatsAndValidates) {
  auto r = run_cli({"check", demo_rules()});
  EXPECT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("demo.sig: ok, 6 rules"), std::string::npos);
  EXPECT_NE(r.out.find("compiled 6 rules: 21 strings"), std::string::npos);
  EXPECT_NE(r.out.find("automaton: "), std::string::npos);
  EXPECT_NE(r.out.find("0 warnings"), std::string::npos);

  test::TempDir dir;
  test::write_file(dir / "warn.sig", "rule w { strings: $a = \"aaa\" $b = \"bbb\" condition: $a }");
  r = run_cli({"check", (dir / "warn.sig").string()});
  EXPECT_EQ(r.code, 0);
  EXPECT_NE(r.err.find("warning: string '$b' in rule 'w' is not used"), std::string::npos);
  EXPECT_NE(r.out.find("1 warning"), std::string::npos);

  test::write_file(dir / "bad.sig", "rule a { condition: true }\nrule a { condition: true }\n");
  r = run_cli({"check", (dir / "bad.sig").string(), demo_rules()});
  EXPECT_EQ(r.code, 2);
  EXPECT_NE(r.err.find("duplicate rule name 'a'"), std::string::npos);
  EXPECT_NE(r.out.find("check failed: 1 error, 0 warnings"), std::string::npos);
  EXPECT_EQ(run_cli({"check"}).code, 2);
}

TEST(Cli, BenchComparesEngines) {
  const auto r = run_cli({"bench", "-r", demo_rules(), "--iterations", "2", sample_files()});
  EXPECT_EQ(r.code, 0) << r.err;
  EXPECT_NE(r.out.find("aho-corasick"), std::string::npos);
  EXPECT_NE(r.out.find("naive"), std::string::npos);
  EXPECT_NE(r.out.find("both engines found identical hits"), std::string::npos);
  EXPECT_EQ(run_cli({"bench", "-r", demo_rules()}).code, 2);
}

}  // namespace
}  // namespace sigscan
