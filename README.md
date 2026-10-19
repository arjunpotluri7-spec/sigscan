# Sigscan

A fast, explainable signature scanner for files: write small YARA-style rules describing known-bad
content, and Sigscan tells you which files match, **where**, and **why**. It only ever reads files.

![CI](../../actions/workflows/ci.yml/badge.svg)

## Why this exists

During triage you often know what you are looking for (a marker string from an incident report, a
config key, a header with a few variable bytes) and need to sweep a directory for it. `grep`
handles one literal at a time and knows nothing about UTF-16, wildcards or "two of these five".
Full YARA is powerful, but its engine is large and its output says *that* a rule matched, not
*why*.

Sigscan is the small, readable middle ground. Its rule language covers the parts of YARA used
most in practice, every match comes with a one-line explanation built from the actual offsets,
counts and sizes, and the whole engine (lexer, parser, Aho-Corasick matcher, condition
evaluator) is about 5,000 lines of C++20 that you can read in an afternoon. It is
defensive by construction: no network, no subprocesses, no execution of scanned content.

## Distinctive feature: one-pass Aho-Corasick matching, fuzzed against a naive oracle

- **Hand-written Aho-Corasick automaton.** Every literal and hex string from every loaded rule
  is reduced to one *atom* (the longest literal run, case-folded), and all atoms go into a single
  automaton. Each file is read once, in 1 MiB chunks, and every byte costs one table lookup no
  matter how many rules are loaded. Candidate hits are then verified against the full pattern
  (wildcards, exact case) at the right offset.
- **Compact dense DFA.** Failure links are compiled away into a dense transition table, bytes that
  no atom uses share one *alphabet class* (369 states x 44 classes = 63 KB for the demo rules
  instead of 369 x 256), and each table entry stores a pre-multiplied row offset plus an
  "output here" flag bit, so the hot loop has no multiply and no second lookup.
- **Proven boundaries.** Chunks overlap by (longest pattern - 1) bytes and a hit is kept only if
  it ends inside the new bytes, so a pattern that straddles a chunk boundary is found exactly
  once. Tests check this for every chunk size from 1 to 40 bytes and on a real 192 KiB file.
- **A naive scanner as an oracle and a baseline.** `naive_find_all` checks every pattern at every
  offset. A property test (60 fixed seeds) and the `fuzz_matcher` harness require the automaton
  to produce exactly the same hits, and `sigscan bench` times both on the same bytes.
- **Sanitizers and fuzzing.** libFuzzer harnesses for the rule parser and the matcher run in Linux
  CI; a portable smoke driver replays the seed corpus plus deterministic mutations under
  AddressSanitizer and UndefinedBehaviorSanitizer on any platform.

## Features

- **Rule language** (full reference in [docs/rule-language.md](docs/rule-language.md)):
  - text strings with escapes (`\n \t \r \\ \" \xHH`) and the modifiers `nocase`, `wide`
    (UTF-16LE) and `ascii`;
  - hex strings with `??` single-byte wildcards (`{ 4D 5A ?? 00 DE AD ?? EF }`);
  - conditions with `and`, `or`, `not`, parentheses, `$a`, `#a >= N` (all six comparisons),
    `$a at OFFSET`, `$a in (START..END)`, `any/all/N of them`, `any of ($a, $b)`,
    `N of ($cfg*)`, and `filesize < 5MB` (with `KB`/`MB` suffixes);
  - tags and typed meta (`severity = "low|medium|high|critical"`, `description`, anything else).
- **Compiler-quality diagnostics**: `file:line:col: error: message` with the source line and a
  caret. Unknown identifiers, duplicate rule or string names, all-wildcard hex strings and
  unsupported syntax (hex jumps, alternatives, nibble wildcards) are errors with specific
  messages; unused strings and single-byte anchors are warnings. The parser recovers at the next
  `rule`, so one run reports several problems.
- **Explainable matches**: every result carries a "why" line such as
  `matched because $a found at 0x0 and #d is 2 (>= 2); filesize 140 bytes < 5 MB`, plus per-string
  counts and offsets, and with `--show-strings` hex/ASCII snippets with context.
- **Three output formats**: a terminal table, a stable JSON schema, and SARIF 2.1.0 for code
  scanning dashboards.
- **Safe directory scanning**: recursive, sorted (deterministic) output, directory symlinks never
  followed, file symlinks only with `--follow-symlinks`, `--skip` globs (`*`, `?`, `**`) that also
  prune directories, a `--max-files` cap, and a `--max-filesize` cap (default 64 MiB) enforced with
  `fstat` and again while reading.
- **Parallel and deterministic**: `--threads N` scans files on a small worker pool; results are
  written into per-file slots and always reported in path order, so the output is byte-identical
  for any thread count (tested).
- **`check` and `bench` subcommands** for validating rule packs and measuring the engine.

## Architecture

```
 .sig files ──► Lexer ──► Parser ──► Rule AST ──► RulesetBuilder::compile ──► Ruleset
                (tokens,  (recursive  (strings,     │  each string -> 1-2 Patterns            │
                 hex,      descent,    conditions,  │  (ascii / wide), each Pattern -> atom    │
                 escapes)  recovery,   meta, tags)  │  (longest literal run, folded)          │
                           semantic                 └► AhoCorasick: trie -> BFS -> dense DFA   │
                           checks)                                                             ▼
 paths ──► collect_files (walker) ──► WorkerPool ──► Scanner::scan_file ──► FileResult[] ──► report
           sorted, no symlinks,        N threads,     chunked read + overlap,   per string:      table
           skip globs, caps            slot per file  automaton + verify,      count, offsets,  json
                                                       evaluate + explain       why line         sarif
```

| Module | Role |
|---|---|
| `lexer.cpp` | Tokens with line/column; decodes text escapes and hex strings (a `{` right after `=` starts hex); checked number parsing with `KB`/`MB` |
| `parser.cpp` | Recursive descent with precedence `or` < `and` < `not`, semantic checks, error recovery, depth limit |
| `ruleset.cpp` | Merges rule files, rejects duplicate names, compiles strings into patterns and deduplicated atoms |
| `aho_corasick.hpp/.cpp` | Trie, BFS failure links, alphabet classes, dense DFA with output flags and dictionary links |
| `pattern.cpp` | Pattern verification (`nocase`, wildcards), atom choice, the naive reference matcher |
| `scanner.cpp` | Chunked streaming scan with overlap, per-string hits (exact counts, capped offsets, snippets), rule evaluation |
| `condition.cpp` | Condition evaluation and the human "why" explanation |
| `walker.cpp` | Directory walk with symlink policy, glob pruning and caps |
| `file_io.cpp` | Read-only `O_NOFOLLOW` / `O_NONBLOCK` file handle with `fstat` checks |
| `report.cpp`, `json_writer.cpp` | Table, JSON and SARIF writers; UTF-8-safe JSON escaping |
| `worker_pool.cpp`, `log.cpp` | Thread pool with deterministic result slots; text/JSON structured logging |
| `src/cli/cli.cpp` | Subcommands, options, config file, exit codes, safe `--output` writing |

## Build & install

Requirements: a C++20 compiler, Ninja, Python 3 (for the sample generator check) and CMake 3.25+.
Tested with Apple clang 21 locally and with the clang that ships on GitHub's `ubuntu-latest` and
`macos-latest` runners in CI; GCC 12+ should work but is not tested. The CI-pinned CMake,
clang-format and clang-tidy can be installed locally:

```bash
python3 -m venv .tools && .tools/bin/pip install -r tools/requirements.txt
export PATH="$PWD/.tools/bin:$PATH"

cmake --preset release
cmake --build --preset release
./build/release/sigscan --version
cmake --install build/release --prefix ~/.local     # optional: installs bin/sigscan
```

- **macOS**: Xcode command line tools provide clang; `brew install ninja` if needed.
- **Linux**: `sudo apt-get install clang ninja-build` (GCC works too).
- **Windows**: not built or tested. POSIX calls are confined to `file_io.cpp` and the CLI's
  `--output` writer, both of which have untested `_WIN32` fallbacks (without an `O_NOFOLLOW`
  equivalent, so symlink protection would rely on the walker alone). Treat Windows as
  unsupported for now.

Presets: `dev` (Debug, warnings as errors), `asan` (Debug + ASan + UBSan), `release`, and `fuzz`
(libFuzzer targets; Linux clang only).

## Quick start against `samples/`

Everything in `samples/` is synthetic and harmless (see [samples/README.md](samples/README.md)).

```bash
./build/release/sigscan check samples/rules/demo.sig
./build/release/sigscan scan -r samples/rules/demo.sig samples/files
./build/release/sigscan scan -r samples/rules/demo.sig --show-strings samples/files/dropper_stub.bin
./build/release/sigscan scan -r samples/rules/demo.sig --format json -o report.json samples/files
```

## Usage

```
sigscan scan  -r RULES [-r RULES ...] PATH... [options]
sigscan check RULES...
sigscan bench -r RULES PATH [--iterations N]
sigscan --version | --help          (sigscan COMMAND --help for details)
```

`scan` options:

| Option | Default | Meaning |
|---|---|---|
| `-r, --rules FILE` | required | Rule file; repeat to load several (names must be unique across them) |
| `-f, --format` | `table` | `table`, `json` or `sarif` |
| `-o, --output FILE` | stdout | Write the report to FILE (mode 0600; refuses to overwrite) |
| `--force` | off | Allow `--output` to overwrite |
| `--fail-on SEVERITY` | `low` | Exit 1 if a match at or above this severity exists; `none` disables |
| `--show-strings` | off | Hex/ASCII snippets for up to 8 hits per string |
| `--max-filesize SIZE` | `64MB` | Larger files are reported as skipped (`KB`, `MB`, `GB` suffixes) |
| `--max-matches N` | `1000` | Offsets stored per string (counts stay exact) |
| `--max-files N` | `100000` | Stop walking after N files (reported as truncated) |
| `--skip GLOB` | none | Skip matching paths; matched against the path relative to the root and the file name |
| `--follow-symlinks` | off | Include symlinked files met while walking (directory symlinks are never followed) |
| `-j, --threads N` | CPUs, max 8 | Worker threads; output order does not change |
| `--config FILE` | none | Defaults from a config file (see below) |

Global options: `--log-level error|warn|info|debug` (default `info`) and
`--log-format text|json`. Logs go to stderr; reports go to stdout or `--output`.

## Configuration

`--config FILE` reads `key = value` lines (`#` comments). Command-line flags override the file;
`rules` and `skip` entries are added to those given on the command line. See
[config.example.ini](config.example.ini):

```ini
format = table
fail_on = high
max_filesize = 64MB
max_matches_per_string = 1000
max_files = 100000
threads = 4
follow_symlinks = false
show_strings = false
skip = .git
skip = node_modules
skip = **/*.iso
```

Unknown keys and bad values are errors with `file:line:` locations (exit code 2).

## Sample output (real)

All output below was produced by the commands shown, on the committed samples, with the release
build.

`sigscan check samples/rules/demo.sig`:

```
samples/rules/demo.sig: ok, 6 rules
compiled 6 rules: 21 strings, 23 patterns, 23 atoms
automaton: 369 states x 44 alphabet classes = 63.4 KB transition table; longest pattern 88 bytes
0 warnings
```

`sigscan scan -r samples/rules/demo.sig samples/files` (exit code 1):

```
SEVERITY  RULE                   FILE
medium    Demo_Beacon_Config     samples/files/archive/nested/beacon_copy.cfg
          tags: beacon, config, demo
          why:  matched because 2 of ($cfg*) found ($cfg_interval, $cfg_jitter) and $host found at 0x48
          hits: $cfg_interval x1 @0x0, $cfg_jitter x1 @0x1c, $host x1 @0x48
medium    Demo_Beacon_Config     samples/files/beacon.cfg
          tags: beacon, config, demo
          why:  matched because 3 of ($cfg*) found and $host found at 0x71
          hits: $cfg_interval x1 @0x36, $cfg_jitter x1 @0x51, $cfg_server x1 @0x6a, $host x1 @0x71
high      Demo_Dropper_Strings   samples/files/dropper_note.txt
          tags: dropper, demo
          why:  matched because $a found at 0x49 and 1 of ($b, $c) found ($b); filesize 166 bytes < 5 MB
          hits: $a x1 @0x49, $b x1 @0x73
high      Demo_Dropper_Strings   samples/files/dropper_stub.bin
          tags: dropper, demo
          why:  matched because $a found at 0x20 and 1 of ($b, $c) found ($c); filesize 108 bytes < 5 MB
          hits: $a x1 @0x20, $c x1 @0x44
high      Demo_Dropper_Strings   samples/files/dropper_wide.bin
          tags: dropper, demo
          why:  matched because $a found at 0x0 and #d is 2 (>= 2); filesize 140 bytes < 5 MB
          hits: $a x1 @0x0, $d x2 @0x18
low       Demo_Multi_Marker      samples/files/markers.txt
          tags: demo
          why:  matched because #m1 is 2 (== 2) and $m1 at 0x10
          hits: $m1 x2 @0x10
critical  Demo_Packed_Header     samples/files/packed_sample.bin
          tags: packer, binary, demo
          why:  matched because $magic at 0x0 and $section found at 0x40 within (0..4096) and 3 of them found; filesize 2.0 KB < 64 KB
          hits: $magic x1 @0x0, $section x1 @0x40, $stub x1 @0x200
high      Demo_Ransom_Note_Text  samples/files/ransom_note_utf16.txt
          tags: note, demo
          why:  matched because $headline found at 0x2 and $allow not found
          hits: $headline x1 @0x2
medium    Demo_Unicode_Notice    samples/files/ransom_note_utf16.txt
          tags: unicode, demo
          why:  matched because 2 of them found; filesize 208 bytes <= 1 MB
          hits: $w1 x1 @0x60, $w2 x1 @0x94

Scanned 13 files (9.4 KB): 9 matches in 8 files, 0 skipped, 0 errors.
sigscan: info: scan complete files=13 matches=9 skipped=0 errors=0 elapsed_ms=2
```

The five `benign_*` files are near misses (header at offset 1 instead of 0, allowlisted note,
`connect back` without the hyphen, ...) and correctly produce no match.

`--show-strings` adds hex/ASCII snippets (match bytes plus 4 bytes of context on each side):

```
SEVERITY  RULE                  FILE
high      Demo_Dropper_Strings  samples/files/dropper_stub.bin
          tags: dropper, demo
          why:  matched because $a found at 0x20 and 1 of ($b, $c) found ($c); filesize 108 bytes < 5 MB
          $a @0x20 len 20  5c ec ce ba 53 49 47 53 43 41 4e 2d 44 45 4d 4f 2d 50 41 59 4c 4f 41 44 3d 5d 09 1c  |\...SIGSCAN-DEMO-PAYLOAD=]..|
          $c @0x44 len 8  56 4e bf 1b 4d 5a 90 00 de ad be ef 3d 75 b8 26  |VN..MZ......=u.&|

Scanned 1 file (108 bytes): 1 match in 1 file, 0 skipped, 0 errors.
```

Rule errors (from `sigscan check fuzz/corpus/rule_parser/errors.sig`, exit code 2):

```
fuzz/corpus/rule_parser/errors.sig:1:27: error: hex string '$a' contains only wildcards; at least one literal byte is needed to anchor the matcher
rule bad1 { strings: $a = { ?? ?? } condition: $a }
                          ^
fuzz/corpus/rule_parser/errors.sig:2:32: error: jumps like [2-4] are not supported in hex strings (v1)
rule bad2 { strings: $a = { 4D [2-4] 5A } condition: $a }
                               ^
fuzz/corpus/rule_parser/errors.sig:3:29: error: unknown escape sequence '\q' (supported: \n \t \r \\ \" \xHH)
rule bad3 { strings: $a = "x\q" condition: $a }
                            ^
fuzz/corpus/rule_parser/errors.sig:4:24: error: unknown string identifier '$missing' (rule 'bad4' has no strings section)
rule bad4 { condition: $missing and unknown_identifier }
                       ^
fuzz/corpus/rule_parser/errors.sig:5:30: error: invalid severity 'urgent' (expected "low", "medium", "high" or "critical")
rule bad5 { meta: severity = "urgent" condition: true }
                             ^
fuzz/corpus/rule_parser/errors.sig:7:6: error: duplicate rule name 'good' (first defined at fuzz/corpus/rule_parser/errors.sig:6:6)
rule good { condition: true }
     ^
fuzz/corpus/rule_parser/errors.sig: errors, 1 rule
check failed: 6 errors, 0 warnings
```

## Output formats & exit codes

- **table** (default): one block per (file, rule) with severity, tags, the why line and per-string
  hits, then files that were skipped or unreadable, then a summary line.
- **json**: a stable, documented schema (`schema_version: 1`; field list in
  [docs/rule-language.md](docs/rule-language.md#json-report-schema-version-1)). Excerpt from
  `sigscan scan -r samples/rules/demo.sig --format json samples/files/dropper_wide.bin`:

  ```json
  {
    "file": "samples/files/dropper_wide.bin",
    "file_size": 140,
    "rule": "Demo_Dropper_Strings",
    "tags": ["dropper", "demo"],
    "severity": "high",
    "meta": {"author": "Sigscan samples", "description": "Fictional dropper marker strings used in the synthetic samples", "severity": "high"},
    "condition": "$a and (any of ($b, $c) or #d >= 2) and filesize < 5MB",
    "why": "matched because $a found at 0x0 and #d is 2 (>= 2); filesize 140 bytes < 5 MB",
    "strings": [
      {"id": "$a", "count": 1, "offsets": [0], "offsets_truncated": false},
      {"id": "$d", "count": 2, "offsets": [24, 106], "offsets_truncated": false}
    ]
  }
  ```

  (The real output is pretty-printed one value per line; arrays are condensed here for space.)
- **sarif**: SARIF 2.1.0 with one run; `tool.driver.rules` describes every loaded rule
  (`shortDescription` from `meta.description`, `level` from severity, `security-severity`
  9.5/8.0/5.0/2.0), and each result has the why line as its message and a `region.byteOffset` /
  `byteLength` for the first hit of each matched string. Unreadable or skipped files appear as
  `toolExecutionNotifications`.

| Exit code | Meaning |
|---|---|
| `0` | Ran fine; no match at or above `--fail-on` |
| `1` | At least one match at or above `--fail-on` (default `low`, so any match) |
| `2` | Usage, configuration, rule or input error (bad option, rule diagnostics, missing path, refused `--output` overwrite) |

Unreadable or oversized files inside a scan are reported and counted but do not change the exit
code on their own.

## Testing

```bash
cmake --preset dev  && cmake --build --preset dev  && ctest --preset dev
cmake --preset asan && cmake --build --preset asan && ctest --preset asan
./tools/lint.sh      # clang-format --dry-run --Werror + clang-tidy on src/lib
```

`ctest` runs 99 tests: 96 GoogleTest cases, a check that `samples/files` is exactly what
`samples/generate.py` produces, and the two fuzz smoke drivers (2,000 mutations each). The
GoogleTest suite covers:

- the lexer and parser: every construct, every error message with its `line:col`, error
  recovery, precedence, depth limits, duplicate names across files;
- the matcher: Aho-Corasick against the naive matcher on randomized inputs (60 fixed seeds,
  text/nocase/wide/hex patterns over a small alphabet), the classic `he/she/his/hers` dictionary,
  alphabet classes, atom sharing, the table-size budget;
- scanning: chunk boundaries for every chunk size 1-40 and in a 192 KiB file, overlapping hits,
  every condition operator, counts, offsets, `at`, `in`, `filesize`, the offset cap, snippets,
  and the exact "why" text;
- directory walking: symlinked files and directories not followed, a symlink loop, skip globs
  pruning directories, `--max-files`, and a file swapped for a symlink after the walk;
- the CLI: exit codes 0/1/2, `--fail-on`, the JSON schema, SARIF structure, `--output` mode
  0600 and overwrite refusal, config files, JSON logs, and identical output for 1 and 8 threads;
- a regression over all 13 sample files (expected matches *and* non-matches) at two chunk sizes.

### Sanitizers and fuzzing: what ran where

| What | Where | Result |
|---|---|---|
| Full test suite under ASan + UBSan (`asan` preset) | locally (macOS, Apple clang 21) and in CI (Ubuntu, clang) | locally: 99/99 passed |
| Fuzz smoke driver, `fuzz_rule_parser`, ASan + UBSan | locally | 5 seeds + 25,000 mutated inputs per run, seeds 1 and 2 (18.4 MB and 18.7 MB), clean |
| Fuzz smoke driver, `fuzz_matcher`, ASan + UBSan | locally | 5 seeds + 25,000 mutated inputs per run, seeds 1 and 2 (3.1 MB each), clean |
| Fuzz smoke driver, 20,000 mutations per target | CI (Ubuntu, ASan + UBSan) | runs on every push |
| libFuzzer (coverage-guided), 60 s per target | CI only (Ubuntu clang) | runs on every push |

Apple clang does not ship libFuzzer, so the coverage-guided targets were not run locally; the
smoke driver (`fuzz/smoke_main.cpp`) feeds the same `LLVMFuzzerTestOneInput` entry points with
the seed corpus plus deterministic mutations (bit flips, byte edits, range deletes and
duplicates, rule-language dictionary tokens, splices). `fuzz_matcher` is differential: it builds
random text/nocase/wide/hex patterns from the input and aborts unless the automaton, the naive
matcher and a chunked scan with a fuzzer-chosen chunk size all agree.

## Performance notes

`sigscan bench` loads the input into memory, checks that both engines find identical hits, then
times each engine on the same bytes (1 MB = 1,048,576 bytes). The benchmark corpus is generated:

```bash
python3 samples/generate.py bench build/bench --size-mb 32 --rules 100
./build/release/sigscan bench -r build/bench/bench.sig --iterations 3 build/bench/corpus.bin
```

Measured on this machine: **Apple M2** (`sysctl -n machdep.cpu.brand_string`), 8 cores, 16 GB,
macOS, Apple clang 21, **`release` preset (`-O3 -DNDEBUG`)**, single thread, 3 timed passes per
engine over a 32 MiB generated corpus. The machine was shared with other work (1-minute load
average about 6 when the run started), so treat the absolute numbers as indicative; both engines
ran under the same conditions on the same bytes.

100 generated rules (400 strings: text, `nocase`, `wide`, hex with a wildcard):

```
rules:       100 rules, 400 patterns, 400 atoms, 2852 automaton states
input:       1 file, 32.0 MB, 3 timed passes per engine

engine          time (ms)   throughput (MB/s)   hits/pass
aho-corasick    189.4       507.0               32
naive           45338.0     2.1                 32

speedup: 239.4x (1 MB = 1048576 bytes); both engines found identical hits
```

The six demo rules (23 patterns) on the same corpus:

```
rules:       6 rules, 23 patterns, 23 atoms, 369 automaton states
input:       1 file, 32.0 MB, 3 timed passes per engine

engine          time (ms)   throughput (MB/s)   hits/pass
aho-corasick    188.8       508.5               0
naive           2629.1      36.5                0

speedup: 13.9x (1 MB = 1048576 bytes); both engines found identical hits
```

The automaton's throughput is the same (about 508 MB/s) for 23 and 400 patterns, while the naive
scanner slows down roughly in proportion to the pattern count (one pass per pattern), so the gap
widens as rule packs grow. Matching is single-threaded per file; `--threads` parallelizes across
files.

## Limitations

- **Language subset.** No hex jumps (`[2-4]`), alternatives, nibble wildcards or negated bytes;
  no regular expressions; no `fullword`, `xor`, `base64` or `private`/`global` rules; no modules
  (`pe`, `elf`, ...); no `for` loops, arithmetic, `@a[i]`/`!a[i]`, `entrypoint`, `uint32(...)`
  reads, or rule references inside conditions. Unsupported syntax is a clear error, never
  silently ignored.
- **`nocase` is ASCII-only**, and `wide` means UTF-16LE of the given bytes (no UTF-8 to UTF-16
  transcoding of non-ASCII text).
- **Offset cap.** Only the first `--max-matches` offsets per string are kept (counts stay exact),
  so `at`/`in` conditions cannot see occurrences beyond the cap.
- **Single-byte anchors** (hex strings whose longest literal run is one byte) are accepted with a
  warning but can be slow on large inputs, because every occurrence of that byte must be verified.
- **Whole-file size cap.** Files above `--max-filesize` are skipped, not partially scanned.
- **Not a sandbox.** Sigscan never executes files, but it is a content matcher: it does not
  unpack archives, decompress, or emulate anything.
- Windows builds are untested.

## Roadmap

- Hex jumps and alternatives by splitting patterns into several anchored atoms.
- `fullword` and `private` rules; rule references inside conditions.
- An optional memory-mapped read path for large files.
- A `--stats` flag with per-rule timing to spot slow rules.
- Packaging (Homebrew formula, Debian package) once the CLI is stable.

## Ethical use

Sigscan is a defensive tool for finding known content in files you own or are authorized to
examine. Only scan systems and data you have permission to inspect, and handle any real samples
you analyze according to your organization's policies. The repository contains only synthetic,
harmless sample data; please keep it that way in contributions.

## License

[MIT](LICENSE). Copyright (c) 2026 Sigscan contributors.
