# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **private vulnerability reporting**:
open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a
public issue for security problems.

Include the Sigscan version (`sigscan --version`), compiler and OS, a minimal rule file and/or
input that reproduces the problem (synthetic data only, please; never send real malware), and
what you expected to happen. A crashing input found with the fuzzers in `fuzz/` is ideal.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days.
- A fix or mitigation plan for confirmed issues, with credit in the release notes if you want
  it. Please allow a reasonable time for a fix before public disclosure.

## Scope

In scope: anything that lets a crafted rule file, config file or scanned file cause memory
corruption, undefined behaviour, code execution, reads of files other than the ones named or
walked, writes outside the requested `--output` path, a hang, or resource use out of proportion
to the input size and the configured limits. Wrong match results (false negatives on the
documented language subset) are bugs too; please report them as normal issues unless they have
a security impact.

Out of scope: detection quality of the sample rules, and the documented limitations in the
README (for example the per-string offset cap).

## Safety design

Sigscan is a defensive, read-only tool. The design choices below are deliberate; changes that
weaken them will not be accepted.

- **Never executes or modifies scanned files.** Files are opened read-only (`O_RDONLY`) and only
  their bytes are inspected. There are no subprocesses, no shell, no plugins, and no network
  code at all.
- **No symlink surprises.** Directory walking never descends into directory symlinks (which also
  rules out symlink loops) and skips file symlinks unless `--follow-symlinks` is given. Walked
  files are opened with `O_NOFOLLOW`, so a file swapped for a symlink between the walk and the
  open is refused rather than followed. FIFOs, sockets and devices are skipped, and files are
  opened with `O_NONBLOCK` so a FIFO can never block a scan.
- **Bounded resource use.** Every file is size-checked with `fstat` and again while reading
  (default cap 64 MiB, `--max-filesize`); oversized files are reported as skipped. Reads are
  chunked (1 MiB) with a small overlap, so memory does not grow with file size. Offsets kept per
  string are capped (`--max-matches`, counts stay exact), the walk is capped (`--max-files`), rule
  and config files are capped at 4 MiB / 1 MiB, the automaton's transition table is capped at
  256 MiB, and condition nesting is capped at 64 levels so hostile rules cannot exhaust the stack.
- **Defensive parsing.** The rule lexer and parser are hand-written with explicit bounds checks
  and checked 64-bit arithmetic for every number, size suffix and offset. Bad input produces a
  `file:line:col` diagnostic, never a crash. Both the parser and the matcher are fuzzed (libFuzzer
  in CI, plus a portable smoke driver under ASan and UBSan).
- **Safe output.** Reports go to stdout or to `--output`, which is created with mode `0600`,
  refuses to overwrite an existing file without `--force`, and refuses to write through a
  symlink (`O_NOFOLLOW`). JSON and SARIF strings are escaped, and invalid UTF-8 in file names is
  replaced rather than emitted raw.
