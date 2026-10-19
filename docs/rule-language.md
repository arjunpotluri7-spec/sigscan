# Sigscan rule language reference

Sigscan rules (`.sig` files) are a deliberately small, YARA-like language. This page is the
complete reference for v1; anything not listed here is rejected with a `file:line:col` error.

## File structure

```
rule NAME [: TAG ...]
{
  [meta:
    KEY = "text" | NUMBER | true | false
    ...]
  [strings:
    $ID = "text" [nocase] [wide] [ascii]
    $ID = { HEX BYTES }
    ...]
  condition:
    EXPRESSION
}
```

- Sections must appear in the order `meta`, `strings`, `condition`. Only `condition` is required.
- Rule names, tags and meta keys are identifiers: `[A-Za-z_][A-Za-z0-9_]*`, at most 128
  characters, and not a keyword (`rule meta strings condition and or not any all of them at in
  filesize true false nocase wide ascii`).
- Rule names must be unique across **all** rule files loaded together. Tags and meta keys must be
  unique within a rule.
- Comments: `// to end of line` and `/* block */`.

## Meta

Any key is allowed; values are text, numbers (decimal or `0x` hex, optional `KB`/`MB` suffix) or
`true`/`false`. Two keys are special:

| Key | Effect |
|---|---|
| `severity` | `"low"`, `"medium"` (default), `"high"` or `"critical"`. Drives `--fail-on`, table output and SARIF `level`. Any other value is an error. |
| `description` | Used as the SARIF rule `shortDescription`. |

All meta entries appear in JSON output with their types preserved.

## Strings

### Text strings

`$id = "text"` matches the bytes of the text exactly (case-sensitive).

Escapes: `\n` `\t` `\r` `\\` `\"` `\xHH` (two hex digits; `\x00` is allowed). Any other escape
is an error. Text strings may not be empty, may not span lines, and are at most 4096 bytes.

Modifiers (each at most once):

| Modifier | Meaning |
|---|---|
| `nocase` | ASCII case-insensitive (`A-Z` = `a-z`; bytes >= 0x80 compare exactly). |
| `wide` | Match the UTF-16LE form: every byte followed by `00`. On its own, only the wide form is matched. |
| `ascii` | Match the plain form. This is the default; write it together with `wide` to match both. |

### Hex strings

`$id = { 4D 5A ?? 00 DE AD ?? EF }`: pairs of hex digits are literal bytes, `??` matches any
single byte. Whitespace (including newlines) and `//` comments are allowed between bytes.

Not supported in v1, each with a specific error message: jumps (`[2-4]`), alternatives
(`( AA | BB )`), nibble wildcards (`4?`, `?D`) and negated bytes (`~AA`). Modifiers are not
allowed on hex strings.

A hex string must contain **at least one literal byte**. A string made only of `??` is rejected,
because it gives the multi-pattern matcher nothing to anchor on (it would match at every offset).
A string anchored on a single literal byte is accepted with a warning, since it produces many
candidate positions to verify.

### Unused strings

A string that the condition never references (directly, through `them`, or through a `$prefix*`
set) produces a **warning**, not an error.

## Conditions

Operator precedence, from loosest to tightest: `or`, `and`, `not`. Use parentheses to group.
Nesting is limited to 64 levels.

| Expression | True when |
|---|---|
| `true`, `false` | always / never |
| `$a` | `$a` occurs at least once |
| `#a OP N` | the number of occurrences of `$a` compares true; `OP` is one of `== != < <= > >=` |
| `$a at N` | `$a` occurs at exactly file offset `N` |
| `$a in (S..E)` | `$a` occurs at some offset `S <= offset <= E` (inclusive); `S > E` is an error |
| `any of SET` | at least one string in `SET` occurs |
| `all of SET` | every string in `SET` occurs |
| `N of SET` | at least `N` strings in `SET` occur; `N` must be 1..size of `SET` |
| `filesize OP N` | the file size compares true |

`SET` is `them` (every string in the rule) or a parenthesised list of identifiers and prefix
wildcards, such as `($a, $b)`, `($cfg*)` or `($*)`. A wildcard that matches no string is an
error.

Numbers are decimal or `0x` hex and may carry a `KB` (x1024) or `MB` (x1048576) suffix, as in
`filesize < 5MB` or `$a at 0x1A0`. Every number must fit in 64 bits; overflow is an error.

Referencing a string that does not exist in the rule (`$z`, `#z`), or any identifier that is not
part of the language, is an error.

## Matching semantics

- Occurrences may overlap: `"aa"` occurs 4 times in `aaaaa`.
- For a string with both `ascii` and `wide` forms, an offset where both forms match counts once.
- Counts (`#a`) are always exact. Offsets used by `at`, `in`, the "why" line and the report are
  kept for the first `--max-matches` occurrences of each string (default 1000); with more
  occurrences than that, `at`/`in` only see the stored ones.
- Files are matched in 1 MiB chunks with an overlap of (longest pattern - 1) bytes, so a pattern
  that crosses a chunk boundary is found exactly once.

## Diagnostics

Errors and warnings use the compiler format, with the source line and a caret:

```
fuzz/corpus/rule_parser/errors.sig:4:24: error: unknown string identifier '$missing' (rule 'bad4' has no strings section)
rule bad4 { condition: $missing and unknown_identifier }
                       ^
```

After an error, the parser skips to the next `rule` keyword and keeps going, so one run reports
problems in several rules (up to 50 per file).

## JSON report schema (version 1)

`sigscan scan --format json` prints one object:

| Field | Type | Notes |
|---|---|---|
| `tool`, `version` | string | `"sigscan"`, tool version |
| `schema_version` | number | `1`; bumped on incompatible changes |
| `rule_files` | string[] | rule files as given |
| `summary` | object | `files_scanned`, `files_matched`, `matches`, `skipped`, `errors`, `bytes_scanned` (numbers), `truncated` (bool: `--max-files` reached) |
| `matches[]` | object[] | one entry per (file, rule), sorted by file path, then rule order |
| `matches[].file`, `.file_size` | string, number | path as displayed, size in bytes |
| `matches[].rule`, `.tags`, `.severity`, `.meta`, `.condition` | | from the rule; `meta` keeps value types |
| `matches[].why` | string | one-line explanation |
| `matches[].strings[]` | object[] | strings of the rule that were found: `id`, `count`, `offsets` (number[]), `offsets_truncated` (bool) and, with `--show-strings`, `snippets[]` of `{offset, length, context_offset, hex, ascii}` |
| `skipped[]` | object[] | `{file, reason}` for files over `--max-filesize` |
| `errors[]` | object[] | `{file, message}` for files that could not be read |

The SARIF output follows SARIF 2.1.0: one run, `tool.driver.rules` lists every loaded rule
(with `properties.tags`, `severity` and `security-severity`), and each result points at the
first offset of up to 10 matched strings via `region.byteOffset` / `byteLength`.
