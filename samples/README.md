# Samples

Everything in this directory is **synthetic and harmless**. There is no real malware here, no
EICAR test file, and no strings taken from real malware families.

- `rules/demo.sig` holds six demo rules. Their strings are fictional markers invented for this
  project, such as `SIGSCAN-DEMO-PAYLOAD`, `SIGSCAN_BEACON_INTERVAL=` and `evil.example.net`
  (`example.net` and `example.org` are reserved documentation domains). Together the rules use
  every feature of the rule language.
- `files/` holds the files the rules are tested against. **All of them are written by
  [`generate.py`](generate.py)**, so the origin of every byte is visible: fixed text, UTF-16LE
  encodings of fixed text, and filler from a tiny seeded linear congruential generator.

| File | Expected match | Why |
|---|---|---|
| `dropper_note.txt` | `Demo_Dropper_Strings` | `$a` plus `Connect-Back` (`$b`, nocase) |
| `dropper_stub.bin` | `Demo_Dropper_Strings` | `$a` plus the hex pattern `$c` with wildcards |
| `dropper_wide.bin` | `Demo_Dropper_Strings` | `$a` plus two UTF-16LE copies of `$d` (`#d >= 2`) |
| `beacon.cfg` | `Demo_Beacon_Config` | three `$cfg*` keys and the host |
| `archive/nested/beacon_copy.cfg` | `Demo_Beacon_Config` | two `$cfg*` keys and the host in UTF-16LE (`ascii wide`) |
| `packed_sample.bin` | `Demo_Packed_Header` | header `at 0`, section `in (0..4096)`, stub, `filesize < 64KB` |
| `ransom_note_utf16.txt` | `Demo_Ransom_Note_Text`, `Demo_Unicode_Notice` | UTF-16LE text, `nocase wide` |
| `markers.txt` | `Demo_Multi_Marker` | marker one twice, first copy `at 16` |
| `benign_readme.txt` | none | near misses: `SIGSCAN-DEMO`, `connect back`, key without `=` |
| `benign_allowlisted_note.txt` | none | headline present but `not $allow` fails |
| `benign_near_miss.bin` | none | header at offset 1 instead of 0 |
| `benign_markers_partial.txt` | none | only one marker string |
| `benign_random.bin` | none | 4 KiB of seeded pseudo-random bytes |

Regenerate or verify:

```bash
python3 samples/generate.py           # rewrite samples/files/
python3 samples/generate.py --check   # CI/ctest: committed files must match the script
python3 samples/generate.py bench build/bench --size-mb 32 --rules 100   # benchmark corpus
```

The benchmark corpus is written under `build/` (gitignored); it is not committed.
