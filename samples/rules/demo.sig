// Sigscan demo rules.
//
// Every string below is a fictional marker invented for the synthetic files in samples/files
// (see samples/generate.py). None of them comes from real malware. Together the rules exercise
// every feature of the rule language: text, nocase, wide, ascii, escapes, hex with wildcards,
// counts, at, in, filesize, string sets with wildcards, any/all/N of, and, or, not.

rule Demo_Dropper_Strings : dropper demo
{
  meta:
    author = "Sigscan samples"
    description = "Fictional dropper marker strings used in the synthetic samples"
    severity = "high"          // low|medium|high|critical
  strings:
    $a = "SIGSCAN-DEMO-PAYLOAD"            // text, case-sensitive
    $b = "connect-back" nocase             // case-insensitive ASCII
    $c = { 4D 5A ?? 00 DE AD ?? EF }        // hex with ?? wildcards (single-byte)
    $d = "evil.example.net" wide           // UTF-16LE
  condition:
    $a and (any of ($b, $c) or #d >= 2) and filesize < 5MB
}

rule Demo_Beacon_Config : beacon config demo
{
  meta:
    description = "Fictional beacon configuration keys"
    severity = "medium"
    version = 2
    reviewed = true
  strings:
    $cfg_interval = "SIGSCAN_BEACON_INTERVAL="
    $cfg_jitter = "SIGSCAN_BEACON_JITTER="
    $cfg_server = "server=c2.example.org"
    $host = "c2.example.org" ascii wide
  condition:
    2 of ($cfg*) and $host
}

rule Demo_Packed_Header : packer binary demo
{
  meta:
    description = "Synthetic container header written by samples/generate.py"
    severity = "critical"
  strings:
    $magic = { 53 53 43 4B ?? ?? 01 00 }   // "SSCK", two wildcard bytes, version 1
    $section = ".sspk\x00\x01"
    $stub = { E8 ?? ?? ?? ?? 5D C3 }
  condition:
    $magic at 0 and $section in (0..4096) and all of them and filesize < 64KB
}

rule Demo_Ransom_Note_Text : note demo
{
  meta:
    description = "Fictional ransom-note phrasing (synthetic and harmless)"
    severity = "high"
  strings:
    $headline = "YOUR FILES ARE SAFE - THIS IS A SIGSCAN TEST" nocase ascii wide
    $id = "sigscan-recovery-id:"
    $contact = "contact=\"help@example.com\"\t(test)"
    $allow = "SIGSCAN-ALLOWLISTED"
  condition:
    ($headline or all of ($id, $contact)) and not $allow
}

rule Demo_Unicode_Notice : unicode demo
{
  meta:
    description = "UTF-16LE notice text from the synthetic samples"
    severity = "medium"
  strings:
    $w1 = "Sigscan synthetic notice" wide
    $w2 = "do not distribute this demo" wide nocase
  condition:
    any of them and filesize <= 1MB
}

rule Demo_Multi_Marker : demo
{
  meta:
    description = "Most of the generic demo markers together, or marker one twice"
    severity = "low"
  strings:
    $m1 = "SIGSCAN-MARKER-ONE"
    $m2 = "SIGSCAN-MARKER-TWO\n"
    $m3 = "sigscan\\marker\\three"
    $m4 = { 53 49 47 ?? 34 }
  condition:
    3 of them or (#m1 == 2 and $m1 at 16)
}
