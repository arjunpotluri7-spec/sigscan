rule all_constructs : t1 t2
{
  meta:
    severity = "critical"
    count = 0x10
    flag = false
  strings:
    $a = "a\n\t\\\"\x41" nocase wide ascii
    $b1 = { 41 ?? 42 }
    $b2 = "bb"
  condition:
    ($a at 0 or $a in (0..10) or #a != 3) and not (2 of ($b*) or all of them or any of ($a, $b1))
    and filesize >= 1KB and filesize <= 2MB and #b2 < 5 and #b2 > 0 and #b2 == 1 and true
}
