rule bad1 { strings: $a = { ?? ?? } condition: $a }
rule bad2 { strings: $a = { 4D [2-4] 5A } condition: $a }
rule bad3 { strings: $a = "x\q" condition: $a }
rule bad4 { condition: $missing and unknown_identifier }
rule bad5 { meta: severity = "urgent" condition: true }
rule good { condition: false }
rule good { condition: true }
