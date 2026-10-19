#!/usr/bin/env python3
"""Generate the synthetic, harmless sample files used by Sigscan's demo and tests.

Every file is built from fictional marker strings (for example "SIGSCAN-DEMO-PAYLOAD") and a
small deterministic pseudo-random generator, so the bytes are reproducible and their origin is
transparent. Nothing here is, contains, or resembles real malware.

    python3 samples/generate.py            # (re)write samples/files/
    python3 samples/generate.py --check    # verify committed files match this script
    python3 samples/generate.py bench OUT  # write a larger benchmark corpus + rules into OUT
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"


class Lcg:
    """Tiny 32-bit LCG so the filler bytes do not depend on Python's random module."""

    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFF

    def next_byte(self) -> int:
        self.state = (self.state * 1664525 + 1013904223) & 0xFFFFFFFF
        return (self.state >> 24) & 0xFF

    def bytes(self, n: int) -> bytes:
        return bytes(self.next_byte() for _ in range(n))

    def text(self, n: int) -> bytes:
        alphabet = b"abcdefghijklmnopqrstuvwxyz      .,\n"
        return bytes(alphabet[self.next_byte() % len(alphabet)] for _ in range(n))


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def place(size: int, filler: bytes, items: list[tuple[int, bytes]]) -> bytes:
    data = bytearray(filler[:size].ljust(size, b"\x00"))
    for offset, blob in items:
        data[offset : offset + len(blob)] = blob
    return bytes(data)


def build_samples() -> dict[str, bytes]:
    out: dict[str, bytes] = {}

    # --- files that must match -------------------------------------------------------------
    out["dropper_note.txt"] = (
        b"Synthetic sample for the Sigscan demo. Harmless text only.\n"
        b"stage marker: SIGSCAN-DEMO-PAYLOAD\n"
        b"next step would be a Connect-Back to 192.0.2.10 (documentation address)\n"
    )

    out["dropper_wide.bin"] = (
        b"SIGSCAN-DEMO-PAYLOAD\x00\x00\x00\x00"
        + utf16("evil.example.net")
        + b"\x00\x00"
        + Lcg(7).bytes(48)
        + utf16("evil.example.net")
        + b"\x00\x00"
    )

    out["dropper_stub.bin"] = (
        Lcg(11).bytes(32)
        + b"SIGSCAN-DEMO-PAYLOAD"
        + Lcg(12).bytes(16)
        + bytes([0x4D, 0x5A, 0x90, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
        + Lcg(13).bytes(32)
    )

    out["beacon.cfg"] = (
        b"# synthetic beacon configuration for the Sigscan demo\n"
        b"SIGSCAN_BEACON_INTERVAL=60\n"
        b"SIGSCAN_BEACON_JITTER=15\n"
        b"server=c2.example.org\n"
    )

    out["archive/nested/beacon_copy.cfg"] = (
        b"SIGSCAN_BEACON_INTERVAL=300\n"
        b"SIGSCAN_BEACON_JITTER=30\n"
        b"endpoint (utf-16): " + utf16("c2.example.org") + b"\n"
    )

    header = b"SSCK" + bytes([0x02, 0x07, 0x01, 0x00])
    section = b".sspk\x00\x01"
    stub = bytes([0xE8, 0x10, 0x20, 0x30, 0x40, 0x5D, 0xC3])
    out["packed_sample.bin"] = place(
        2048, Lcg(21).bytes(2048), [(0, header), (0x40, section), (0x200, stub)]
    )

    out["ransom_note_utf16.txt"] = b"\xff\xfe" + utf16(
        "Your files are SAFE - this is a Sigscan test.\r\n"
        "Sigscan synthetic notice: do not distribute this demo.\r\n"
    )

    markers = bytearray(Lcg(31).text(16))
    markers += b"SIGSCAN-MARKER-ONE\n"
    markers += Lcg(32).text(40)
    markers += b"SIGSCAN-MARKER-ONE\n"
    out["markers.txt"] = bytes(markers)

    # --- files that must NOT match ---------------------------------------------------------
    out["benign_readme.txt"] = (
        b"This README talks about SIGSCAN-DEMO files and how to connect back\n"
        b"to a support desk at support@example.com. It sets SIGSCAN_BEACON_INTERVAL\n"
        b"in prose only, without the equals sign, and mentions example.org.\n"
    )

    out["benign_allowlisted_note.txt"] = (
        b"YOUR FILES ARE SAFE - THIS IS A SIGSCAN TEST\n"
        b"This copy is marked SIGSCAN-ALLOWLISTED by the training team.\n"
    )

    out["benign_near_miss.bin"] = place(
        2048, Lcg(41).bytes(2048), [(1, header), (0x40, section), (0x200, stub)]
    )

    out["benign_random.bin"] = Lcg(51).bytes(4096)

    out["benign_markers_partial.txt"] = (
        b"SIGSCAN-MARKER-ONE appears once here, next to SIGSCAN-MARKER-TWO.\n"
        b"The rule wants marker two followed by a newline, so it stays quiet.\n"
    )
    return out


def write_samples() -> None:
    for name, data in build_samples().items():
        path = FILES / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(f"wrote {path.relative_to(HERE.parent)} ({len(data)} bytes)")


def check_samples() -> int:
    problems = 0
    for name, data in build_samples().items():
        path = FILES / name
        if not path.exists():
            print(f"missing: {name}")
            problems += 1
        elif path.read_bytes() != data:
            print(f"differs: {name}")
            problems += 1
    if problems:
        print(f"{problems} sample file(s) out of date; run python3 samples/generate.py")
        return 1
    print(f"all {len(build_samples())} sample files match generate.py")
    return 0


def write_bench(out_dir: Path, size_mb: int, rule_count: int) -> None:
    """Benchmark corpus: text-like filler with planted markers, plus a large rule file."""
    rng = random.Random(20261019)
    out_dir.mkdir(parents=True, exist_ok=True)
    words = [
        "alpha", "bravo", "config", "delta", "echo", "service", "update", "window", "kernel",
        "socket", "buffer", "thread", "module", "packet", "router", "signal", "vector", "matrix",
    ]
    rules = ["// Generated by samples/generate.py bench: synthetic markers only.\n"]
    markers: list[bytes] = []
    for r in range(rule_count):
        a = f"SIGSCAN-BENCH-{r:04d}-{rng.choice(words)}"
        b = f"{rng.choice(words)}-{r:04d}.example.net"
        c = " ".join(f"{rng.randrange(256):02X}" for _ in range(3))
        d = f"bench_token_{r:04d}"
        markers.append(a.encode())
        rules.append(
            f"rule Bench_{r:04d} : bench\n{{\n  meta:\n    severity = \"low\"\n"
            f"  strings:\n"
            f"    $a = \"{a}\"\n"
            f"    $b = \"{b}\" nocase\n"
            f"    $c = {{ {c} ?? 5A 5A }}\n"
            f"    $d = \"{d}\" wide\n"
            f"  condition:\n    any of them\n}}\n\n"
        )
    (out_dir / "bench.sig").write_text("".join(rules))

    block = bytearray()
    while len(block) < 1024 * 1024:
        block += rng.choice(words).encode() + b" "
        if rng.random() < 0.02:
            block += rng.randbytes(rng.randrange(1, 24))
    block = block[: 1024 * 1024]
    with (out_dir / "corpus.bin").open("wb") as f:
        for i in range(size_mb):
            chunk = bytearray(block)
            marker = markers[i % len(markers)]
            pos = rng.randrange(0, len(chunk) - len(marker))
            chunk[pos : pos + len(marker)] = marker
            f.write(chunk)
    print(f"wrote {out_dir / 'bench.sig'} ({rule_count} rules) and "
          f"{out_dir / 'corpus.bin'} ({size_mb} MiB)")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify committed sample files")
    sub = parser.add_subparsers(dest="command")
    bench = sub.add_parser("bench", help="write a benchmark corpus and rule file")
    bench.add_argument("out", type=Path)
    bench.add_argument("--size-mb", type=int, default=32)
    bench.add_argument("--rules", type=int, default=100)
    args = parser.parse_args(argv)
    if args.command == "bench":
        write_bench(args.out, args.size_mb, args.rules)
        return 0
    if args.check:
        return check_samples()
    write_samples()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
