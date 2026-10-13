#!/usr/bin/env python3
"""Dump EC RAM window 0xFE800700 (8KB) looking for the fingerprint mailbox.
Read-only. Run as root:  pkexec python3 dump-ec-ram.py
"""
import os
import sys

# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 17:37 and 17:46
# (this exact script: EC RAM 0xFE800700, zero kernel trace => hardware lockup below the OS).
if os.environ.get("ALLOW_DEVMEM") != "1":
    sys.exit("REFUSING: raw /dev/mem reads freeze this laptop. Set up crash capture first. "
             "Override only if a full hard freeze is acceptable: ALLOW_DEVMEM=1")

BASE = 0xFE800700
SIZE = 8192
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state-compare", "ec-ram-fe800700.bin")

with open("/dev/mem", "rb", buffering=0) as f:
    f.seek(BASE)
    data = f.read(SIZE)

with open(OUT, "wb") as f:
    f.write(data)
os.chmod(OUT, 0o644)
print(f"saved {len(data)} bytes -> {OUT}")

nz_rows = sum(1 for i in range(0, SIZE, 16) if any(data[i:i + 16]))
print(f"nonzero 16B rows: {nz_rows}/{SIZE // 16}")

pats = {
    b"\xcc\xf2": "frame hdr cc f2",
    b"\xa0\x06\x00\xa6\x20": "seen payload a00600a620",
    b"GF3658": "GF3658 ascii",
    b"GFSPI": "GFSPI ascii",
    b"finger": "finger ascii",
    b"S2H8": "S2H8 ascii",
}
for p, name in pats.items():
    hits, idx = [], 0
    while len(hits) <= 32:
        i = data.find(p, idx)
        if i < 0:
            break
        hits.append(hex(BASE + i))
        idx = i + 1
    print(f"PATTERN {name:26s}: {hits if hits else '-'}")

# nonzero region map
runs, start = [], None
for i in range(0, SIZE, 16):
    nz = any(data[i:i + 16])
    if nz and start is None:
        start = i
    if not nz and start is not None:
        runs.append((start, i))
        start = None
if start is not None:
    runs.append((start, SIZE))
print("nonzero regions:", " ".join(f"{BASE+a:#x}-{BASE+b:#x}" for a, b in runs))
