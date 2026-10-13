#!/bin/bash
# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 16:55, 17:37, 17:46
# (zero kernel trace => hardware lockup). Keep off until crash capture (netconsole) is in place.
[ "${ALLOW_DEVMEM:-}" = "1" ] || { echo "REFUSING: raw /dev/mem probes freeze this laptop. Override: ALLOW_DEVMEM=1 $0" >&2; exit 1; }
set -u
OUT="$(cd "$(dirname "$0")/.." && pwd)/state-compare"
mkdir -p "$OUT"
python3 - <<PYEOF
import struct
with open('/dev/mem','rb',buffering=0) as f:
    f.seek(0x4017003000)
    data = f.read(512)
open('$OUT/linux-lpss-spi1.bin','wb').write(data)
print("saved", len(data), "bytes")
for i in range(0, 512, 16):
    row = data[i:i+16]
    print(f"  {i:03X}: " + ' '.join(f'{b:02X}' for b in row))
PYEOF
chmod 644 "$OUT"/* 2>/dev/null
