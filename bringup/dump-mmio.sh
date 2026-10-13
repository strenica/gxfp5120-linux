#!/bin/bash
# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 16:55, 17:37, 17:46
# (zero kernel trace => hardware lockup). Keep off until crash capture (netconsole) is in place.
[ "${ALLOW_DEVMEM:-}" = "1" ] || { echo "REFUSING: raw /dev/mem probes freeze this laptop. Override: ALLOW_DEVMEM=1 $0" >&2; exit 1; }
# Capture the Linux-side hardware state of the fingerprint SPI controller +
# GPP_B pads, for diffing against a Windows-side (RWEverything) capture.
set -u
OUT="$(cd "$(dirname "$0")/.." && pwd)/state-compare"
mkdir -p "$OUT"
chmod 777 "$OUT" 2>/dev/null

echo "== LPSS SPI1 MMIO (PCI 00:1e.3 BAR0 = 0x4017003000), 512 bytes =="
dd if=/sys/bus/pci/devices/0000:00:1e.3/resource0 of="$OUT/linux-lpss-spi1.bin" bs=1 count=512 2>/dev/null
echo "saved $(stat -c%s "$OUT/linux-lpss-spi1.bin") bytes -> $OUT/linux-lpss-spi1.bin"
hexdump -C "$OUT/linux-lpss-spi1.bin" | head -36

echo
echo "== GPP_B pads 15-22 + community regs (PCH SBREG 0xFD6E0000 base) =="
python3 - <<'EOF' | tee "$OUT/linux-pads.txt"
import struct
def u32(a):
    with open('/dev/mem','rb',buffering=0) as f:
        f.seek(a); return struct.unpack('<I', f.read(4))[0]
print("PCH community 0x6E0000 (GPP_B):")
for name,off in (("PAD_OWN",0x020),("PADCFGLOCK",0x080),("PADCFGLOCKTX",0x084),("HOSTSW_OWN",0x0B0),("GPI_IS",0x100),("GPI_IE",0x120)):
    print("  %-12s @0xFD6E%04X = 0x%08X" % (name, off, u32(0xFD6E0000+off)))
print("pads 15..22 PADCFG (DW0..DW3):")
for pad in range(15,23):
    base=0xFD6E0700+pad*16
    dw=[u32(base+4*i) for i in range(4)]
    print("  pad %2d: %08X %08X %08X %08X" % (pad, *dw))
EOF
chmod 644 "$OUT"/* 2>/dev/null
echo
echo "saved -> $OUT/linux-pads.txt"
