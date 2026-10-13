#!/bin/bash
# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 16:55, 17:37, 17:46
# (zero kernel trace => hardware lockup). Keep off until crash capture (netconsole) is in place.
[ "${ALLOW_DEVMEM:-}" = "1" ] || { echo "REFUSING: raw /dev/mem probes freeze this laptop. Override: ALLOW_DEVMEM=1 $0" >&2; exit 1; }
# Deep diagnostic batch #2 for GXFP5120 bring-up. Run as root (pkexec).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SPI=spi-GXFP5120:00
DSL="${DSL:-$HOME/Desktop/projects/acpi-tables/DSDT.dsl}"
[ -r "$DSL" ] || { echo "ERROR: cannot read $DSL"; exit 1; }

echo "==================== A. memory blobs ===================="
python3 - "$DSL" <<'PYEOF'
import re, struct, sys
dsl = open(sys.argv[1]).read()

def field_offsets(region):
    i = dsl.find('Field (%s' % region)
    if i < 0: return None
    j = dsl.index('{', i)
    depth = 0; k = j
    while k < len(dsl):
        if dsl[k] == '{': depth += 1
        elif dsl[k] == '}':
            depth -= 1
            if depth == 0: break
        k += 1
    body = dsl[j:k]
    off = 0; out = {}
    for line in body.splitlines():
        line = line.strip()
        m = re.match(r'Offset \((0x[0-9A-Fa-f]+)\)', line)
        if m: off = int(m.group(1), 16); continue
        m = re.match(r'([A-Z0-9]+),\s*(\d+)', line)
        if m:
            out[m.group(1)] = off
            off += (int(m.group(2)) + 7) // 8
    return out

gnvs = field_offsets('GNVS'); pnva = field_offsets('PNVA'); ogns = field_offsets('OGNS')
G_BASE, P_BASE, O_BASE = 0x45AB8018, 0x45AC3018, 0x45AC3D18

def rd(addr, n):
    with open('/dev/mem', 'rb', buffering=0) as f:
        f.seek(addr); return f.read(n)

def u32(b, o=0): return struct.unpack_from('<I', b, o)[0]
def u16(b, o=0): return struct.unpack_from('<H', b, o)[0]

try:
    gnvs_data = rd(G_BASE + gnvs['FPTT'] - 8, 64)
    fptt = gnvs_data[ 8 ]
    fptm = gnvs_data[ 9 ]
    print("GNVS raw around FPTT (offset 0x%X):" % (gnvs['FPTT']-8), gnvs_data.hex(' '))
    for name in ('TPDT','TPDM','FPTT','FPTM'):
        print("  %s = 0x%02X" % (name, gnvs_data[8 + gnvs[name] - gnvs['FPTT']]))
    for name in ('SDS7',):
        b = rd(G_BASE + gnvs[name], 1); print("  %s = 0x%02X" % (name, b[0]))
    gf = rd(G_BASE + gnvs['GFPS'], 8)
    print("  GFPS = 0x%08X   GFPI = 0x%08X" % (u32(gf,0), u32(gf,4)))
    gd = rd(G_BASE + gnvs['GPDI'], 8)
    print("  GPDI = 0x%08X   GPLI = 0x%08X" % (u32(gd,0), u32(gd,4)))
except Exception as e:
    print("GNVS read failed:", e)

try:
    sbrg = u32(rd(P_BASE + pnva['SBRG'], 4))
    pchs = u16(rd(P_BASE + pnva['PCHS'], 2))
    print("PNVA: PCHS=0x%04X  SBRG=0x%08X" % (pchs, sbrg))
except Exception as e:
    sbrg = None
    print("PNVA read failed:", e)

try:
    org = rd(O_BASE, 16)
    print("OGNS: raw =", org.hex(' '), "  FPSW(off 0x%X)=0x%02X" % (ogns['FPSW'], org[ogns['FPSW']]))
except Exception as e:
    print("OGNS read failed:", e)

# --- pad scan: decode PMODE for all pads per GPCL community ---
if sbrg:
    i = dsl.find('Name (GPCL, Package')
    seg = dsl[i:i+6000]
    entries = []
    for m in re.finditer(r'Package \(0x07\)\s*\{(.*?)\}', seg, re.S):
        nums = re.findall(r'0x[0-9A-Fa-f]+|Zero|One', m.group(1))
        vals = [int(x, 16) if x.startswith('0x') else (0 if x == 'Zero' else 1) for x in nums]
        if len(vals) == 7: entries.append(vals)
    print("\nGPCL communities parsed: %d" % len(entries))
    try:
        use_sel = u32(rd(sbrg + entries[0][0] + entries[0][3], 4))
        print("community0 GPIO_USE_SEL = 0x%08X  (bit17 = %d)  <- SHPO evidence"
              % (use_sel, (use_sel >> 17) & 1))
    except Exception as e:
        print("usesel read failed:", e)
    for idx, e in enumerate(entries):
        try:
            base = sbrg + e[0] + e[2]
            nf = []
            for pad in range(e[1]):
                dw0 = u32(rd(base + pad * 8, 4))
                pmode = (dw0 >> 10) & 7
                if pmode != 0:
                    nf.append((pad, pmode, dw0))
            if nf:
                print("  community[%2d] base=0x%06X count=%d -> non-GPIO pads: %s"
                      % (idx, e[0], e[1],
                         ', '.join('p%d:m%d' % (p, m) for p, m, _ in nf)))
            else:
                print("  community[%2d] base=0x%06X count=%d -> all GPIO (PMODE 0)" % (idx, e[0], e[1]))
        except Exception as ex:
            print("  community[%d] scan failed: %s" % (idx, ex))
PYEOF

echo
echo "==================== B. iomem reservation ===================="
grep -iE '45ab|45ac|45ad' /proc/iomem || echo "(no matching reservations)"
grep -iE 'pxa|spi' /proc/iomem || true

echo
echo "==================== C. pinctrl ===================="
ls /sys/kernel/debug/pinctrl/ 2>/dev/null
P=$(ls -d /sys/kernel/debug/pinctrl/*/ 2>/dev/null | head -1)
if [ -n "$P" ]; then
    echo "-- files: $(ls "$P")"
    echo "-- claimed (non-unclaimed) pins:"
    grep -v "MUX UNCLAIMED" "$P/pinmux-pins" 2>/dev/null | head -20
    echo "-- total pins: $(wc -l < "$P/pinmux-pins" 2>/dev/null)"
fi

echo
echo "==================== D. gpio watch during probe ===================="
command -v gpiomon >/dev/null || {
    echo "installing gpiod..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y gpiod >/dev/null 2>&1 \
        && echo "installed" || echo "INSTALL FAILED"
}
STAT="/sys/bus/spi/devices/$SPI/statistics"
echo "-- stats before:"; for f in bytes messages transfers errors timedout; do printf "%s=%s " "$f" "$(cat "$STAT/$f" 2>/dev/null)"; done; echo

if command -v gpiomon >/dev/null; then
    timeout 16 gpiomon -c gpiochip0 -n 80 $(seq 512 871) > /tmp/gpiomon.log 2>&1 &
    GM_PID=$!
    sleep 1
    "$HERE/spi-probe" /dev/spidev0.0 | grep -E 'variant|RESPONSE|SUCCESS|no response|No variant|firmware|MISO'
    wait $GM_PID 2>/dev/null
    echo "-- gpiomon events during probe window:"
    head -60 /tmp/gpiomon.log
else
    "$HERE/spi-probe" /dev/spidev0.0 | grep -E 'variant|RESPONSE|SUCCESS|no response|No variant|firmware|MISO'
fi

echo
echo "-- stats after:"; for f in bytes messages transfers errors timedout; do printf "%s=%s " "$f" "$(cat "$STAT/$f" 2>/dev/null)"; done; echo

echo
echo "==================== E. dmesg ===================="
dmesg | grep -iE 'spi|pxa|gpio|pinctrl' | tail -20
echo "done."
