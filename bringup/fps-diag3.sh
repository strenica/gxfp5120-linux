#!/bin/bash
# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 16:55, 17:37, 17:46
# (zero kernel trace => hardware lockup). Keep off until crash capture (netconsole) is in place.
[ "${ALLOW_DEVMEM:-}" = "1" ] || { echo "REFUSING: raw /dev/mem probes freeze this laptop. Override: ALLOW_DEVMEM=1 $0" >&2; exit 1; }
# Diagnostic batch #3: pad mux states for the SPI candidates.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SPI=spi-GXFP5120:00
DSL="${DSL:-$HOME/Desktop/projects/acpi-tables/DSDT.dsl}"

echo "==================== A. INT34C5 _CRS + GPCL mapping ===================="
python3 - "$DSL" <<'PYEOF'
import re, struct, sys
dsl = open(sys.argv[1]).read()

# --- INT34C5 device scope _CRS memory ranges ---
i = dsl.find('INT34C5')
print("INT34C5 first occurrence at", i)
seg = dsl[i-200:i+1500] if i > 0 else ""
for m in re.finditer(r'Memory(?:32)? \((0x[0-9A-Fa-f]+)', seg):
    print("  mem range start", m.group(1))
for m in re.finditer(r'(?:DWord)?Memory32Fixed.*?\n\s*\{?\s*(0x[0-9A-Fa-f]+)', seg):
    pass
# GNVS SBRG
pnva_i = dsl.find('OperationRegion (PNVA')
print("PNVA decl:", dsl[pnva_i:pnva_i+90].splitlines()[0])

# --- GPCL entries: [base, count, padcfg_off, hostsw_off, padown_off, ie_off, gpio_base] ---
i = dsl.find('Name (GPCL, Package')
seg = dsl[i:i+8000]
entries = []
for m in re.finditer(r'Package \(0x07\)\s*\{(.*?)\}', seg, re.S):
    nums = re.findall(r'0x[0-9A-Fa-f]+|Zero|One', m.group(1))
    vals = [int(x, 16) if x.startswith('0x') else (0 if x == 'Zero' else 1) for x in nums]
    if len(vals) == 7: entries.append(vals)
print("\nGPCL entries (idx: base count padcfg hostsw | gpio_base[6]):")
for k, v in enumerate(entries[:25]):
    print("  e%-2d: %06X cnt=%-3d padcfg=%04X hs=%03X | base[6]=0x%04X"
          % (k, v[0], v[1], v[2], v[3], v[6]))

# read SBRG + GNVS values we need
def rd(addr, n):
    with open('/dev/mem', 'rb', buffering=0) as f:
        f.seek(addr); return f.read(n)
def u32(b, o=0): return struct.unpack_from('<I', b, o)[0]

def field_offsets(region):
    i = dsl.find('Field (%s' % region)
    j = dsl.index('{', i); depth = 0; k = j
    while k < len(dsl):
        if dsl[k] == '{': depth += 1
        elif dsl[k] == '}':
            depth -= 1
            if depth == 0: break
        k += 1
    body = dsl[j:k]; off = 0; out = {}
    for line in body.splitlines():
        line = line.strip()
        m = re.match(r'Offset \((0x[0-9A-Fa-f]+)\)', line)
        if m: off = int(m.group(1), 16); continue
        m = re.match(r'([A-Z0-9]+),\s*(\d+)', line)
        if m:
            out[m.group(1)] = off; off += (int(m.group(2)) + 7) // 8
    return out

try:
    pnva = field_offsets('PNVA')
    sbrg = u32(rd(0x45AC3018 + pnva['SBRG'], 4))
except Exception as e:
    sbrg = 0xFD000000
    print("SBRG read failed (%s), assuming 0xFD000000" % str(e))
print("\nSBRG = 0x%08X" % sbrg)

# GNVS: read all SDS*/SDM*/FPTT/FPTM/SPBA fields
gnvs = field_offsets('GNVS')
vals = {}
for name in ('SDS0','SDS1','SDS2','SDS3','SDS4','SDS5','SDS6','SDS7','SDS8','SDS9','SDSA',
             'SDM0','SDM1','SDM2','SDM3','SDM4','SDM5','SDM6','SDM7','SDM8','SDM9','SDMA','SDMB',
             'FPTT','FPTM','GPTD','SPTD','UTKX','GIRQ','SPBA','SIO1','SIO2'):
    try:
        b = rd(0x45AB8018 + gnvs[name], 2)
        n = 1
        vals[name] = u32(b,0) & 0xFFFF
    except Exception as e:
        vals[name] = None
print("GNVS values:")
print("  " + "  ".join("%s=0x%X" % (k, v) for k, v in vals.items() if v is not None))

# --- pad scan for GPP_B (GPCL e0), GPP_T (e1), GPP_A (e2), GPP_S (e6) with stride 16 ---
for ei in (0, 1, 2, 6):
    e = entries[ei]
    base = sbrg + e[0] + e[2]
    print("\nPADCFG dump: GPCL e%d base=0x%06X padcfg@0x%08X count=%d (stride 16)" % (ei, e[0], base, e[1]))
    try:
        for pad in range(e[1]):
            dw0 = u32(rd(base + pad * 16, 4))
            dw1 = u32(rd(base + pad * 16 + 4, 4))
            pm = (dw0 >> 10) & 7
            tag = " *" if pm else ""
            print("  pad %2d: DW0=%08X DW1=%08X pmode=%d%s" % (pad, dw0, dw1, pm, tag))
    except Exception as ex:
        print("  read failed:", ex)
PYEOF

echo
echo "==================== B. pinctrl pin names near GPP_B ===================="
P=/sys/kernel/debug/pinctrl/INT34C5:00
sed -n '1,30p' "$P/pins" 2>/dev/null
echo "-- gpio-ranges:"
head -20 "$P/gpio-ranges" 2>/dev/null

echo
echo "==================== C. gpio levels + watch ===================="
if command -v gpioget >/dev/null; then
    echo "-- levels of lines 512-538 (GPP_B window):"
    gpioget -c gpiochip0 $(seq 512 538) 2>&1
    echo "-- watching lines 512-578 for 12 s during a probe run..."
    timeout 12 gpiomon -c gpiochip0 -n 40 $(seq 512 578) > /tmp/gpiomon2.log 2>&1 &
    GM=$!
    sleep 0.5
    "$HERE/spi-probe" /dev/spidev0.0 >/dev/null 2>&1
    wait $GM 2>/dev/null
    echo "-- events:"; cat /tmp/gpiomon2.log
else
    echo "gpioget missing"
fi
echo "done."
