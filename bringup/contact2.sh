#!/bin/bash
# CRASH GUARD 2026-10-12: raw /dev/mem MMIO reads hard-froze this laptop at 16:55, 17:37, 17:46
# (zero kernel trace => hardware lockup). Keep off until crash capture (netconsole) is in place.
[ "${ALLOW_DEVMEM:-}" = "1" ] || { echo "REFUSING: raw /dev/mem probes freeze this laptop. Override: ALLOW_DEVMEM=1 $0" >&2; exit 1; }
# First-contact round 2 for GXFP5120: verified pad pulses + IRQ-aware probes.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE=/dev/spidev0.0
CONTACT="$HERE/spi-contact2"
HOLD_DIR=/tmp/fps-holds2
rm -rf "$HOLD_DIR"; mkdir -p "$HOLD_DIR"

padcfg () {
python3 - <<'EOF'
import struct
def u32(a):
    with open('/dev/mem','rb',buffering=0) as f:
        f.seek(a); return struct.unpack('<I', f.read(4))[0]
for pad in (15,16,17,18):
    dw0 = u32(0xFD6E0700 + pad*16)
    tx = dw0 & 1; rx = (dw0 >> 1) & 1; pm = (dw0 >> 10) & 7
    print("  pad %d: DW0=%08X  TXSTATE=%d RXSTATE=%d PMODE=%d" % (pad, dw0, tx, rx, pm))
EOF
}

hold () {  # line value
    local l=$1 v=$2 pid
    if [ -f "$HOLD_DIR/$l.pid" ]; then kill "$(cat "$HOLD_DIR/$l.pid")" 2>/dev/null; sleep 0.15; fi
    gpioset -c gpiochip0 "$l=$v" 2>"$HOLD_DIR/$l.err" & pid=$!
    sleep 0.25
    [ -s "$HOLD_DIR/$l.err" ] && echo "  gpioset $l=$v stderr: $(cat "$HOLD_DIR/$l.err")"
    kill -0 "$pid" 2>/dev/null && echo "$pid" > "$HOLD_DIR/$l.pid"
    return 0
}

release_all () {
    for f in "$HOLD_DIR"/*.pid; do
        [ -e "$f" ] && kill "$(cat "$f")" 2>/dev/null
    done
    rm -f "$HOLD_DIR"/*.pid "$HOLD_DIR"/*.err
}

echo "==== PADCFG baseline ===="
padcfg
echo
echo "==== gpioset foreground sanity ===="
echo "-- gpioset 15=0:"; gpioset -c gpiochip0 -t 0 15=0 && echo "  rc=0" || echo "  rc=$?"
sleep 0.2; padcfg | head -1
echo "-- restore:"; gpioset -c gpiochip0 -t 0 15=1 || true
sleep 0.2; padcfg | head -1
echo

pulse_and_probe () {  # label  lines...
    local label=$1; shift
    echo "==== $label ===="
    for l in "$@"; do hold "$l" 1; done
    sleep 0.15
    rm -f /tmp/pw.log
    timeout 3 gpiomon -c gpiochip0 -n 60 17 > /tmp/pw.log 2>&1 &
    local gw=$!
    for l in "$@"; do hold "$l" 0; done
    sleep 0.8
    kill "$gw" 2>/dev/null; sleep 0.2
    local ev; ev=$(grep -c . /tmp/pw.log 2>/dev/null || echo 0)
    echo "-- IRQ reaction edges during pulse: $ev"
    [ "$ev" != "0" ] && head -8 /tmp/pw.log
    echo "-- padcfg while driven:"; padcfg | grep -E "pad (15|16):"
    "$CONTACT" "$NODE" 1000000
    local rc=$?
    if [ $rc -eq 0 ]; then echo ">>> CONTACT: $label"; return 0; fi
    for l in "$@"; do hold "$l" 1; done
    sleep 0.3
    return 3
}

pulse_and_probe "1. pad 15 fresh 1->0" 15 && { echo "state left: pad15 held LOW"; exit 0; }
pulse_and_probe "2. pad 16 fresh 1->0" 16 && { echo "state left: pad16 held LOW"; exit 0; }
pulse_and_probe "3. pads 15+16 fresh 1->0" 15 16 && { echo "state left: 15+16 held LOW"; exit 0; }

echo "==== 4. pad15 LOW held 2s, then probe ===="
hold 15 1; sleep 0.2; hold 15 0; sleep 2.0
"$CONTACT" "$NODE" 1000000 && { echo "state left: pad15 held LOW"; exit 0; }

echo
echo "-- no contact; restoring (15=1, 16=1)"
hold 15 1; hold 16 1; sleep 0.3
echo "-- final padcfg:"; padcfg
release_all
exit 3
