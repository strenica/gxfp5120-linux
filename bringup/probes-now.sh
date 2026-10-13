#!/bin/bash
# One-shot speed probe (no persistence): 10 MHz vs 1 MHz, pads high vs low.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE=/dev/spidev0.0
C="$HERE/spi-contact2"
HOLD=/tmp/fps-holds3
rm -rf "$HOLD"; mkdir -p "$HOLD"

hold () {
    local l=$1 v=$2
    [ -f "$HOLD/$l.pid" ] && { kill "$(cat "$HOLD/$l.pid")" 2>/dev/null; sleep 0.15; }
    gpioset -c gpiochip0 "$l=$v" 2>/dev/null & echo $! > "$HOLD/$l.pid"
    sleep 0.25
}

echo "==== A. pads high (BIOS state), 10 MHz ===="
"$C" "$NODE" 10000000
echo "rc=$?"
echo
echo "==== B. pads 15+16 LOW, 10 MHz ===="
hold 15 0; hold 16 0; sleep 0.7
"$C" "$NODE" 10000000
RC=$?
echo "rc=$RC"
if [ $RC -ne 0 ]; then
    echo "==== C. pads 15+16 LOW, 1 MHz (recheck) ===="
    "$C" "$NODE" 1000000
    echo "rc=$?"
fi
echo
echo "-- restoring pads high"
hold 15 1; hold 16 1
for f in "$HOLD"/*.pid; do kill "$(cat "$f")" 2>/dev/null; done
exit 0
