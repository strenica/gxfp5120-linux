#!/bin/bash
# First-contact attempt for GXFP5120:
#   CS_HIGH probe + reset-line candidates pads 15/16 (MateBook 13 recipe:
#   reset HIGH = held in reset, LOW = running). Watches pad 17 (IRQ) throughout.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE=/dev/spidev0.0
CONTACT="$HERE/spi-contact"
HOLD_DIR=/tmp/fps-holds
rm -rf "$HOLD_DIR"; mkdir -p "$HOLD_DIR"

echo "==== gpioinfo, offsets 14-25 ===="
gpioinfo -c gpiochip0 2>/dev/null | sed -n '/line *14:/,/line *26:/p'
echo

setline () {  # line value -- drive and keep held until release_all
    local l=$1 v=$2 pid cur
    if [ -f "$HOLD_DIR/$l.pid" ]; then kill "$(cat "$HOLD_DIR/$l.pid")" 2>/dev/null; sleep 0.2; fi
    gpioset -c gpiochip0 "$l=$v" >/dev/null 2>&1 & pid=$!
    sleep 0.3
    cur=$(gpioget -c gpiochip0 "$l" 2>&1)
    if [ "$cur" != "$v" ]; then
        gpioset -c gpiochip0 -t 0 "$l=$v" >/dev/null 2>&1
        sleep 0.2
        cur=$(gpioget -c gpiochip0 "$l" 2>&1)
    fi
    if kill -0 "$pid" 2>/dev/null; then echo "$pid" > "$HOLD_DIR/$l.pid"; fi
    echo "  line $l -> $cur"
}

release_all () {
    for f in "$HOLD_DIR"/*.pid; do
        [ -e "$f" ] && kill "$(cat "$f")" 2>/dev/null
    done
    rm -f "$HOLD_DIR"/*.pid
}

IRQ_PID=""
watch_irq () {
    rm -f /tmp/irqwatch.log
    timeout 90 gpiomon -c gpiochip0 -n 100 17 > /tmp/irqwatch.log 2>&1 &
    IRQ_PID=$!
}
report_irq () {
    [ -n "$IRQ_PID" ] && kill "$IRQ_PID" 2>/dev/null
    sleep 0.3
    echo "-- IRQ pad (offset 17) events:"
    cat /tmp/irqwatch.log 2>/dev/null | head -40
    echo
}

try_contact () {  # label
    echo "-- probe: $1"
    "$CONTACT" "$NODE" 1000000
    local rc=$?
    [ $rc -eq 0 ] && return 0
    return 1
}

watch_irq

echo "==== 0. baseline (CS_HIGH probe, pads untouched) ===="
if try_contact "baseline"; then echo ">>> CONTACT AT BASELINE"; report_irq; exit 0; fi

echo
echo "==== 1. pad 15 LOW ===="
setline 15 0; sleep 0.7
if try_contact "pad15 LOW"; then echo ">>> CONTACT (15 LOW)"; report_irq; exit 0; fi
setline 15 1

echo
echo "==== 2. pad 16 LOW ===="
setline 16 0; sleep 0.7
if try_contact "pad16 LOW"; then echo ">>> CONTACT (16 LOW)"; report_irq; exit 0; fi
setline 16 1

echo
echo "==== 3. pads 15+16 LOW ===="
setline 15 0; setline 16 0; sleep 0.7
if try_contact "15+16 LOW"; then echo ">>> CONTACT (15+16 LOW)"; report_irq; exit 0; fi

echo
echo "==== 4. pad 15 LOW, long settle ===="
setline 15 1; setline 16 1; sleep 0.5
setline 15 0; sleep 2.0
if try_contact "15 LOW, 2s settle"; then echo ">>> CONTACT (15 LOW slow)"; report_irq; exit 0; fi

echo
echo "-- no contact; restoring pads to found state"
setline 15 1; setline 16 1
report_irq
release_all
exit 3
