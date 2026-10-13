#!/bin/bash
# Full diagnostic pass for the GXFP5120 SPI bring-up. Run as root.
set -u
SPI=spi-GXFP5120:00
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "== 1. module state =="
lsmod | grep -E 'spidev|pxa2xx' || echo "(no spi modules?)"
echo "bufsiz before: $(cat /sys/module/spidev/parameters/bufsiz 2>/dev/null || echo none)"

echo
echo "== 2. clean reload of spidev with bufsiz=65536 =="
if [ -e "/sys/bus/spi/devices/$SPI/driver" ]; then
    echo "$SPI" > "/sys/bus/spi/drivers/spidev/unbind" 2>/dev/null || true
fi
rmmod spidev 2>/dev/null || true
modprobe -v spidev bufsiz=65536 2>&1
echo "bufsiz after: $(cat /sys/module/spidev/parameters/bufsiz)"
echo 65536 > /sys/module/spidev/parameters/bufsiz 2>/dev/null || true
echo "bufsiz forced: $(cat /sys/module/spidev/parameters/bufsiz)"

echo
echo "== 3. rebind =="
echo spidev > "/sys/bus/spi/devices/$SPI/driver_override"
echo "$SPI" > /sys/bus/spi/drivers/spidev/bind && echo "bound"
ls -la /dev/spidev*

echo
echo "== 4. per-slave SPI statistics =="
for f in "/sys/bus/spi/devices/$SPI"/statistics/*; do
    [ -e "$f" ] && echo "$(basename "$f"): $(cat "$f")"
done

echo
echo "== 5. dmesg (spi/gxfp lines, last 30) =="
dmesg | grep -iE 'spi|spba|pxa|gxfp' | tail -30

echo
echo "== 6. GPIO controller state =="
mountpoint -q /sys/kernel/debug || mount -t debugfs none /sys/kernel/debug
head -100 /sys/kernel/debug/gpio 2>/dev/null

echo
echo "== 7. SPI interrupts =="
grep -iE 'spi|pxa' /proc/interrupts || echo "(none)"

echo
echo "== 8. probe =="
"$HERE/spi-probe" /dev/spidev0.0
RC=$?

echo
echo "== 9. dmesg after probe (last 10) =="
dmesg | tail -10
exit $RC
