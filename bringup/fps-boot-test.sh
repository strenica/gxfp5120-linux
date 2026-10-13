#!/bin/bash
# FPS boot-state bring-up test v2 (installed to /usr/local/bin/fps-boot-test.sh).
# Passive-first: probes the sensor WITHOUT touching any pad first, so a
# post-Windows warm-reboot state can be caught intact; only then runs the
# pad experiments. Logs: /var/log/fps-boot-test.log, /var/log/fps-boot-irq.log
exec > /var/log/fps-boot-test.log 2>&1
echo "=== fps-boot-test start $(date '+%T') ==="

SPI=spi-GXFP5120:00
modprobe spidev bufsiz=65536 2>/dev/null

if [ -d "/sys/bus/spi/devices/$SPI" ] && [ ! -e "/sys/bus/spi/devices/$SPI/driver" ]; then
    echo spidev > "/sys/bus/spi/devices/$SPI/driver_override"
    echo "$SPI" > /sys/bus/spi/drivers/spidev/bind 2>/dev/null
fi
ls -la /dev/spidev* 2>&1

# IRQ watch over the power-on window (runs during the passive phase too;
# the probe tool falls back to ungated reads while this holds the line)
timeout 30 gpiomon -c gpiochip0 -n 500 17 > /var/log/fps-boot-irq.log 2>&1 &
GM=$!

sleep 2
echo "== passive A: CS_HIGH 1 MHz, pads untouched ($(date '+%T')) =="
/usr/local/bin/spi-contact2 /dev/spidev0.0 1000000
echo "passiveA rc=$?"
echo "== passive B: normal CS 1 MHz, pads untouched =="
/usr/local/bin/spi-contact2 /dev/spidev0.0 1000000 nocs
echo "passiveB rc=$?"

sleep 1
kill $GM 2>/dev/null
echo "-- IRQ events during passive window:"
sed -n '1,20p' /var/log/fps-boot-irq.log

echo "== phase 1: pads 15/16 LOW, CS_HIGH 1 MHz =="
for l in 15 16; do gpioset -c gpiochip0 -t 0 "$l=0" 2>/dev/null; done
sleep 0.7
/usr/local/bin/spi-contact2 /dev/spidev0.0 1000000
echo "phase1 rc=$?"

echo "== phase 2: 10 MHz =="
/usr/local/bin/spi-contact2 /dev/spidev0.0 10000000
echo "phase2 rc=$?"

echo "== phase 3: fresh reset pulse (high->low) then 1 MHz =="
for l in 15 16; do gpioset -c gpiochip0 -t 0 "$l=1" 2>/dev/null; done
sleep 0.1
for l in 15 16; do gpioset -c gpiochip0 -t 0 "$l=0" 2>/dev/null; done
sleep 0.7
/usr/local/bin/spi-contact2 /dev/spidev0.0 1000000
echo "phase3 rc=$?"

echo "-- restore pads to BIOS state (high)"
for l in 15 16; do gpioset -c gpiochip0 -t 0 "$l=1" 2>/dev/null; done
echo "=== done $(date '+%T') ==="
