#!/bin/bash
# Bring-up: bind spidev to the GXFP5120 sensor and run the firmware-version test.
# Must run as root (modprobe + sysfs writes + spidev node access).
# NOTE: boot-time persistence now lives in ../driver/boot-bind/ (udev rule +
# /usr/local/sbin/gxfp5120-spidev-bind); this script remains for manual bring-up.
set -e

SPI_DEV=spi-GXFP5120:00
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/spi-fwtest"

echo "== 1. spidev module with enlarged buffer =="
modprobe -r spidev 2>/dev/null || true
modprobe spidev bufsiz=65536
echo "bufsiz = $(cat /sys/module/spidev/parameters/bufsiz)"

echo
echo "== 2. bind spidev to $SPI_DEV =="
if [ ! -d "/sys/bus/spi/devices/$SPI_DEV" ]; then
    echo "ERROR: $SPI_DEV not present" >&2
    exit 1
fi
echo spidev > "/sys/bus/spi/devices/$SPI_DEV/driver_override"
if [ -e "/sys/bus/spi/devices/$SPI_DEV/driver" ]; then
    echo "already bound to $(basename "$(readlink -f "/sys/bus/spi/devices/$SPI_DEV/driver")")"
else
    echo "$SPI_DEV" > /sys/bus/spi/drivers/spidev/bind
    echo "bound to $(basename "$(readlink -f "/sys/bus/spi/devices/$SPI_DEV/driver")")"
fi

NODE_NAME=$(ls "/sys/bus/spi/devices/$SPI_DEV/spidev/" 2>/dev/null | head -1)
if [ -z "$NODE_NAME" ]; then
    echo "ERROR: no spidev node appeared" >&2
    exit 1
fi
NODE="/dev/$NODE_NAME"
echo "node: $NODE"
ls -la "$NODE"

echo
echo "== 3. SPI dialogue test (firmware version read) =="
"$BIN" "$NODE"
RC=$?

echo
echo "== done (exit $RC). Sensor left bound to spidev; to undo: =="
echo "  echo $SPI_DEV | sudo tee /sys/bus/spi/drivers/spidev/unbind"
exit $RC
