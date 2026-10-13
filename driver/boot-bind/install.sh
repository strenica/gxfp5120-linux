#!/bin/sh
# Install boot-time persistence for the GXFP5120 fingerprint sensor:
#   /usr/local/sbin/gxfp5120-spidev-bind        (bind helper; idempotent)
#   /etc/udev/rules.d/70-gxfp5120-spidev.rules  (run it on every SPI add)
#
# Without this, spi-GXFP5120:00 exists at boot but nothing binds spidev to it,
# so /dev/spidev0.0 never appears and fprintd finds no device.
#
# Run as root; idempotent. Uninstall: rm the two files above and reload udev.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (sudo $0)" >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -m 0755 "$here/gxfp5120-spidev-bind.sh" /usr/local/sbin/gxfp5120-spidev-bind
install -m 0644 "$here/70-gxfp5120-spidev.rules" /etc/udev/rules.d/70-gxfp5120-spidev.rules

udevadm control --reload
udevadm trigger --subsystem-match=spi --action=add
/usr/local/sbin/gxfp5120-spidev-bind        # also covers a slow udev trigger

if [ -e /dev/spidev0.0 ]; then
    ls -la /dev/spidev0.0
    echo "OK — sensor bound to spidev; also happens automatically at every boot."
else
    echo "error: /dev/spidev0.0 did not appear — debug with:" >&2
    echo "  udevadm test /sys/bus/spi/devices/spi-GXFP5120:00" >&2
    exit 1
fi
