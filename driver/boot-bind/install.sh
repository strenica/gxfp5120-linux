#!/bin/sh
# Install system integration for the GXFP5120 fingerprint sensor:
#   /usr/local/sbin/gxfp5120-spidev-bind        (bind helper; idempotent)
#   /etc/udev/rules.d/70-gxfp5120-spidev.rules  (run it on every SPI add)
#   /etc/gxfp5120/cc90.hex                      (sensor config frame; required at open)
#   /etc/systemd/system/fprintd.service.d/gxfp5120.conf (fprintd sandbox: device access)
#
# Without the udev rule, spi-GXFP5120:00 exists at boot but nothing binds spidev
# to it, so /dev/spidev0.0 never appears and fprintd finds no device.
#
# Run as root; idempotent. Uninstall: delete the four files above, then
# `udevadm control --reload` + `systemctl daemon-reload`.
set -eu

[ "$(id -u)" -eq 0 ] || { echo "error: run as root (sudo $0)" >&2; exit 1; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -m 0755 "$here/gxfp5120-spidev-bind.sh" /usr/local/sbin/gxfp5120-spidev-bind
install -m 0644 "$here/70-gxfp5120-spidev.rules" /etc/udev/rules.d/70-gxfp5120-spidev.rules

# runtime files: sensor config frame + state dir + fprintd sandbox drop-in
install -D -m 0644 "$here/../gxfp5120/cc90.hex" /etc/gxfp5120/cc90.hex
install -d -m 0755 /var/lib/gxfp5120        # TLS session cache
install -D -m 0644 "$here/fprintd-gxfp5120.conf" \
    /etc/systemd/system/fprintd.service.d/gxfp5120.conf
systemctl daemon-reload

udevadm control --reload
udevadm trigger --subsystem-match=spi --action=add
/usr/local/sbin/gxfp5120-spidev-bind        # also covers a slow udev trigger

if [ -e /dev/spidev0.0 ]; then
    ls -la /dev/spidev0.0
    echo "OK — sensor bound to spidev (automatic at every boot); cc90.hex + fprintd drop-in installed."
else
    echo "error: /dev/spidev0.0 did not appear — debug with:" >&2
    echo "  udevadm test /sys/bus/spi/devices/spi-GXFP5120:00" >&2
    exit 1
fi
