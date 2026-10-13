#!/bin/sh
# gxfp5120-spidev-bind — bind the spidev driver to the Goodix GXFP5120
# fingerprint sensor (ACPI-enumerated on Intel GSPI1, spi-GXFP5120:00).
#
# The SPI device exists on the bus right after boot, but spidev only
# auto-binds to ACPI IDs SPT0001-0003 — not GXFP5120. Without this bind,
# /dev/spidev0.0 never appears and fprintd's udev discovery (spi_acpi_id
# "GXFP5120") finds no device.
#
# Idempotent. Installed at /usr/local/sbin/gxfp5120-spidev-bind and invoked
# by udev rule 70-gxfp5120-spidev.rules on every SPI "add" event.
set -eu

found=0
for dev in /sys/bus/spi/devices/*; do
    [ -e "$dev/modalias" ] || continue
    case "$(cat "$dev/modalias")" in
        acpi:GXFP5120*) ;;
        *) continue ;;
    esac
    found=1
    if [ -d "$dev/spidev" ]; then
        continue                      # already bound to spidev
    fi
    echo spidev > "$dev/driver_override"
    echo "${dev##*/}" > /sys/bus/spi/drivers/spidev/bind
done

if [ "$found" -eq 0 ]; then
    echo "gxfp5120-spidev-bind: no GXFP5120 SPI device found" >&2
    exit 1
fi
