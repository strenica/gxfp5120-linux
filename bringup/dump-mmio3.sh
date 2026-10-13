#!/bin/bash
set -u
OUT="$(cd "$(dirname "$0")/.." && pwd)/state-compare"
mkdir -p "$OUT"
echo "== real iomem addresses (root view) =="
grep -B1 -A3 "1e\.3" /proc/iomem | head -12
echo
echo "== resource0 direct (driver bound) =="
dd if=/sys/bus/pci/devices/0000:00:1e.3/resource0 of=/tmp/res0.bin bs=512 count=1 status=none; echo "dd rc=$?"
ls -la /tmp/res0.bin 2>/dev/null
if [ ! -s /tmp/res0.bin ]; then
  DRV=$(basename "$(readlink /sys/bus/platform/devices/pxa2xx-spi.3/driver)" 2>/dev/null)
  echo "== unbinding platform driver '$DRV' =="
  echo pxa2xx-spi.3 > "/sys/bus/platform/drivers/$DRV/unbind" 2>&1 || echo "unbind failed"
  sleep 0.5
  dd if=/sys/bus/pci/devices/0000:00:1e.3/resource0 of=/tmp/res0.bin bs=512 count=1 status=none; echo "dd rc=$?"
  ls -la /tmp/res0.bin 2>/dev/null
  echo "== rebinding =="
  echo pxa2xx-spi.3 > "/sys/bus/platform/drivers/$DRV/bind" 2>&1 || echo "rebind failed"
  sleep 0.5
  # re-bind spidev to the sensor (children were recreated)
  SPI=spi-GXFP5120:00
  if [ -d "/sys/bus/spi/devices/$SPI" ] && [ ! -e "/sys/bus/spi/devices/$SPI/driver" ]; then
    modprobe spidev 2>/dev/null
    echo spidev > "/sys/bus/spi/devices/$SPI/driver_override"
    echo "$SPI" > /sys/bus/spi/drivers/spidev/bind 2>/dev/null && echo "spidev rebound"
  fi
fi
if [ -s /tmp/res0.bin ]; then
  cp /tmp/res0.bin "$OUT/linux-lpss-spi1.bin"
  hexdump -C /tmp/res0.bin > "$OUT/linux-lpss-spi1.txt"
  chmod 644 "$OUT"/linux-lpss-spi1.*
  echo "SAVED to $OUT/linux-lpss-spi1.bin"
  cat "$OUT/linux-lpss-spi1.txt" | head -34
else
  echo "STILL FAILED to read resource0"
fi
