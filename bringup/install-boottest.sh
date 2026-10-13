#!/bin/bash
# Install the boot-state test + run a quick current-boot speed check. Root.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

install -m0755 "$HERE/spi-contact2" /usr/local/bin/spi-contact2
install -m0755 "$HERE/fps-boot-test.sh" /usr/local/bin/fps-boot-test.sh

cat > /etc/systemd/system/fps-boot-test.service <<'EOF'
[Unit]
Description=Fingerprint sensor boot-state bring-up test (GXFP5120)
After=sysinit.target
Wants=sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fps-boot-test.sh
TimeoutStartSec=120

[Install]
WantedBy=sysinit.target
EOF

systemctl daemon-reload
systemctl enable fps-boot-test.service
echo "boot test installed (unit: fps-boot-test.service)"

echo
echo "== current-boot probe at 10 MHz (CS_HIGH) =="
/usr/local/bin/spi-contact2 /dev/spidev0.0 10000000
echo "rc=$?"
echo "== current-boot probe at 1 MHz (CS_HIGH) =="
/usr/local/bin/spi-contact2 /dev/spidev0.0 1000000
echo "rc=$?"

echo
echo "To run the boot test: reboot. Logs:"
echo "  /var/log/fps-boot-test.log   /var/log/fps-boot-irq.log"
echo "To remove afterwards:"
echo "  systemctl disable fps-boot-test.service && rm /etc/systemd/system/fps-boot-test.service /usr/local/bin/fps-boot-test.sh /usr/local/bin/spi-contact2"
