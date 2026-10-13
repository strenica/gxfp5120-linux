#!/bin/bash
# Make Linux answer TRUE to _OSI("Windows 2015") so the firmware/EC treats
# this boot like Windows 10 (OSYS = 0x07DF). Reversible: disable-osi.sh.
# Run with sudo.
set -e
[ "$(id -u)" -eq 0 ] || { echo "run with: sudo bash $0"; exit 1; }

mkdir -p /etc/default/grub.d
cat > /etc/default/grub.d/99-fps-osi.cfg <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="${GRUB_CMDLINE_LINUX_DEFAULT} acpi_osi=\"Windows 2015\""
EOF

update-grub

echo
echo "== check: acpi_osi in generated grub.cfg =="
if grep -m2 -o 'acpi_osi="Windows 2015"' /boot/grub/grub.cfg; then
    echo "OK - will activate on next boot"
else
    echo "!! NOT FOUND - inspect /boot/grub/grub.cfg manually"
    grep -m3 acpi_osi /boot/grub/grub.cfg || true
fi
echo
echo "Reboot to test. To revert: sudo bash disable-osi.sh"
