#!/bin/bash
# Revert the _OSI("Windows 2015") spoof. Run with sudo.
set -e
[ "$(id -u)" -eq 0 ] || { echo "run with: sudo bash $0"; exit 1; }
rm -f /etc/default/grub.d/99-fps-osi.cfg
update-grub
echo "reverted; acpi_osi removed from grub.cfg:"
grep -c acpi_osi /boot/grub/grub.cfg || true
