#!/bin/bash
set -e

GRUB_FILE="/etc/default/grub"

# Already using eth0: nothing to do.
if ip link show eth0 >/dev/null 2>&1; then
    exit 0
fi

# Find the interface used for the default IPv4 route.
CURRENT_IF=$(ip -4 route show default | awk '{print $5; exit}')

if [ -z "$CURRENT_IF" ]; then
    echo "WARNING: Could not determine the active Ethernet interface."
    exit 0
fi

# Only handle predictable Ethernet interface names.
if [[ "$CURRENT_IF" != enp* &&
      "$CURRENT_IF" != ens* &&
      "$CURRENT_IF" != eno* ]]; then
    echo "WARNING: Ethernet interface '$CURRENT_IF' was not recognized."
    exit 0
fi

# If GRUB is already configured, a reboot is pending.
if grep -q 'net.ifnames=0' "$GRUB_FILE"; then
    echo
    echo "Ethernet interface configuration has already been changed."
    echo "Please reboot the VM to activate eth0."
    echo
    exit 0
fi

echo
echo "Configuring Ethernet interface '$CURRENT_IF' as eth0..."

# Backup GRUB configuration.
cp "$GRUB_FILE" "${GRUB_FILE}.bak"

# Disable predictable network interface naming.
sed -i \
    's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="net.ifnames=0 biosdevname=0 /' \
    "$GRUB_FILE"

update-grub

echo
echo "Ethernet interface configuration updated successfully."
echo
echo "IMPORTANT: Reboot the VM before continuing:"
echo
echo "    sudo reboot"
echo
