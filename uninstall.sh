#!/usr/bin/env bash
# AdaptShield -- Uninstaller
# Cleanly stops and removes AdaptShield from Linux systems.
#
# Usage:
#   sudo ./uninstall.sh [--purge]
#
# Flags:
#   --purge   Delete all quarantined data, telemetry, and configuration.
#             (Default preserves quarantined files in /var/lib/adaptshield/quarantine)
set -euo pipefail

PURGE=false
for arg in "$@"; do
  case "$arg" in
    --purge)
      PURGE=true
      ;;
    --help|-h)
      echo "Usage: sudo ./uninstall.sh [--purge]"
      echo "  --purge  Remove all logs, configuration (/etc/adaptshield), and quarantined files (/var/lib/adaptshield)"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

echo "=================================================================="
echo " AdaptShield Autonomous Defense Agent -- Uninstaller"
echo "=================================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Uninstaller must be run as root (use: sudo ./uninstall.sh)" >&2
  exit 1
fi

# 1. Thaw any frozen cgroups before teardown
echo "== Thawing frozen processes =="
if command -v adaptshield >/dev/null 2>&1; then
  adaptshield release --all 2>/dev/null || true
fi

# Also check cgroup hierarchy directly
if [ -d /sys/fs/cgroup/adaptshield ]; then
  for p in /sys/fs/cgroup/adaptshield/proc_*; do
    if [ -f "$p/cgroup.freeze" ]; then
      echo "0" > "$p/cgroup.freeze" 2>/dev/null || true
    fi
  done
fi

# 2. Stop and disable systemd service
echo "== Stopping and disabling systemd service =="
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop adaptshield.service 2>/dev/null || true
  systemctl disable adaptshield.service 2>/dev/null || true
fi

if [ -f /etc/systemd/system/adaptshield.service ]; then
  rm -f /etc/systemd/system/adaptshield.service
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
  fi
  echo "[*] Removed /etc/systemd/system/adaptshield.service"
fi

# 3. Remove CLI symlinks
echo "== Removing CLI symlinks =="
rm -f /usr/local/bin/adaptshield
rm -f /usr/local/bin/adaptshield-agent

# 4. Remove /opt/adaptshield runtime environment
echo "== Removing /opt/adaptshield runtime environment =="
rm -rf /opt/adaptshield

# 5. Handle Logs
rm -rf /var/log/adaptshield

# 6. Handle Configuration and State (/var/lib/adaptshield)
if [ "$PURGE" = true ]; then
  echo "== Purging configuration and quarantined files (--purge enabled) =="
  rm -rf /etc/adaptshield
  rm -rf /var/lib/adaptshield
  echo "[*] Removed /etc/adaptshield and /var/lib/adaptshield completely."
else
  echo ""
  echo "=================================================================="
  echo " [!] NOTICE: Quarantined files and configuration preserved:"
  echo "     - Configuration: /etc/adaptshield"
  echo "     - Quarantine:    /var/lib/adaptshield/quarantine"
  echo "     - State:         /var/lib/adaptshield"
  echo ""
  echo " To completely delete all retained state and quarantined data, run:"
  echo "     sudo ./uninstall.sh --purge"
  echo "=================================================================="
fi

echo ""
echo "AdaptShield uninstallation finished successfully."
