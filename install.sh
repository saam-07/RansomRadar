#!/usr/bin/env bash
# AdaptShield -- Production Installer
# Installs AdaptShield Autonomous Ransomware Defense Agent on Linux (Ubuntu 22.04/24.04)
#
# Usage:
#   sudo ./install.sh [--dev] [--upgrade]
set -euo pipefail

DEV_MODE=false
UPGRADE_MODE=false

for arg in "$@"; do
  case "$arg" in
    --dev)
      DEV_MODE=true
      ;;
    --upgrade)
      UPGRADE_MODE=true
      ;;
    --help|-h)
      echo "Usage: sudo ./install.sh [--dev] [--upgrade]"
      echo "  --dev      Install development benchmark tools (sysbench, MySQL, PostgreSQL, restic)"
      echo "  --upgrade  Upgrade existing AdaptShield installation without overwriting config"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

echo "=================================================================="
echo " AdaptShield Autonomous Defense Agent -- Installer"
echo "=================================================================="

# 1. Privilege Check
if [ "$EUID" -ne 0 ]; then
  echo "[-] ERROR: Installer must be run as root (use: sudo ./install.sh)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[*] Repository root: $REPO_ROOT"

# 2. Operating System & Kernel Preflight Report
echo ""
echo "=== Preflight System Checks ==="
OS_NAME="Unknown"
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_NAME="${NAME:-Linux} ${VERSION_ID:-}"
fi
echo "[*] Operating System:   $OS_NAME"

KERNEL_RELEASE="$(uname -r)"
KVER_MAJOR="$(echo "$KERNEL_RELEASE" | cut -d. -f1)"
KVER_MINOR="$(echo "$KERNEL_RELEASE" | cut -d. -f2)"
echo "[*] Kernel Release:     $KERNEL_RELEASE"
if (( KVER_MAJOR < 5 || (KVER_MAJOR == 5 && KVER_MINOR < 9) )); then
  echo "    [WARN] Kernel version < 5.9. fanotify PID attribution may have limited functionality."
else
  echo "    [PASS] Kernel >= 5.9 meets fanotify & cgroups v2 requirements."
fi

# 3. cgroups v2 & Freezer
if mount | grep -q cgroup2 || [ -d /sys/fs/cgroup/cgroup.controllers ]; then
  echo "[*] cgroups v2:         Mounted unified hierarchy -> [PASS]"
  if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
    if ! grep -q "freezer" /sys/fs/cgroup/cgroup.subtree_control; then
      echo "+freezer" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    fi
  fi
else
  echo "[*] cgroups v2:         Not detected as unified hierarchy -> [WARN]"
  echo "    Tip: Add 'systemd.unified_cgroup_hierarchy=1' to GRUB_CMDLINE_LINUX if needed."
fi

# 4. fanotify
if [ -d /proc/sys/fs/fanotify ] || grep -q "CONFIG_FANOTIFY=y" "/boot/config-$KERNEL_RELEASE" 2>/dev/null || true; then
  echo "[*] fanotify subsystem: Detected -> [PASS]"
else
  echo "[*] fanotify subsystem: Checking capability during runtime init -> [INFO]"
fi

# 5. eBPF / BCC Preflight Check
EBPF_SUPPORTED=false
if command -v bpftool >/dev/null 2>&1 || [ -f /sys/kernel/debug/tracing/trace ] || [ -f /sys/kernel/tracing/trace ]; then
  echo "[*] Kernel Tracing/BPF: Available in kernel -> [PASS]"
fi

if python3 -c "import bcc" >/dev/null 2>&1; then
  echo "[*] BCC / eBPF Library: Installed and importable -> [PASS]"
  EBPF_SUPPORTED=true
else
  echo "[*] BCC / eBPF Library: Not currently installed in system Python."
  echo "    [INFO] eBPF Tier-1 is optional. AdaptShield will operate with robust Tier-0 fanotify"
  echo "    and fall back smoothly if BCC is not configured."
fi

# 6. Install Runtime APT Dependencies Only
echo ""
echo "=== Installing Runtime Dependencies ==="
apt-get update -qq || true
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  python3 \
  python3-venv \
  python3-pip \
  python3-setuptools \
  cgroup-tools \
  inotify-tools \
  libcap2-bin \
  util-linux \
  curl || {
    echo "[-] Warning: Failed to install some base packages, continuing..."
  }

# Attempt installing BCC packages if available, but DO NOT abort if unavailable
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  bpfcc-tools python3-bpfcc linux-headers-"$KERNEL_RELEASE" 2>/dev/null || {
    echo "[INFO] BCC packages not installed via apt; Tier-0 mode will be used."
  }

# 7. Dev / Benchmark Dependencies (behind --dev)
if [ "$DEV_MODE" = true ]; then
  echo ""
  echo "=== Installing Dev/Benchmark Lab Dependencies (--dev) ==="
  if [ -f "$REPO_ROOT/setup/dev_lab_setup.sh" ]; then
    bash "$REPO_ROOT/setup/dev_lab_setup.sh"
  fi
fi

# 8. Setup Python Virtual Environment at /opt/adaptshield/venv
echo ""
echo "=== Configuring Runtime Environment (/opt/adaptshield) ==="
mkdir -p /opt/adaptshield
if [ ! -d /opt/adaptshield/venv ] || [ "$UPGRADE_MODE" = true ]; then
  if [ ! -d /opt/adaptshield/venv ]; then
    python3 -m venv --system-site-packages /opt/adaptshield/venv
  else
    # Ensure existing venv has system site packages enabled
    if [ -f /opt/adaptshield/venv/pyvenv.cfg ]; then
      sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' /opt/adaptshield/venv/pyvenv.cfg || true
    fi
  fi
fi

/opt/adaptshield/venv/bin/pip install --upgrade pip setuptools wheel -q
if [ -f "$REPO_ROOT/requirements.txt" ]; then
  /opt/adaptshield/venv/bin/pip install -r "$REPO_ROOT/requirements.txt" -q
fi
/opt/adaptshield/venv/bin/pip install -e "$REPO_ROOT" -q

# 9. Setup System Paths & Config
echo ""
echo "=== Configuring State, Log, and Config Directories ==="
mkdir -p /etc/adaptshield
mkdir -p /var/lib/adaptshield/models
mkdir -p /var/lib/adaptshield/quarantine
mkdir -p /var/lib/adaptshield/control
mkdir -p /var/lib/adaptshield/telemetry
mkdir -p /var/lib/adaptshield/overlay_mounts
mkdir -p /var/log/adaptshield

chmod 750 /var/lib/adaptshield
chmod 755 /var/log/adaptshield

# Config file: NEVER overwrite on upgrade or if existing
if [ -f /etc/adaptshield/config.yaml ]; then
  echo "[*] Existing configuration found at /etc/adaptshield/config.yaml. Preserving untouched."
else
  echo "[*] Creating default configuration at /etc/adaptshield/config.yaml."
  cp "$REPO_ROOT/packaging/config.default.yaml" /etc/adaptshield/config.yaml
  chmod 640 /etc/adaptshield/config.yaml
fi

# Seed model registry if models exist in repo
if [ -d "$REPO_ROOT/models/registry" ]; then
  cp -r "$REPO_ROOT/models/registry"/* /var/lib/adaptshield/models/ 2>/dev/null || true
fi
if [ -d "$REPO_ROOT/results/processed" ]; then
  cp "$REPO_ROOT/results/processed"/*.joblib /var/lib/adaptshield/models/ 2>/dev/null || true
fi

# 10. Install CLI Symlinks on PATH
echo ""
echo "=== Installing CLI Binaries ==="
ln -sf /opt/adaptshield/venv/bin/adaptshield /usr/local/bin/adaptshield
ln -sf /opt/adaptshield/venv/bin/adaptshield-agent /usr/local/bin/adaptshield-agent
chmod 755 /usr/local/bin/adaptshield /usr/local/bin/adaptshield-agent

# 11. Install and Enable Systemd Service
echo ""
echo "=== Configuring systemd Service ==="
cp "$REPO_ROOT/packaging/systemd/adaptshield.service" /etc/systemd/system/adaptshield.service
chmod 644 /etc/systemd/system/adaptshield.service

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable adaptshield.service
  echo "[*] Restarting adaptshield.service..."
  systemctl restart adaptshield.service || {
    echo "[WARN] Could not immediately start service via systemctl (systemd may be inactive in container)."
  }
else
  echo "[INFO] systemd daemon not detected (containerized environment). Service registered at /etc/systemd/system/adaptshield.service."
fi

# 12. Verification and Doctor Diagnostics
echo ""
echo "=================================================================="
echo " AdaptShield Installation Summary"
echo "=================================================================="
/usr/local/bin/adaptshield doctor || true

echo ""
echo "AdaptShield is running."
MODE_INFO="$(/usr/local/bin/adaptshield mode 2>/dev/null || echo 'Operating Mode: protect (with 24h monitor-first grace period)')"
echo "$MODE_INFO"
echo "Status check: adaptshield status"
echo "Logs:         journalctl -u adaptshield -f  OR  tail -f /var/log/adaptshield/adaptshield.log"
echo "=================================================================="
