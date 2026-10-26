#!/usr/bin/env bash
# AdaptShield -- Step 1/2: install all OS + Python dependencies.
# Target: Ubuntu 22.04 or 24.04, kernel >= 5.9 (needed for FAN_REPORT_DFID_NAME/PID
# and for a stable cgroups v2 unified hierarchy with the freezer controller).
set -euo pipefail

echo "=============================================="
echo " AdaptShield Environment & Dependencies Setup"
echo "=============================================="

echo "== Checking kernel version =="
uname -r
KVER_MAJOR=$(uname -r | cut -d. -f1)
KVER_MINOR=$(uname -r | cut -d. -f2)
if (( KVER_MAJOR < 5 || (KVER_MAJOR == 5 && KVER_MINOR < 9) )); then
  echo "WARNING: kernel < 5.9. fanotify PID reporting and some eBPF features may be unavailable."
fi

# Resolve the repo root relative to THIS script's location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
REAL_USER="${SUDO_USER:-$USER}"
echo "== Detected repo root: $REPO_ROOT (target user: $REAL_USER) =="

echo "== Installing APT packages =="
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) \
  bpfcc-tools python3-bpfcc linux-tools-common linux-tools-$(uname -r) \
  cgroup-tools libcgroup-dev \
  inotify-tools \
  btrfs-progs xfsprogs e2fsprogs util-linux \
  rsync tar gzip bzip2 \
  restic \
  sysbench mysql-server postgresql \
  python3 python3-pip python3-venv python3-setuptools \
  bpftrace

echo "== Checking cgroups v2 hierarchy =="
if mount | grep -q cgroup2; then
  echo "cgroup2 unified hierarchy is mounted."
else
  echo "cgroup2 NOT mounted as unified hierarchy. On modern Ubuntu this is default;"
  echo "if not, add GRUB_CMDLINE_LINUX=\"systemd.unified_cgroup_hierarchy=1\" to /etc/default/grub, update-grub and reboot."
fi

# Enable freezer controller in cgroup root if supported
if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
  if grep -qw "freezer" /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
    if ! grep -q "freezer" /sys/fs/cgroup/cgroup.subtree_control; then
      echo "+freezer" | sudo tee /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
    fi
  fi
  echo "Root subtree_control: $(cat /sys/fs/cgroup/cgroup.subtree_control || true)"
fi

echo "== Creating Python virtual environment with --system-site-packages =="
# Using --system-site-packages allows python3-bpfcc (BCC eBPF bindings from apt) to be imported inside venv
if [ ! -d "$REPO_ROOT/.venv" ]; then
  python3 -m venv --system-site-packages "$REPO_ROOT/.venv"
else
  # Ensure existing venv has system site packages enabled
  if [ -f "$REPO_ROOT/.venv/pyvenv.cfg" ]; then
    sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' "$REPO_ROOT/.venv/pyvenv.cfg"
  fi
fi

# Ensure ownership belongs to non-root user
sudo chown -R "$REAL_USER":"$REAL_USER" "$REPO_ROOT/.venv"

echo "== Installing Python dependencies =="
"$REPO_ROOT/.venv/bin/pip" install --upgrade pip setuptools wheel
"$REPO_ROOT/.venv/bin/pip" install -r "$REPO_ROOT/requirements.txt"

echo "== Installing adaptshield package in editable mode =="
"$REPO_ROOT/.venv/bin/pip" install -e "$REPO_ROOT"

# Ensure all repository files belong to the non-root user
sudo chown -R "$REAL_USER":"$REAL_USER" "$REPO_ROOT"

echo "== Verifying BCC (eBPF) bindings inside venv =="
"$REPO_ROOT/.venv/bin/python3" -c "from bcc import BPF; print('BCC OK')"

echo "=============================================="
echo " Setup complete!"
echo " Activate your venv in any shell with:"
echo "   source $REPO_ROOT/.venv/bin/activate"
echo "=============================================="
