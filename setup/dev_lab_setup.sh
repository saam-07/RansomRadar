#!/usr/bin/env bash
# AdaptShield -- Development & Benchmark Lab Setup
# Installs heavy benchmark dependencies (sysbench, MySQL, PostgreSQL, restic)
# and initializes loopback test filesystems.
#
# Usage:
#   sudo ./setup/dev_lab_setup.sh [--with-loopback]
set -euo pipefail

echo "=========================================================="
echo " AdaptShield Development & Benchmark Lab Setup"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run this script with root privileges (sudo)." >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "== Installing Lab & Benchmark Packages =="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  sysbench \
  mysql-server \
  postgresql \
  restic \
  btrfs-progs \
  xfsprogs \
  rsync

echo "== Configuring MySQL for sysbench OLTP benchmarks =="
if [ -f "$SCRIPT_DIR/create_sysbench_db.sh" ]; then
  bash "$SCRIPT_DIR/create_sysbench_db.sh" || {
    echo "Warning: create_sysbench_db.sh encountered a warning; continuing..."
  }
fi

if [[ "${1:-}" == "--with-loopback" ]]; then
  echo "== Setting up loopback test filesystems (ext4, btrfs, xfs) =="
  if [ -f "$SCRIPT_DIR/make_test_filesystems.sh" ]; then
    bash "$SCRIPT_DIR/make_test_filesystems.sh"
  fi
else
  echo "Tip: Run '$SCRIPT_DIR/make_test_filesystems.sh' to create loopback mounts if needed."
fi

echo ""
echo "=========================================================="
echo " Dev/Lab benchmark environment setup complete!"
echo "=========================================================="
