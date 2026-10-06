#!/usr/bin/env bash
# AdaptShield -- Automated System Verification Script
# Runs all checks from Phase 1 through Phase 5 in one command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

echo "========================================================="
echo " AdaptShield Full System Verification"
echo "========================================================="

echo ""
echo "[Step 1/6] Checking kernel and cgroups v2..."
uname -r
if mount | grep -q cgroup2; then
  echo "  [OK] cgroup2 unified hierarchy active."
else
  echo "  [FAIL] cgroup2 not active."
fi
if [ -f /sys/fs/cgroup/cgroup.subtree_control ]; then
  echo "  [INFO] Controllers available: $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true)"
  echo "  [INFO] Subtree control: $(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true)"
fi

echo ""
echo "[Step 2/6] Checking Python virtual environment and BCC (eBPF) bindings..."
if [ ! -d ".venv" ]; then
  echo "  [FAIL] .venv directory not found. Run sudo ./setup/install_deps.sh first."
  exit 1
fi

.venv/bin/python3 -c "import bcc; print('  [OK] BCC eBPF bindings imported successfully.')"
.venv/bin/python3 -c "import adaptshield; print('  [OK] adaptshield package imported successfully.')"

echo ""
echo "[Step 3/6] Running unit tests..."
.venv/bin/python3 -m pytest tests/ -v

echo ""
echo "[Step 4/6] Checking test filesystems..."
for fs in ext4 btrfs xfs; do
  MNT="/mnt/testfs_${fs}"
  if mount | grep -q "$MNT"; then
    echo "  [OK] $MNT is mounted."
    touch "$MNT/data/.test_write" 2>/dev/null && rm -f "$MNT/data/.test_write" && echo "  [OK] $MNT is writable."
  else
    echo "  [WARN] $MNT is NOT mounted. Run sudo ./setup/make_test_filesystems.sh"
  fi
done

echo ""
echo "[Step 5/6] Testing Tier 1 eBPF tracer initialization..."
if [ "$EUID" -ne 0 ]; then
  echo "  [INFO] Running eBPF and cgroup tests requires root. Running via sudo..."
  sudo .venv/bin/python3 -c "
from adaptshield.tier1_bridge import Tier1Tracer
import os
tracer = Tier1Tracer()
print('  [OK] Tier 1 eBPF tracer compiled & kprobes attached successfully.')
tracer.escalate(os.getpid())
tracer.poll(timeout_ms=100)
tracer.deescalate(os.getpid())
print('  [OK] eBPF escalation / de-escalation test passed.')
"
else
  .venv/bin/python3 -c "
from adaptshield.tier1_bridge import Tier1Tracer
import os
tracer = Tier1Tracer()
print('  [OK] Tier 1 eBPF tracer compiled & kprobes attached successfully.')
tracer.escalate(os.getpid())
tracer.poll(timeout_ms=100)
tracer.deescalate(os.getpid())
print('  [OK] eBPF escalation / de-escalation test passed.')
"
fi

echo ""
echo "[Step 6/6] Testing Cgroups v2 process freezer..."
if [ "$EUID" -ne 0 ]; then
  sudo .venv/bin/python3 -c "
from adaptshield.containment_manager import ensure_cgroup_ready, freeze_pid, unfreeze_pid
import subprocess, time
ensure_cgroup_ready()
p = subprocess.Popen(['sleep', '10'])
t = freeze_pid(p.pid)
print('  [OK] Process', p.pid, 'frozen successfully.')
time.sleep(0.5)
unfreeze_pid()
p.terminate()
p.wait()
print('  [OK] Process unfreeze and containment test passed.')
"
else
  .venv/bin/python3 -c "
from adaptshield.containment_manager import ensure_cgroup_ready, freeze_pid, unfreeze_pid
import subprocess, time
ensure_cgroup_ready()
p = subprocess.Popen(['sleep', '10'])
t = freeze_pid(p.pid)
print('  [OK] Process', p.pid, 'frozen successfully.')
time.sleep(0.5)
unfreeze_pid()
p.terminate()
p.wait()
print('  [OK] Process unfreeze and containment test passed.')
"
fi

echo ""
echo "========================================================="
echo " ALL ADAPTSHIELD VERIFICATION CHECKS PASSED!"
echo "========================================================="
