#!/usr/bin/env bash
# AdaptShield -- Step 1: create three independent, snapshot-able test
# filesystems (ext4, btrfs, xfs) as loopback images, so the SAME experiment
# code can run against all three without touching the host root filesystem.
set -euo pipefail

IMG_DIR="${1:-$HOME/adaptshield_fsimages}"
SIZE_MB="${2:-4096}"   # 4GB per filesystem; raise if your dataset needs more
REAL_USER="${SUDO_USER:-$USER}"
mkdir -p "$IMG_DIR"

declare -A MKFS_CMDS=(
  [ext4]="mkfs.ext4 -F"
  [btrfs]="mkfs.btrfs -f"
  [xfs]="mkfs.xfs -f"
)

for fs in ext4 btrfs xfs; do
  IMG="$IMG_DIR/testfs_${fs}.img"
  MNT="/mnt/testfs_${fs}"
  echo "== Creating $fs image at $IMG (${SIZE_MB}MB) =="

  # Auto-unmount if already mounted
  if mountpoint -q "$MNT" 2>/dev/null || mount | grep -q " $MNT "; then
    echo "Unmounting existing mount at $MNT..."
    sudo umount -f "$MNT" 2>/dev/null || true
  fi

  # Clean up any leftover loop devices attached to this image
  if [ -f "$IMG" ]; then
    for loop in $(losetup -j "$IMG" 2>/dev/null | cut -d: -f1); do
      sudo losetup -d "$loop" 2>/dev/null || true
    done
  fi

  fallocate -l "${SIZE_MB}M" "$IMG"
  eval "${MKFS_CMDS[$fs]} \"$IMG\""
  sudo mkdir -p "$MNT"
  sudo mount -o loop "$IMG" "$MNT"
  
  # Create standard experiment directories inside mount point
  sudo mkdir -p "$MNT/data" "$MNT/backup" "$MNT/.overlay_upper" "$MNT/.overlay_work" "$MNT/.quarantine" "$MNT/merged"
  sudo chown -R "$REAL_USER":"$REAL_USER" "$MNT"
  sudo chmod -R 777 "$MNT"

  echo "Mounted $fs at $MNT (permissions: 777, owned by $REAL_USER)"
done

echo ""
echo "== Summary of Test Filesystems =="
mount | grep testfs

echo ""
echo "Test filesystems are ready! Mount points: /mnt/testfs_ext4, /mnt/testfs_btrfs, /mnt/testfs_xfs"
