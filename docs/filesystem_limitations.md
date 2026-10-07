# AdaptShield Kernel & Filesystem Limitations

This document provides a technical explanation of the kernel, filesystem, and privilege limitations governing AdaptShield's fanotify monitoring and overlayfs protection layers.

---

## 1. Fanotify Monitoring (Tier-0 Watcher)

AdaptShield relies on Linux `fanotify(7)` for low-overhead filesystem event notifications.

### 1.1 Kernel Version Requirements
- **Linux >= 5.9 (Modern mode: `FAN_REPORT_DFID_NAME`):**
  - Full support for tracking directory-level lifecycle events (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`, `FAN_MOVED_TO`) alongside file data modifications (`FAN_MODIFY`, `FAN_CLOSE_WRITE`).
  - Delivers both file handles and directory event metadata (`FAN_EVENT_ON_CHILD`), enabling exact rename and deletion rate calculation.
- **Linux 5.1 – 5.8 (Classic mode fallback):**
  - Supports `FAN_MARK_FILESYSTEM`, but lacks directory-entry reporting (`DFID_NAME`).
  - Falls back to open/modify/close_write events only; rename and delete rates cannot be tracked via fanotify.
- **Linux < 5.1:**
  - `FAN_MARK_FILESYSTEM` is unsupported. Marks must be attached per mountpoint (`FAN_MARK_MOUNT`) or per inode.

### 1.2 Privilege Requirements
- Initializing `fanotify_init` requires `CAP_SYS_ADMIN` in the host's initial user namespace (i.e. root privileges).
- In unprivileged Docker containers or non-root user sessions, fanotify initialization fails (`EPERM`). AdaptShield detects this condition at startup and logs an informative warning.

### 1.3 Filesystem Compatibility
- **Supported:** Local block-device filesystems supporting file handles (`ext4`, `xfs`, `btrfs`).
- **Excluded by Default:**
  - Virtual filesystems (`/proc`, `/sys`, `/dev`): Do not generate standard inode events; excluded to avoid kernel lockups.
  - Dynamic runtimes (`/run`, `/tmp`, `/var/cache/apt`): Excluded to prevent false-positive noise and feedback loops.
  - Agent directories (`/var/lib/adaptshield`, `/var/log/adaptshield`): Excluded to prevent recursive event loops from the agent's own writes.
- **Network Filesystems (NFS, CIFS, GlusterFS):**
  - Fanotify does not report events triggered by remote clients on network shares. Modifications executed on remote clients will not generate local kernel notifications.

---

## 2. OverlayFS Protection & Rollback Layer

AdaptShield uses Linux `overlayfs` copy-on-write layers over configured `protect_paths` to allow reversible containment.

### 2.1 Backing Filesystem Requirements
- **`d_type` Support:**
  - OverlayFS requires the underlying storage for `upperdir` and `workdir` to support `d_type` in `readdir(3)`.
  - Supported: `ext4`, `xfs` (formatted with `ftype=1`), `btrfs`.
  - Unsupported: `vfat`, `exfat`, legacy `xfs` (`ftype=0`), and standard NFS mounts.
- **Same Mount Requirement:**
  - `upperdir` and `workdir` **must** reside on the same underlying mountpoint. AdaptShield enforces this by creating both under `/var/lib/adaptshield/overlay/<slug>/`.

### 2.2 Mount & Inode Limitations
- **Mountpoint In-Use / Nested Overlays:**
  - If a path in `protect_paths` is already a mountpoint or is already backed by an overlayfs (e.g. inside an existing container), mounting another overlayfs layer can fail or cause kernel conflicts.
- **Inode Instability:**
  - When an existing lower file is modified, overlayfs copies the file up to `upperdir`. The file receives a new inode number. Applications relying on persistent inode numbers across modifications (e.g. certain database engines) may encounter anomalies.

---

## 3. Graceful Fallback Strategy: "Rollback Unavailable"

When a configured path cannot be overlay-protected:
1. **Detection & Logging:** AdaptShield detects the mount failure or absence of root privileges, logs a loud warning (`[PROTECTION FALLBACK]`), and records the failure reason.
2. **Fallback Mode (`fallback_quarantine_only`):**
   - The path is placed into `fallback_quarantine_only` mode.
   - Per-PID cgroup containment and process termination remain fully operational.
   - On alert trigger, AdaptShield performs **quarantine-copy-on-detect** instead of overlay rollback.
3. **Status Transparency:**
   - `adaptshield status` and API outputs explicitly show `"rollback_available": false` and `"status": "fallback_quarantine_only"` for that path.
   - The system never makes false claims of reversible protection when overlayfs cannot be established.
