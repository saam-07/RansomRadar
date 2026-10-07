#!/usr/bin/env bash
# AdaptShield -- Debian (.deb) Package Builder
# Builds adaptshield_<version>_amd64.deb for Debian/Ubuntu systems
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$REPO_ROOT/build/deb"
VERSION="0.2.0"
ARCH="amd64"
PKG_NAME="adaptshield_${VERSION}_${ARCH}"
TARGET_DIR="$BUILD_DIR/$PKG_NAME"

echo "=========================================================="
echo " Building Debian package: ${PKG_NAME}.deb"
echo "=========================================================="

rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR/DEBIAN"
mkdir -p "$TARGET_DIR/etc/adaptshield"
mkdir -p "$TARGET_DIR/lib/systemd/system"
mkdir -p "$TARGET_DIR/opt/adaptshield/package"
mkdir -p "$TARGET_DIR/var/lib/adaptshield"
mkdir -p "$TARGET_DIR/var/log/adaptshield"

# 1. Control File
cat <<EOF > "$TARGET_DIR/DEBIAN/control"
Package: adaptshield
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Maintainer: AdaptShield Team <https://github.com/saam-07/RansomRadar>
Depends: python3 (>= 3.8), python3-venv, python3-pip, cgroup-tools, inotify-tools, libcap2-bin, util-linux
Recommends: bpfcc-tools, python3-bpfcc
Description: Autonomous Linux ransomware defense and reversible containment system.
 AdaptShield combines multi-path fanotify event streaming, optional eBPF Tier-1
 kernel tracing, machine-learned classification, and per-process cgroup v2
 reversible freezing with automated overlayfs rollback.
EOF

# 2. Conffiles (never overwrite existing user config on dpkg upgrade)
cat <<EOF > "$TARGET_DIR/DEBIAN/conffiles"
/etc/adaptshield/config.yaml
EOF

# 3. Post-install script
cat <<'EOF' > "$TARGET_DIR/DEBIAN/postinst"
#!/bin/sh
set -e

if [ "$1" = "configure" ]; then
  echo "Setting up AdaptShield runtime virtual environment..."
  if [ ! -d /opt/adaptshield/venv ]; then
    python3 -m venv --system-site-packages /opt/adaptshield/venv
  fi
  
  /opt/adaptshield/venv/bin/pip install --upgrade pip setuptools wheel -q
  /opt/adaptshield/venv/bin/pip install /opt/adaptshield/package -q

  # Ensure symlinks in /usr/local/bin
  ln -sf /opt/adaptshield/venv/bin/adaptshield /usr/local/bin/adaptshield
  ln -sf /opt/adaptshield/venv/bin/adaptshield-agent /usr/local/bin/adaptshield-agent

  # Permissions
  chmod 750 /var/lib/adaptshield
  chmod 755 /var/log/adaptshield
  chmod 640 /etc/adaptshield/config.yaml || true

  # systemd configuration
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable adaptshield.service || true
    systemctl restart adaptshield.service || true
  fi

  echo "AdaptShield installation complete. Run 'adaptshield status' or 'adaptshield doctor'."
fi
exit 0
EOF
chmod 755 "$TARGET_DIR/DEBIAN/postinst"

# 4. Pre-remove script
cat <<'EOF' > "$TARGET_DIR/DEBIAN/prerm"
#!/bin/sh
set -e

if [ "$1" = "remove" ] || [ "$1" = "deconfigure" ]; then
  # Thaw processes before stopping
  if command -v adaptshield >/dev/null 2>&1; then
    adaptshield release --all 2>/dev/null || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop adaptshield.service 2>/dev/null || true
    systemctl disable adaptshield.service 2>/dev/null || true
  fi
fi
exit 0
EOF
chmod 755 "$TARGET_DIR/DEBIAN/prerm"

# 5. Post-remove script
cat <<'EOF' > "$TARGET_DIR/DEBIAN/postrm"
#!/bin/sh
set -e

if [ "$1" = "purge" ]; then
  rm -rf /var/lib/adaptshield
  rm -rf /etc/adaptshield
  rm -rf /var/log/adaptshield
  rm -rf /opt/adaptshield
  rm -f /usr/local/bin/adaptshield
  rm -f /usr/local/bin/adaptshield-agent
elif [ "$1" = "remove" ]; then
  rm -f /usr/local/bin/adaptshield
  rm -f /usr/local/bin/adaptshield-agent
  echo "Preserved /var/lib/adaptshield/quarantine and /etc/adaptshield. Use --purge to delete."
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "$TARGET_DIR/DEBIAN/postrm"

# 6. Copy Files
cp "$REPO_ROOT/packaging/config.default.yaml" "$TARGET_DIR/etc/adaptshield/config.yaml"
cp "$REPO_ROOT/packaging/systemd/adaptshield.service" "$TARGET_DIR/lib/systemd/system/adaptshield.service"

# Build Python source archive/distribution into package payload
cd "$REPO_ROOT"
python3 -m pip install build --quiet 2>/dev/null || true
if python3 -m build --sdist --outdir "$TARGET_DIR/opt/adaptshield/package" 2>/dev/null; then
  echo "[*] Built sdist package payload."
else
  # Fallback: copy source tree directly
  cp -r "$REPO_ROOT/src" "$TARGET_DIR/opt/adaptshield/package/"
  cp "$REPO_ROOT/pyproject.toml" "$TARGET_DIR/opt/adaptshield/package/"
  if [ -f "$REPO_ROOT/requirements.txt" ]; then
    cp "$REPO_ROOT/requirements.txt" "$TARGET_DIR/opt/adaptshield/package/"
  fi
fi

# 7. Build .deb package using dpkg-deb
mkdir -p "$REPO_ROOT/dist"
if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --build "$TARGET_DIR" "$REPO_ROOT/dist/${PKG_NAME}.deb"
  echo "[*] Created Debian package: dist/${PKG_NAME}.deb"
else
  echo "[WARN] dpkg-deb not found on this host. Staged debian layout at $TARGET_DIR."
fi
