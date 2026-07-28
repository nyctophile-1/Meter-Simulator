#!/usr/bin/env bash
#
# Deploy (or redeploy) the simulator from an uploaded artifact.
# Run AFTER host-prep.sh. Idempotent — this is the every-deployment script.
#
#   sudo bash deploy.sh /tmp/maya-sim.tar.gz
#
set -euo pipefail

TARBALL="${1:-/tmp/maya-sim.tar.gz}"
APP_DIR="/opt/maya-sim"
SVC_USER="maya"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi
if [ ! -f "$TARBALL" ]; then
  echo "Artifact not found: $TARBALL" >&2
  exit 1
fi

echo "==> Stopping service"
systemctl stop maya-sim 2>/dev/null || true

# Keep the previous release so a rollback is a real option.
if [ -d "$APP_DIR" ]; then
  echo "==> Snapshotting current release to ${APP_DIR}.prev"
  rm -rf "${APP_DIR}.prev"
  cp -a "$APP_DIR" "${APP_DIR}.prev"
fi

echo "==> Extracting $TARBALL"
mkdir -p "$APP_DIR"
tar -xzf "$TARBALL" -C "$APP_DIR"

# The publish is produced on NTFS, which carries no execute bit. Without this,
# systemd fails with 203/EXEC.
echo "==> Setting execute bit and ownership"
chmod +x "$APP_DIR/ManyMeterSimulator"
mkdir -p "$APP_DIR/logs" "$APP_DIR/Templates"
chown -R "$SVC_USER:$SVC_USER" "$APP_DIR"

echo "==> Starting service"
systemctl start maya-sim
sleep 4

echo
echo "==> Status"
systemctl is-active maya-sim || true
echo
echo "==> Recent log"
journalctl -u maya-sim -n 30 --no-pager || true
echo
echo "==> Listening sockets"
ss -6 -lntp 2>/dev/null | grep 4059 || echo "  WARNING: nothing listening on 4059"
ss -lntp   2>/dev/null | grep ':80 ' || echo "  WARNING: nothing listening on 80"
echo
echo "Check the log above for: 'TCP NIC listener bound to [::]:4059' and that the"
echo "logged address prefix is the real meter /64, not the fd00: dev default."
