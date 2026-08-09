#!/usr/bin/env bash
#
# Deploy (or redeploy) the simulator from an uploaded artifact.
# Run AFTER host-prep.sh. Idempotent — this is the every-deployment script.
#
#   sudo bash deploy.sh /tmp/maya-sim.tar.gz
#
set -euo pipefail

TARBALL="${1:-/tmp/maya-sim.tar.gz}"
# app/ is the deployment (replaced here); data/ and logs/ are persistent siblings under the
# sim-root that this script never touches, so batches and logs survive every redeploy.
SIM_ROOT="/opt/maya-sim"
APP_DIR="$SIM_ROOT/app"
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
# Ensure the persistent siblings exist (the app also self-creates them, but pre-owning them
# by the service user avoids a first-run permission miss). data/ and logs/ are left untouched.
mkdir -p "$APP_DIR/Templates" "$SIM_ROOT/data" "$SIM_ROOT/logs"
chown -R "$SVC_USER:$SVC_USER" "$SIM_ROOT"

# Re-assert the local meter route before starting the app. The route unit is oneshot +
# RemainAfterExit, so systemd will not re-run it on its own even when the kernel route has
# been flushed - which leaves the app serving the UI while every meter address is
# unroutable. `replace` is idempotent, so this is a no-op when the route is already right.
echo "==> Re-asserting meter route"
systemctl start maya-meter-route-check.service 2>/dev/null \
  || systemctl restart maya-meter-route.service 2>/dev/null \
  || true

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

# A bound socket is only half the story: without the local route the meter addresses are
# unroutable and connections time out, even though everything above looks healthy.
echo
echo "==> Meter route"
FIRST_METER="$(awk -F'"' '/"AddressPrefix"/ {print $4}' "$APP_DIR/appsettings.Production.json" 2>/dev/null | sed 's#/[0-9]*$##')1"
if [ -n "$FIRST_METER" ] && ip -6 route get "$FIRST_METER" 2>/dev/null | grep -q local; then
  echo "  OK: $FIRST_METER resolves as local"
else
  echo "  WARNING: $FIRST_METER is NOT local - meters will time out. Run:"
  echo "           sudo systemctl restart maya-meter-route maya-sim"
fi
echo
echo "Check the log above for: 'TCP NIC listener bound to [::]:4059' and that the"
echo "logged address prefix is the real meter /64, not the fd00: dev default."
