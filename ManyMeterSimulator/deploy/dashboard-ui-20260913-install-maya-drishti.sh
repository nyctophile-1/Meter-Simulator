#!/usr/bin/env bash
set -Eeuo pipefail
test "$(id -u)" -eq 0
COMMIT=${1:?full commit required}
HASH=${2:?archive SHA256 required}
DLL_HASH=${3:?DLL SHA256 required}
CORE_HASH=${4:?core DLL SHA256 required}
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$HASH" =~ ^[0-9a-f]{64}$ ]]
[[ "$DLL_HASH" =~ ^[0-9a-f]{64}$ ]]
exec 9>/run/lock/maya-deploy.lock
flock -n 9 || { echo 'Another deployment is running'; exit 1; }
RELEASE=${COMMIT:0:7}
ROOT=/opt/maya-sim
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="$ROOT/backups/$STAMP-$RELEASE"
STAGE="$ROOT/app-stage-$STAMP"
ARCHIVE="/tmp/maya-drishti-$RELEASE.tar.gz"
echo "$HASH  $ARCHIVE" | sha256sum -c -
test -d "$ROOT/app"
test -d "$ROOT/data"
test ! -e "$BACKUP"
test ! -e "$STAGE"
AVAILABLE=$(df -B1 --output=avail "$ROOT" | tail -1)
DATA_BYTES=$(du -sb "$ROOT/data" | cut -f1)
APP_BYTES=$(du -sb "$ROOT/app" | cut -f1)
NEEDED=$((DATA_BYTES + APP_BYTES + 1073741824))
[ "$AVAILABLE" -gt "$NEEDED" ] || { echo "Insufficient backup headroom: $AVAILABLE available, $NEEDED needed"; exit 1; }
install -d -m 700 "$BACKUP"
cp -a "$ROOT/app" "$STAGE"
tar -xzf "$ARCHIVE" -C "$STAGE" --exclude='./appsettings*.json' --exclude='./Templates'
echo "$DLL_HASH  $STAGE/ManyMeterSimulator.dll" | sha256sum -c -
echo "$CORE_HASH  $STAGE/MeterSimulator.Core.dll" | sha256sum -c -
test -s "$STAGE/deployed-release.txt"
chmod +x "$STAGE/ManyMeterSimulator"
chown -R maya:maya "$STAGE"
diff -q "$ROOT/app/appsettings.json" "$STAGE/appsettings.json"
diff -q "$ROOT/app/appsettings.Production.json" "$STAGE/appsettings.Production.json"
diff -qr "$ROOT/app/Templates" "$STAGE/Templates"
systemctl cat maya-sim > "$BACKUP/maya-sim.service.txt"
SWAPPED=0
rollback() {
    trap - ERR
    if [ "$SWAPPED" = 1 ]; then
        systemctl stop maya-sim || true
        if [ -e "$ROOT/app" ]; then mv "$ROOT/app" "$ROOT/app-failed-$STAMP"; fi
        cp -a "$BACKUP/app" "$ROOT/app"
        mv "$ROOT/data" "$ROOT/data-failed-$STAMP"
        cp -a "$BACKUP/data" "$ROOT/data"
    fi
    systemctl start maya-sim
    echo "DEPLOYMENT_FAILED BACKUP=$BACKUP" >&2
    exit 1
}
trap rollback ERR
systemctl stop maya-sim
cp -a "$ROOT/data" "$BACKUP/data"
mv "$ROOT/app" "$BACKUP/app"
SWAPPED=1
mv "$STAGE" "$ROOT/app"
systemctl start maya-sim
for attempt in $(seq 1 30); do
    if curl --fail --silent --output /dev/null http://localhost/login; then break; fi
    sleep 1
done
systemctl is-active --quiet maya-sim
curl --fail --silent --output /dev/null http://localhost/login
ss -6 -lnt | grep -q ':4059 '
ip -6 route get 2406:da1a:a2d:a604:52fa::1 | grep -q local
diff -q "$BACKUP/app/appsettings.json" "$ROOT/app/appsettings.json"
diff -q "$BACKUP/app/appsettings.Production.json" "$ROOT/app/appsettings.Production.json"
diff -qr "$BACKUP/app/Templates" "$ROOT/app/Templates"
trap - ERR
echo "DEPLOYMENT_VERIFIED BACKUP=$BACKUP"
