#!/usr/bin/env bash
# Uploaded with maya-sim.tar.gz and eqa-metadata.tar.gz. Run as root with their SHA256 hashes.
set -euo pipefail
test "$(id -u)" -eq 0
cd /tmp
echo "$1  maya-sim.tar.gz" | sha256sum -c -
echo "$2  eqa-metadata.tar.gz" | sha256sum -c -
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="/opt/maya-sim/backups/$STAMP"
STAGE=$(mktemp -d /tmp/maya-profiles-release.XXXXXX)
tar -xzf maya-sim.tar.gz -C "$STAGE"
# Operator explicitly requested preserving the EQA XML versions.
cp -a /opt/maya-sim/app/Templates/. "$STAGE/Templates/"
install -d -m 700 "$BACKUP"
echo "BACKUP=$BACKUP"
systemctl stop maya-sim
trap 'systemctl start maya-sim' ERR
cp -a /opt/maya-sim/app "$BACKUP/app"
cp -a /opt/maya-sim/data "$BACKUP/data"
systemctl cat maya-sim > "$BACKUP/maya-sim.service.txt"
rollback() {
    trap - ERR
    systemctl stop maya-sim || true
    cp -a "$BACKUP/app/." /opt/maya-sim/app/
    cp -a "$BACKUP/data/." /opt/maya-sim/data/
    systemctl start maya-sim
    echo "ROLLED_BACK=$BACKUP" >&2
    exit 1
}
trap rollback ERR
cp -a "$STAGE/." /opt/maya-sim/app/
mkdir -p /opt/maya-sim/data/custom-pull
tar -xzf eqa-metadata.tar.gz -C /opt/maya-sim/data/custom-pull
chmod +x /opt/maya-sim/app/ManyMeterSimulator
chown -R maya:maya /opt/maya-sim/app /opt/maya-sim/data/custom-pull
systemctl start maya-meter-route-check.service
systemctl start maya-sim
for attempt in $(seq 1 15); do
    if curl --fail --silent --output /dev/null http://localhost/login; then break; fi
    sleep 1
done
systemctl is-active --quiet maya-sim
curl --fail --silent --output /dev/null http://localhost/login
diff -qr "$BACKUP/app/Templates" /opt/maya-sim/app/Templates
sha256sum /opt/maya-sim/app/ManyMeterSimulator.dll
trap - ERR
echo "DEPLOYMENT_VERIFIED BACKUP=$BACKUP"
