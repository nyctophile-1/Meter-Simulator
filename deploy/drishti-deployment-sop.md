# MAYA deployment SOP — DRISHTI (Observability)

Last verified: 11 September 2026. This procedure updates the existing MAYA service from a Windows workstation. It preserves server configuration, templates, persistent data, and encryption keys, and takes a rollback backup before replacing the application.

## 1. Target and access

| Item | Value |
| --- | --- |
| Server | DRISHTI / Observability, `maya-sim` |
| Private IPv4 | `10.254.3.57` — VPN required |
| SSH user | `ubuntu`, with passwordless sudo |
| AWS account | `984588231569` — Kimbal-Drishti-Analytics |
| Instance | `i-0f27b0ec86e8fe7c0` |
| Availability zone | `ap-south-1a` |
| Host | Ubuntu 24.04, x86_64; t3a.large, 2 vCPUs, 8 GiB RAM, 30 GiB root disk |
| Service | `maya-sim` (systemd), running as `maya` |
| Application | `/opt/maya-sim/app` |
| Persistent data / keys | `/opt/maya-sim/data`, `/opt/maya-sim/data/keys` |
| Logs | `/opt/maya-sim/logs` and `journalctl -u maya-sim` |
| Environment secrets | `/etc/maya-sim/secrets.env` |
| UI | [http://10.254.3.57/login](http://10.254.3.57/login) |
| Meter listener | TCP `4059`, IPv6 |
| Meter prefix | `2406:da1a:a2d:a604:52fa::/80` |
| Release branch | `Custom-Push-Implementation` |

Infrastructure record: [DEVO-11383](https://sinhaludyog.atlassian.net/browse/DEVO-11383).
Obtain access through the [Vault entry](https://vault.kimbal.io/ui/vault/secrets/kv/kv/devops%2Fehes%2Fobservability%2Fmaya-sim-load-testing/details?version=1).
Each teammate needs their own authorized access to the SSH key and UI credentials. Do not commit keys, passwords, server config, or data backups to Git.

## 2. Before starting

- Confirm the release commit and restart window with the service owner. Stop or finish active load/stress tests: restart disconnects clients and discards prepared in-memory push datasets.
- Coordinate one deployment at a time. Avoid changing batches, network settings, or templates while deploying.
- Connect to the company VPN. Install Git, OpenSSH (`ssh`/`scp`), `tar`, and the .NET 10 SDK on the workstation. NuGet package restore must work.
- Use a clean checkout. Do not discard someone else's uncommitted work.
- This SOP preserves **all existing `appsettings*.json` and template files**. Review release changes to configuration, persistence, and templates before proceeding. If a new release requires a migration or new non-default settings/templates, agree and document those changes first; this procedure does not apply them automatically.
- Do not use `deploy/build.ps1 -Target eqa` or `-Target personal` for DRISHTI. Those targets contain different IPv6 prefixes. Do not rerun `host-prep.sh` for a routine update.

## 3. Select the release and check connectivity

Run in **PowerShell**. Adjust the repository and key paths for your workstation.

```powershell
Set-Location C:\repos\Meter-Simulator
$KeyPath = 'C:\repos\creds\drishti-ssh.pem'
$SshTarget = 'ubuntu@10.254.3.57'
if (-not (Test-Path -LiteralPath $KeyPath)) { throw 'SSH key not found' }
if (git status --porcelain) { throw 'Use a clean checkout before deploying' }
git fetch origin
if ($LASTEXITCODE -ne 0) { throw 'Fetch failed' }
git switch Custom-Push-Implementation
if ($LASTEXITCODE -ne 0) { throw 'Branch switch failed' }
git pull --ff-only origin Custom-Push-Implementation
if ($LASTEXITCODE -ne 0) { throw 'Fast-forward failed; review branch divergence' }
$Commit = (git rev-parse HEAD).Trim()
$Release = $Commit.Substring(0, 7)
git log -1 --oneline
ssh -i $KeyPath -o IdentitiesOnly=yes -o ConnectTimeout=10 $SshTarget
```

On first SSH connection, verify the host fingerprint through your trusted infrastructure contact before accepting it. Never bypass a changed-host-key warning without investigating it.

At the **Linux SSH prompt**:

```bash
hostname
sudo -n true
systemctl is-active maya-sim
cat /opt/maya-sim/app/deployed-release.txt
df -h /opt/maya-sim
free -h
sudo du -sh /opt/maya-sim/app /opt/maya-sim/data
ip -6 route get 2406:da1a:a2d:a604:52fa::1
exit
```

Expected hostname: `ip-10-254-3-57`; service: `active`; meter route: `local`. Record the installed release. An older installation may lack the release marker. Allow space for another application copy, a full data backup, and the uploaded archive, plus normal operating headroom. Do not delete old backups without checking retention requirements.

## 4. Test, publish, and package

Back in the **same PowerShell session**:

```powershell
$Output = Join-Path (Get-Location) "publish\drishti-$Release-$(Get-Date -Format yyyyMMddHHmmss)"
New-Item -ItemType Directory -Path $Output -ErrorAction Stop | Out-Null
$AppOutput = Join-Path $Output 'app'
$Archive = Join-Path $Output "maya-drishti-$Release.tar.gz"

dotnet test ManyMeterSimulator/ManyMeterSimulator.Tests/ManyMeterSimulator.Tests.csproj -c Release --nologo --verbosity quiet
if ($LASTEXITCODE -ne 0) { throw 'Tests failed; do not deploy' }

dotnet publish ManyMeterSimulator/ManyMeterSimulator/ManyMeterSimulator.csproj -c Release -r linux-x64 --self-contained true -o $AppOutput --nologo --verbosity quiet
if ($LASTEXITCODE -ne 0) { throw 'Publish failed; do not deploy' }
if (-not (Test-Path (Join-Path $AppOutput 'ManyMeterSimulator'))) { throw 'Missing Linux executable' }
if ((git rev-parse HEAD).Trim() -ne $Commit -or (git status --porcelain)) { throw 'Checkout changed during build' }

tar -czf $Archive -C $AppOutput .
if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
$ArchiveHash = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
$DllHash = (Get-FileHash (Join-Path $AppOutput 'ManyMeterSimulator.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
"Commit: $Commit"
"Archive SHA256: $ArchiveHash"
"DLL SHA256: $DllHash"
scp -i $KeyPath -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes $Archive "${SshTarget}:/tmp/maya-drishti-$Release.tar.gz"
if ($LASTEXITCODE -ne 0) { throw 'Upload failed' }
```

Record the three printed values. Self-contained publishing includes the Linux runtime; no server-side SDK installation is required. On 11 September, commit `f66e327` passed 385 tests; future releases may have different totals. Any failed test blocks deployment.

## 5. Install with backup and automatic startup rollback

Open SSH again with `ssh -i $KeyPath $SshTarget`. At the **Linux prompt**, save the following block as `/tmp/install-maya-drishti.sh` using an editor. The script takes the full commit, archive hash, and DLL hash from step 4. It does not contain credentials.

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
test "$(id -u)" -eq 0
COMMIT=${1:?full commit required}
HASH=${2:?archive SHA256 required}
DLL_HASH=${3:?DLL SHA256 required}
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
install -d -m 700 "$BACKUP"
cp -a "$ROOT/app" "$STAGE"
tar -xzf "$ARCHIVE" -C "$STAGE" --exclude='./appsettings*.json' --exclude='./Templates'
echo "$DLL_HASH  $STAGE/ManyMeterSimulator.dll" | sha256sum -c -
printf '%s\n' "$COMMIT Custom-Push-Implementation" > "$STAGE/deployed-release.txt"
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
```

Validate syntax, then execute, replacing all three placeholders with the recorded values:

```bash
bash -n /tmp/install-maya-drishti.sh
sudo bash /tmp/install-maya-drishti.sh FULL_COMMIT ARCHIVE_SHA256 DLL_SHA256
```

Require `DEPLOYMENT_VERIFIED` and save the printed backup path. The backup contains the previous `app`, pre-start `data` including encryption keys, and a service-unit record. Environment secrets, systemd configuration, logs, and network routes are left in place. The new release overlays a copy of the old application, so server-only assets remain available; releases requiring obsolete-file removal need a reviewed cleanup procedure.

Automatic rollback covers command failures during installation and the initial health checks. It does not guarantee recovery from a killed shell or machine failure. Inspect the actual directories and service before attempting manual recovery after an interruption.

## 6. Verify after deployment

Run on **Linux**:

```bash
systemctl show maya-sim -p ActiveState -p SubState -p MainPID -p NRestarts
cat /opt/maya-sim/app/deployed-release.txt
sha256sum /opt/maya-sim/app/ManyMeterSimulator.dll
curl -s -o /dev/null -w 'HTTP:%{http_code}\n' http://localhost/login
ss -6 -lnt | grep ':4059 '
ip -6 route get 2406:da1a:a2d:a604:52fa::1
sudo journalctl -u maya-sim --since '5 minutes ago' --no-pager
```

- Require `active/running`, the intended commit/DLL checksum, HTTP `200`, port `4059`, and a `local` meter route. Check that the restart counter does not increase.
- Open the UI over VPN and log in. Compare batches, meter counts, templates, and network bindings with the pre-deployment state. Large fleets take longer to reload than the login page: a 100,000-meter batch took about 36 seconds in the verified deployment. Wait for the relevant `Reloaded ... meter sessions` entries and batch status before declaring readiness.
- Check broker connection logs for enabled MQTT batches. Stopped batches should stay stopped; disabled brokers should remain disabled.
- Data files can be rewritten during startup. Batch `Starting` status can be temporary, and encrypted password bytes can change when the registry re-saves them. Compare logical state rather than treating every byte difference as data loss. Preserve `data/keys` so saved credentials remain decryptable.
- A healthy login page and connected MQTT client do not prove HES ingestion. For a release needing end-to-end validation, coordinate a small existing test with its owner and verify receipt at the broker/HES. Do not fire a fleet-wide stress test as a deployment health check.
- Record commit, test outcome, deployment time, backup path, health results, and unresolved warnings in the team's deployment record.

Known condition at the last deployment: HES data-model CSVs were absent at `/opt/maya-sim/app/KimbalSpecifics/DataModel`; startup reported the custom channel unavailable. This SOP preserves that configuration. Enabling it requires the correct HES exports and configuration, agreed separately with the owner.

## 7. Manual rollback after later verification failure

Coordinate rollback timing with the owner. Restoring the data snapshot also reverts any batch/network changes made **after** the deployment. Preserve the failed app and current data for investigation. Set `BACKUP` to the exact path printed by the deployment being rolled back; do not blindly choose the newest directory.

At the **Linux prompt**, open a root shell with `sudo bash`, then run:

```bash
set -euo pipefail
BACKUP=/opt/maya-sim/backups/REPLACE_WITH_RECORDED_BACKUP
ROOT=/opt/maya-sim
test -d "$BACKUP/app"
test -d "$BACKUP/data"
exec 9>/run/lock/maya-deploy.lock
flock -n 9
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RECOVERY="$ROOT/rollback-displaced-$STAMP"
install -d -m 700 "$RECOVERY"
systemctl stop maya-sim
mv "$ROOT/app" "$RECOVERY/app"
mv "$ROOT/data" "$RECOVERY/data"
cp -a "$BACKUP/app" "$ROOT/app"
cp -a "$BACKUP/data" "$ROOT/data"
systemctl start maya-sim
systemctl is-active maya-sim
exit
```

Repeat step 6 for the restored release. If a rollback command fails, keep the failure output and recover the missing app/data directories before starting again; do not delete either snapshot.

## 8. Troubleshooting

| Symptom | Action |
| --- | --- |
| SSH timeout | Check VPN, target IP, and VPC access. DRISHTI has no public IPv4. |
| `Permission denied (publickey)` | Check `ubuntu`, the authorized key, and `IdentitiesOnly=yes`. |
| `UNPROTECTED PRIVATE KEY FILE` on Windows | Restrict the PEM **file** to the current user in Windows Security → Advanced; remove inherited/shared read access. Do not change permissions recursively on the credentials directory. |
| NuGet config/cache access denied | Run with access to your authorized user NuGet configuration/cache; resolve local permissions before rebuilding. |
| `203/EXEC` | Check execute permission on `/opt/maya-sim/app/ManyMeterSimulator`; Windows publishing does not retain Linux executable bits. |
| UI works, meter addresses time out | Check the `/80` local route and the on-server prefix; investigate VPC/HES connectivity separately. Do not substitute the EQA prefix. |
| MQTT batch unreachable | Inspect the batch's enabled broker, credentials, endpoint, and connection logs; do not enable unrelated brokers automatically. |
| Repeated restarts / OOM | Inspect `journalctl -u maya-sim`, kernel OOM logs, and `free -h`; coordinate rollback or workload reduction. |
| Checksum mismatch | Stop. Rebuild/retransfer the intended archive; never bypass verification. |

For a service-only restart, with owner authorization: `sudo systemctl restart maya-sim`, then repeat step 6. No rebuild or host preparation is needed.
