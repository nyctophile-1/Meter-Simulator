#!/usr/bin/env bash
#
# One-time host preparation for the meter simulator (Ubuntu 24.04, AWS).
# Idempotent — safe to re-run.
#
# Does NOT deploy the app or start the service; run deploy/deploy.sh for that.
#
#   sudo bash host-prep.sh
#
set -euo pipefail

# The prefix AWS delegated to this instance's ENI (EC2 > Network Interfaces > Details >
# IPv6 Prefix Delegation). Delegated prefixes are /80. Must match Tcp:AddressPrefix in
# appsettings.Production.json, or meters are computed outside the routed range.
# The IPv6 prefix delegated to this instance's ENI. It differs per deployment target, so it is
# an argument rather than a constant — a hardcoded prefix silently configures the wrong local
# route and every meter becomes unreachable while the UI still looks healthy.
# build.ps1 prints the correct invocation for the target you built.
METER_PREFIX="${1:-}"
if [ -z "$METER_PREFIX" ]; then
    echo "usage: host-prep.sh <meter-ipv6-prefix>" >&2
    echo "  eqa:      sudo bash host-prep.sh 2406:da1a:261:6903:882d::/80" >&2
    echo "  personal: sudo bash host-prep.sh 2406:da1a:1c29:500:bc96::/80" >&2
    exit 1
fi
# Sim-root holds three siblings: app/ is replaced on every deploy; data/ and logs/ persist
# across deploys/reboots. The app writes them as ../data and ../logs relative to app/.
SIM_ROOT="/opt/maya-sim"
APP_DIR="$SIM_ROOT/app"
SVC_USER="maya"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run with sudo." >&2
  exit 1
fi

# Primary interface, detected rather than assumed (t3 = ens5, but don't hardcode).
IFACE="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
[ -z "$IFACE" ] && IFACE="$(ip -o -6 route show to default | awk '{print $5}' | head -n1)"
if [ -z "$IFACE" ]; then
  echo "Could not detect the primary network interface." >&2
  exit 1
fi
echo "==> Interface: $IFACE     Meter prefix: $METER_PREFIX"

# ── 1. Runtime prerequisite ───────────────────────────────────────────────────
# A self-contained .NET build still needs ICU on the host.
echo "==> Installing libicu"
apt-get update -qq
apt-get install -y libicu74 || apt-get install -y libicu-dev

# ── 2. Service user and directories ───────────────────────────────────────────
echo "==> Creating $SVC_USER and $SIM_ROOT (app/ + persistent data/ logs/)"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$APP_DIR/Templates" "$SIM_ROOT/data" "$SIM_ROOT/logs"
chown -R "$SVC_USER:$SVC_USER" "$SIM_ROOT"

# ── 2b. Swap ──────────────────────────────────────────────────────────────────
# Small instances (t3.micro = 1 GB) have no swap by default, so overshooting RAM
# means the OOM killer SIGKILLs the process and every batch is lost. Swap turns
# that cliff into a slowdown, which is far easier to notice and recover from.
if ! swapon --show | grep -q '/swapfile'; then
  echo "==> Creating 2G swapfile"
  fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  # Prefer RAM; only reach for swap under real pressure.
  echo 'vm.swappiness = 10' > /etc/sysctl.d/99-maya-swap.conf
else
  echo "==> Swap already present, skipping"
fi

# ── 3. IPv6 forwarding + non-local bind ───────────────────────────────────────
# forwarding: required for the instance to accept traffic addressed to IPs that are not its own
#   (inbound PULL — HES dials a meter address and the wildcard listener answers).
#
# ip_nonlocal_bind: required for outbound PUSH. The meter addresses are covered by a `local` route
#   but are not individually assigned to the interface, so binding one as a socket's SOURCE fails
#   with EADDRNOTAVAIL unless this is on. Without it push either fails or silently leaves from the
#   host's own address — and the source IP is the ONLY thing telling the HES push server which meter
#   sent the data.
#
#   Note pull works fine without this, so no amount of pull load testing surfaces it: accepting an
#   inbound connection needs the local route only, never a source bind.
echo "==> Enabling IPv6 forwarding and non-local bind"
cat > /etc/sysctl.d/99-maya-forwarding.conf <<'EOF'
net.ipv6.conf.all.forwarding = 1
net.ipv6.ip_nonlocal_bind = 1
EOF

# ── 4. Scale-final kernel tuning ──────────────────────────────────────────────
# Set once, sized for the largest fleet this box will ever hold. Thereafter only
# instance size changes — see deploy_task.md.
echo "==> Applying kernel tuning"
cat > /etc/sysctl.d/99-maya-scale.conf <<'EOF'
# One socket per connected meter, plus headroom
fs.file-max = 4000000
fs.nr_open  = 4000000

# Accept queue. NOTE: the app hardcodes listen(backlog=512), so this only takes
# full effect once that is made configurable (deploy_task.md P0-5).
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Large local prefix with many active flows
net.ipv6.route.max_size = 2097152

# Many connections, each with modest buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem  = 786432 1048576 1572864

# Recycle closed sockets promptly during high-churn tests
net.ipv4.tcp_fin_timeout = 15
EOF
sysctl --system >/dev/null

# ── 5. Local route for the meter /64 ──────────────────────────────────────────
# Declares every address in the prefix a valid local destination, so ONE wildcard
# socket answers for every meter — without assigning a million interface addresses.
# netplan cannot express `local` routes, hence a unit.
echo "==> Installing meter route unit"
cat > /etc/systemd/system/maya-meter-route.service <<EOF
[Unit]
Description=Local route for the simulated meter /64
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip -6 route replace local ${METER_PREFIX} dev ${IFACE}
ExecStop=/sbin/ip -6 route del local ${METER_PREFIX} dev ${IFACE}

[Install]
WantedBy=multi-user.target
EOF

# ── 5b. Route watchdog ────────────────────────────────────────────────────────
# The local route is NOT owned by netplan/networkd, so anything that reconfigures the
# interface (DHCPv6 lease renewal, netplan apply, networkd restart, link flap) silently
# flushes it. maya-meter-route is Type=oneshot RemainAfterExit=yes, so systemd still
# believes it is active and never re-runs it: the app keeps serving the UI on :80 while
# every meter address becomes unroutable. From outside that looks like a dead listener,
# but it is a CONNECTION TIMEOUT (packet never lands) rather than the connection-refused
# a dead socket would give.
#
# `ip -6 route replace` is idempotent and atomic - no delete/add gap where packets could
# drop - so simply re-asserting it every minute makes the failure self-healing.
echo "==> Installing meter route watchdog (re-asserts the route every 60s)"
cat > /etc/systemd/system/maya-meter-route-check.service <<EOF
[Unit]
Description=Re-assert the local meter route if something flushed it
After=network-online.target

[Service]
Type=oneshot
ExecStart=/sbin/ip -6 route replace local ${METER_PREFIX} dev ${IFACE}
EOF

cat > /etc/systemd/system/maya-meter-route-check.timer <<'EOF'
[Unit]
Description=Periodically re-assert the local meter route

[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

# ── 6. Application service ────────────────────────────────────────────────────
# Type=simple, NOT notify: readiness notification needs builder.Host.UseSystemd()
# in Program.cs, which does not exist. With notify and no sd_notify, start times out.
echo "==> Installing maya-sim.service"
cat > /etc/systemd/system/maya-sim.service <<EOF
[Unit]
Description=MAYA Many-Meter Simulator
After=network-online.target maya-meter-route.service
Wants=network-online.target
Requires=maya-meter-route.service

[Service]
Type=simple
User=${SVC_USER}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/ManyMeterSimulator
Restart=always
RestartSec=5

# Lets a NON-root user bind port 80, so the UI answers at http://<ip>/
AmbientCapabilities=CAP_NET_BIND_SERVICE

# One file descriptor per connected meter, plus headroom
LimitNOFILE=2000000

Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://*:80
Environment=DOTNET_gcServer=1

# Leading '-' = optional. Password rotation is deferred; drop overrides here later
# without touching this unit.
EnvironmentFile=-/etc/maya-sim/secrets.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now maya-meter-route.service
systemctl enable --now maya-meter-route-check.timer
systemctl enable maya-sim.service >/dev/null 2>&1 || true

# ── 7. Verify ─────────────────────────────────────────────────────────────────
echo
echo "==> Verification"
# Strip the /NN and append 1 — works for any prefix length, not just /64.
FIRST_METER="$(echo "$METER_PREFIX" | sed 's#/[0-9]*$##')1"
echo "-- ip -6 route get $FIRST_METER"
ip -6 route get "$FIRST_METER" || true
echo
if ip -6 route get "$FIRST_METER" 2>/dev/null | grep -q "local"; then
  echo "OK: the kernel owns the meter prefix."
else
  echo "FAIL: '$FIRST_METER' did not resolve as local. The app will start, but no"
  echo "      meter will be reachable. Check step 5 and the ENI route in AWS."
fi
echo
echo "Host prep done. Next: copy the artifact over and run deploy/deploy.sh."
