# Deployment Walkthrough — AWS Linux

The repeatable procedure for deploying the meter simulator. Deployments are **manual** — this
document is the pipeline.

- **Parts A and B are one-time** per server (infrastructure and host preparation).
- **Part C is every deployment.** If you are redeploying a code change, start there.
- **Part D is the four acceptance gates.** Run them in order; each one depends on the previous.

Tracker and open risks: [deploy_task.md](deploy_task.md). Architecture: [walkthrough.md](walkthrough.md).

---

## 0. What you are deploying

**One process** that does three jobs at once:

| Job | Where it listens | Who talks to it |
|---|---|---|
| Blazor Server web UI (control panel) | TCP **80**, all addresses | You, from a browser |
| DLMS/COSEM meter fleet | TCP **4059**, `[::]` wildcard | HES, Gurux/GXDLMSDirector |
| DLMS brain (in-process engine) | — | Neither; it sits behind the listener |

"Kestrel" is the web server built into the app — there is no IIS, no nginx, no Apache. Setting
`ASPNETCORE_URLS=http://*:80` is what makes the UI answer at `http://<ip>/` with no port suffix.

**Every meter is one IPv6 address** inside a single `/64`. The low 64 bits of the address are the
meter's index; its serial number (`MY` + 9 digits) is derived from that same index. One kernel route
makes the whole `/64` locally acceptable, so a single listening socket answers for every meter.

**Nothing is persisted.** Batches, meter state, and metrics are RAM-only. A restart is a clean slate
— which is why batches are declared in configuration rather than only clicked into the UI.

### Fill this in once, before you start

Everything below refers back to these values. Keep the filled-in copy with the deployment.

| Value | Example | Yours |
|---|---|---|
| Region / AZ | `ap-south-1` | **`ap-south-1` / `ap-south-1a`** |
| VPC IPv6 `/56` (Amazon-provided) | `2600:1f18:aaaa:bb00::/56` | **`2406:da1a:1c29:500::/56`** |
| Instance subnet `/64` | `2600:1f18:aaaa:bb00::/64` | **`2406:da1a:1c29:500::/64`** |
| **Meter `/64`** (no subnet — routed to the ENI) | `2600:1f18:aaaa:bb01::/64` | **`2406:da1a:1c29:501::/64`** |
| First meter address (index 1) | `2600:1f18:aaaa:bb01::1` | **`2406:da1a:1c29:501::1`** |
| Instance public IPv4 (UI + SSH) | `13.201.x.x` | *(after launch)* |
| Primary network interface | `ens5` | *(confirm via `ip -br addr`)* |
| Access restriction on 80/22 | operator IPs, or open | **open (`0.0.0.0/0` + `::/0`)** — "any laptop" is a requirement; strong passwords are the control |
| App directory | `/opt/maya-sim` | `/opt/maya-sim` |
| Service user / unit | `maya` / `maya-sim.service` | `maya` / `maya-sim.service` |

**How the `/56` was carved.** A `/56` fixes the first 56 bits, so the 4th hex group's low byte
selects the `/64`: this `/56` spans `2406:da1a:1c29:0500::/64` … `2406:da1a:1c29:05ff::/64`, i.e. 256
`/64`s. The subnet took `0500`; meters take `0501`. The remaining 254 are free for a second simulator
host if the fleet is ever sharded across boxes.

> The meter `/64` **must** be a different `/64` from the instance's subnet, and **must not** have a
> subnet created for it. It exists only as a route pointing at the instance.

---

## Part A — AWS infrastructure (one-time)

Console or CLI, whichever you prefer. The CLI forms are given because they are unambiguous.

### A1. VPC with IPv6

Create the VPC with **"Amazon-provided IPv6 CIDR block"** enabled. Record the `/56`.

```bash
aws ec2 describe-vpcs --vpc-ids <vpc-id> \
  --query 'Vpcs[0].Ipv6CidrBlockAssociationSet[].Ipv6CidrBlock'
```

### A2. Subnet for the instance

One subnet using the **first `/64`** of the `/56`. Enable **auto-assign IPv6 address**. Also enable
auto-assign public IPv4 — you need IPv4 for SSH and for the UI URL.

### A3. Internet gateway and default routes

Attach an IGW to the VPC. In the subnet's route table:

| Destination | Target |
|---|---|
| `0.0.0.0/0` | IGW |
| `::/0` | IGW |

### A4. Launch the instance

Ubuntu **24.04 LTS**, **x86_64** (not Arm — the artifact is compiled `linux-x64`). Give it a public
IPv4 *and* an IPv6 address. 30 GiB gp3 root volume.

**Sizing.** RAM is the binding constraint on fleet size — each live meter holds a fully parsed DLMS
object model, and connections are cheap by comparison. But **the template matters more than the
instance type**: the bundled templates span 128 KB to 4.2 MB, a 33× range in per-meter cost, so
testing with `SA1231166HP_values.xml` instead of `Values_SZ0000014HP.xml` buys more headroom than
any instance upgrade.

`t3.micro` (1 GB, free tier) is enough to prove R1–R3 and a small R4 with the 128 KB template.
`host-prep.sh` adds a 2 GB swapfile so overshoot degrades into slowness rather than an OOM kill that
wipes every batch.

**Resizing later is easy, with one gotcha:** stop the instance, change the type, start it. The ENI
survives, so the meter `/64` route (A5) and source/dest setting (A6) are untouched, and the **IPv6
address persists**. But an auto-assigned **public IPv4 changes on every stop/start**. If you want a
stable IPv4 for the UI, allocate an Elastic IP — otherwise prefer the IPv6 URL, which is stable.

### A5 / A6 — why these two exist

A meter address has to survive **four** layers before the app sees it. Two are AWS, two are on the
instance:

```
Gurux laptop / HES  ──TCP──►  [<meter-/64>::2a]:4059
        ▼
  AWS Internet Gateway        knows the /56 belongs to your VPC
        ▼
  ❶ VPC route table           needs:  <meter-/64> → eni-xxx            (A5)
        ▼                     without it: nowhere to deliver → dropped
  ❷ ENI source/dest check     needs:  DISABLED                          (A6)
        ▼                     without it: "not this ENI's address" → dropped
  ❸ Linux kernel              needs:  ip -6 route add local <meter-/64> (B2)
        ▼                     without it: "no route to host"
  ❹ One socket on [::]:4059   accept() → local endpoint = the meter identity
```

The whole design rests on ❸: one `local` route makes 2^64 addresses valid local destinations, so a
single wildcard socket can front the entire fleet without assigning a million addresses to an
interface. ❶ and ❷ exist only because AWS drops the traffic before the kernel ever gets a look.

**Neither A5 nor A6 is needed for R1** — the app binds and serves regardless; it validates the
*format* of `Tcp:AddressPrefix`, never its reachability. They matter the moment something outside the
instance dials a meter (R3, R4). Do them during initial setup anyway: two clicks, no risk, and it
turns R3 into a test rather than a setup session.

**Useful consequence:** ❸ and ❹ are purely local, so the simulator can be proven *from the instance
itself* before AWS routing is involved — see D3's local pre-check. If an external client fails while
the local check still passes, the fault is provably ❶ or ❷, not the app.

### A5. Route the meter /64 to the instance's ENI

Pick a second `/64` from the `/56`. **Do not create a subnet for it.** Add a route to it in the
**main route table and the instance subnet's route table**, targeting the instance's ENI:

```bash
aws ec2 create-route --route-table-id <rtb-id> \
  --destination-ipv6-cidr-block <meter-/64> \
  --network-interface-id <eni-id>
```

### A6. Disable the source/destination check

EC2 anti-spoofing, on by default: AWS drops traffic crossing an ENI where the ENI is neither source
nor destination — which is every meter packet, by definition. Same setting NAT instances and
software routers require. **The single most common reason meters are unreachable.**

```bash
aws ec2 modify-network-interface-attribute \
  --network-interface-id <eni-id> --no-source-dest-check
```

### A7. Security group

| Port | Protocol | Source | Why |
|---|---|---|---|
| 22 | TCP | `0.0.0.0/0` **and** `::/0` | SSH from any laptop. Safe because the Ubuntu AMI is key-only (`PasswordAuthentication no`); exposure costs bot noise in the logs, nothing more. |
| 80 | TCP | `0.0.0.0/0` **and** `::/0` | The UI, from any laptop on any network. See the warning below. |
| 4059 | TCP | `::/0` | HES is in another AWS account; laptops roam. **IPv6 only** — meters have no IPv4 address, and the listener is `IPv6Only`. |
| All ICMP - IPv6 | ICMPv6 | `::/0` | Diagnostics. Not optional in spirit: IPv6 uses ICMPv6 for Path MTU Discovery, and blocking it wholesale black-holes large packets in ways that look like random protocol failures. Also what makes `ping -6` work. |

Both address families are required on 22 and 80: an IPv6-only laptop (Indian mobile networks) and an
IPv4-only laptop (many corporate networks) must both work. The instance therefore keeps its public
IPv4, and the UI answers at `http://<public-ipv4>/` *and* `http://[<public-ipv6>]/`.

> **Port 80 is open, so the password is the only control.** The UI is plain HTTP: role passwords
> cross the internet in clear, and the Blazor circuit is unencrypted. Deliberate trade-off — the
> requirement is browser access from any laptop with no DNS, and IP-pinning defeats that. What makes
> it acceptable is that the passwords are **strong, random, and not the ones committed to git**. Set
> them in `secrets.env` (B4) and never rely on the `appsettings.json` defaults. If this box ever
> holds anything more sensitive than a load-test fleet, revisit with TLS.

### A8. Gate — public IPv6 reaches the VPC

From your laptop, against the instance's **own** IPv6 address (not a meter address yet). Use **TCP**,
not ping:

```bash
Test-NetConnection <instance-own-ipv6> -Port 22
```

`TcpTestSucceeded : True` is the gate. Do not continue until it passes — if it fails, the problem is
A1–A4 (IPv6 assignment, IGW, `::/0` route) and nothing further will work.

> **Do not use `ping` as this gate.** ICMPv6 is a separate protocol from TCP and is dropped unless
> the security group explicitly permits it (A7). A timing-out ping on a correctly configured host is
> the expected result, and reads as a broken network when nothing is wrong. Test with a port that is
> actually open.

---

## Part B — Linux host preparation (one-time)

### B1. Prerequisites and layout

```bash
sudo apt-get update && sudo apt-get install -y libicu74
sudo useradd --system --create-home --shell /usr/sbin/nologin maya
sudo mkdir -p /opt/maya-sim/logs /opt/maya-sim/Templates
sudo chown -R maya:maya /opt/maya-sim
```

`libicu` is needed even by a self-contained build. `Templates/` and `logs/` must be writable by the
service user — template upload from the UI writes into `Templates/`.

### B2. Make the meter /64 local to the kernel

Two settings, both required. Forwarding lets the instance accept traffic for addresses that are not
its own; the `local` route declares every address in the `/64` a valid local destination without
assigning a million addresses to an interface.

```bash
sudo tee /etc/sysctl.d/99-maya-forwarding.conf >/dev/null <<'EOF'
net.ipv6.conf.all.forwarding = 1
EOF
sudo sysctl --system
```

```bash
sudo ip -6 route add local <meter-/64> dev ens5
```

Persist the route across reboots with a tiny unit (netplan cannot express `local` routes):

```bash
sudo tee /etc/systemd/system/maya-meter-route.service >/dev/null <<'EOF'
[Unit]
Description=Local route for the simulated meter /64
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip -6 route add local <meter-/64> dev ens5
ExecStop=/sbin/ip -6 route del local <meter-/64> dev ens5

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now maya-meter-route.service
```

### B3. Scale-final kernel tuning

Applied once, sized for the largest fleet this box will ever hold — per the decision that config is
not re-tuned per test run.

```bash
sudo tee /etc/sysctl.d/99-maya-scale.conf >/dev/null <<'EOF'
# File descriptors — one socket per connected meter, plus headroom
fs.file-max = 4000000
fs.nr_open  = 4000000

# Accept queue. Must be paired with the app's listen backlog (see P0-5) or the
# app's own cap wins and this has no effect.
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# IPv6 route cache — a very large local prefix with many active flows
net.ipv6.route.max_size = 2097152

# Socket memory. Many connections, each with small buffers.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mem  = 786432 1048576 1572864

# Recycle closed sockets promptly during high-churn tests
net.ipv4.tcp_fin_timeout = 15
EOF
sudo sysctl --system
```

If `nf_conntrack` is loaded, it will exhaust its table long before anything else does. Either raise
`net.netfilter.nf_conntrack_max` or, better, do not load iptables/netfilter on this box at all —
the security group is already the firewall.

### B4. The systemd unit

```bash
sudo tee /etc/systemd/system/maya-sim.service >/dev/null <<'EOF'
[Unit]
Description=MAYA Many-Meter Simulator
After=network-online.target maya-meter-route.service
Wants=network-online.target
Requires=maya-meter-route.service

[Service]
# Type=simple, NOT notify: readiness notification would require builder.Host.UseSystemd()
# in Program.cs, which does not exist. With Type=notify and no sd_notify call, systemd
# waits for a signal that never comes and the start times out.
Type=simple
User=maya
WorkingDirectory=/opt/maya-sim
ExecStart=/opt/maya-sim/ManyMeterSimulator
Restart=always
RestartSec=5

# Lets a NON-ROOT user bind port 80. This is why the UI can answer at
# http://<ip>/ without running the app as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE

# One file descriptor per connected meter, plus headroom.
LimitNOFILE=2000000

Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://*:80
Environment=DOTNET_gcServer=1

# Secrets — NOT in appsettings.json. Root-owned, chmod 600.
EnvironmentFile=/etc/maya-sim/secrets.env

[Install]
WantedBy=multi-user.target
EOF
```

With `Type=simple`, systemd reports "active" as soon as the process starts — a moment before the app
is actually listening. So `systemctl is-active` alone is not proof of a good deploy; C5's log and
socket checks are.

Secrets file:

```bash
sudo mkdir -p /etc/maya-sim
sudo tee /etc/maya-sim/secrets.env >/dev/null <<'EOF'
Auth__AdminPassword=<new-strong-password>
Auth__UtilityPassword=<new-strong-password>
Auth__ViewerPassword=<new-strong-password>
EOF
sudo chmod 600 /etc/maya-sim/secrets.env
```

Double underscore (`__`) is how .NET maps an environment variable onto a nested config key —
`Auth__AdminPassword` overrides `Auth:AdminPassword`. **Rotate these**; the values committed in
`appsettings.json` are in git history and must not be what guards a public port.

### B5. Gate — the kernel owns the meter addresses

```bash
ip -6 route get <first-meter-address>
```

The output must contain **`local`**. If it does not, B2 did not take and no meter will ever be
reachable.

---

## Part C — Deploy the application (every deployment)

### C1. Build on the Windows dev box

```bash
dotnet test ManyMeterSimulator/ManyMeterSimulator.Tests/ManyMeterSimulator.Tests.csproj -c Release
```

```bash
dotnet publish ManyMeterSimulator/ManyMeterSimulator/ManyMeterSimulator.csproj -c Release -r linux-x64 --self-contained true -o publish/linux-x64
```

Self-contained means the .NET runtime ships inside the folder — **nothing to install on the server**.
Expect roughly 114 MB / 400+ files. `publish/` is already gitignored.

Record what you shipped, so a rollback knows where to go back to:

```bash
git rev-parse --short HEAD
```

### C2. Ship it

```bash
tar -czf maya-sim.tar.gz -C publish/linux-x64 .
scp maya-sim.tar.gz ubuntu@<public-ipv4>:/tmp/
```

On the server — keep the previous release so C7 is a real option:

```bash
sudo systemctl stop maya-sim
sudo rm -rf /opt/maya-sim.prev && sudo cp -a /opt/maya-sim /opt/maya-sim.prev
sudo tar -xzf /tmp/maya-sim.tar.gz -C /opt/maya-sim
sudo chmod +x /opt/maya-sim/ManyMeterSimulator
sudo chown -R maya:maya /opt/maya-sim
```

> **`chmod +x` is not optional.** The publish is produced on NTFS, which carries no execute bit, so
> the extracted apphost is not runnable until you set it. A missing exit bit shows up as
> `203/EXEC` from systemd.

### C3. Configuration

Write `/opt/maya-sim/appsettings.Production.json`. This overlays `appsettings.json`; the secrets come
from the environment file instead (B4).

```jsonc
{
  "Tcp": {
    "ListenPort": 4059,
    "AddressPrefix": "<meter-/64>",     // MUST match the routed /64 — validated at startup
    "MaxConcurrentConnections": 2000000, // scale-final; default 10,000 is far too low
    "IdleTimeoutSeconds": 300,           // see R-7: match how the HES holds connections
    "IdleSweepIntervalSeconds": 60,
    "MetricsIntervalSeconds": 60,        // one summary line per minute
    "ShutdownDrainSeconds": 10
  },
  "Templates": { "Folder": "Templates" },
  "Brain": {
    "Mode": "Brain",                     // "Simulated" is an echo stub — never in production
    "ClientAddress": 16,
    "ServerAddress": 1,
    "LogicalName": "1.0.0.0.0.255"
  }
}
```

`Tcp:AddressPrefix` is validated at startup and the app **refuses to start** on a bad value — a
deliberate guard, since a wrong prefix means silently unreachable meters rather than a visible error.

If P0-7 (config-seeded batches) has landed, declare the batches here too — that is what makes the
IP↔serial mapping registered in the HES database survive a restart.

### C4. Start

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now maya-sim
```

### C5. Read the startup log — do not skip this

```bash
sudo journalctl -u maya-sim -n 60 --no-pager
```

Four things must be true:

- [ ] `TCP NIC listener bound to [::]:4059`
- [ ] the logged prefix is **your** meter `/64`, not the `fd00:6d65:7472::/64` dev default
- [ ] `Template folder: /opt/maya-sim/Templates` and the templates are present
- [ ] no startup exception

```bash
ss -6 -lntp | grep 4059 && ss -lntp | grep ':80 '
```

### C6. Reboot survival

```bash
sudo reboot
```

After it comes back, both the route unit and the service must be active on their own:

```bash
ip -6 route get <first-meter-address> && systemctl is-active maya-sim maya-meter-route
```

### C7. Rollback

```bash
sudo systemctl stop maya-sim
sudo rm -rf /opt/maya-sim && sudo mv /opt/maya-sim.prev /opt/maya-sim
sudo systemctl start maya-sim
```

Rollback restores the binaries only. **All batches and meter state are lost** on any restart —
whether you roll back or not — so anything the HES has registered depends on the batches being
reproducible from configuration.

---

## Part D — Acceptance gates

Run in order. Each depends on the one before it, so a failure localises cleanly.

### D1 — R1: running on Linux

```bash
systemctl is-active maya-sim
```

Active, after a real reboot (C6). ✅

### D2 — R2: the UI from a browser

Open `http://<public-ipv4>/` from a laptop.

- [ ] Login page renders (CSS and all — a blank/unstyled page means static assets did not deploy)
- [ ] Admin password logs in; the header shows the role
- [ ] Utility and Viewer log in and show correctly reduced controls
- [ ] Add a small batch (10 meters), pick a template, **Start** it
- [ ] Expanding the batch row lists IP↔serial pairs
- [ ] The page updates live — that confirms the Blazor WebSocket connection survived the network path

If the page loads but is frozen or endlessly reconnecting, it is the WebSocket, not the app. Direct
Kestrel needs no special configuration for this — but a proxy in front of it would.

### D3 — R3: Gurux from any laptop

**Local pre-check, on the instance itself.** This exercises layers ❸ and ❹ only (see A5/A6) with no
AWS routing involved, so it cleanly splits "is the simulator working" from "is AWS delivering":

```bash
curl -sv --max-time 5 "http://[<first-meter-address>]:4059" 2>&1 | head -5
```

`Connected to` means the meter is live and the kernel route is good — the HTTP failure after that is
expected, since the port speaks DLMS. If this passes but the laptop cannot reach the same address,
the fault is in AWS (A5 route, A6 source/dest check), not the app.

**Then prove TCP from outside.** From PowerShell on the laptop:

```bash
Test-NetConnection -ComputerName <first-meter-address> -Port 4059
```

`TcpTestSucceeded : True` before you open GXDLMSDirector. If false, the fault is in the network path
(A5/A6/A7/B2), not in DLMS, and no amount of client configuration will fix it.

Then in GXDLMSDirector, with the settings from Part E:

- [ ] Association succeeds
- [ ] The object list reads back
- [ ] OBIS `0.0.96.1.0.255` reports **this** meter's serial (`MY000000001` for index 1)
- [ ] **Repeat against a second meter address** — a different serial comes back. This is the proof
      that per-IP meter identity works, and it is the whole point of the gate.
- [ ] Note which client address you used and which association it landed in (tracker R-5)

✅

### D4 — R4: HES pull

**Order matters here** — network, then registration, then pull. Registering thousands of meters
before proving one packet can arrive wastes a lot of time.

1. **HES-side network.** Its VPC needs IPv6 and an IGW with a `::/0` route, its ENI needs an IPv6
   address, its security group must allow egress TCP 4059 to `::/0`, and the Windows outbound
   firewall must permit it.
2. **Gate — from the HES Windows box itself:**
   ```bash
   Test-NetConnection -ComputerName <first-meter-address> -Port 4059
   ```
   Do not proceed until this is true.
3. **Pin the batch in configuration** (P0-7), restart, confirm the batch is present and Started.
4. **Export the meter list** (P0-6) and load it into the HES database with the credentials from
   Part E.
5. **One meter first.** A single manual pull from the HES against one registered meter.
6. **Then the batch.** ✅ when the HES pulls from ≥2 meters and reconciles each serial against the
   IP it dialled.
7. **Restart-survival:** `sudo systemctl restart maya-sim`, then re-run the same pull **without
   re-registering anything**. If it still works, the registration is genuinely durable.

Watch from the server while the HES runs:

```bash
sudo journalctl -u maya-sim -f
```

The periodic metrics line is the fastest read on what is going wrong:
`accepted` climbing means connections land; `rejectedNoTemplate` means the meter is outside any batch
or its template is missing; `rejectedBatchNotRunning` means the batch was never Started;
`rejectedCollision` means something is already connected to that meter.

---

## Part E — HES / Gurux registration reference

Every meter shares **one** DLMS identity. Only the serial differs. So HES registration is a single
credential set applied to N serials.

### Connection

| Setting | Value |
|---|---|
| Interface / framing | **DLMS WRAPPER over TCP/IP** (IEC 62056-47) — not HDLC |
| Host | the meter's own IPv6 address |
| Port | **4059** |
| Server / logical device address | **1** (fixed for all meters; the IP is the distinguisher) |
| Max PDU size | 65535 |

### Security (identical for every meter)

| Setting | Value |
|---|---|
| Authentication | **High (HLS)** |
| Security policy | Authenticated **and** encrypted |
| Security suite | Suite 0 |
| Server system title | `SIM` + `0x00` + big-endian int32 `1` → `53 49 4D 00 00 00 00 01` |
| Block cipher key (GUEK) | `AAAAAAAAAAAAAAAA` (16 ASCII `A`) |
| Authentication key (GAK) | `AAAAAAAAAAAAAAAA` |
| HLS secret | `AAAAAAAAAAAAAAAA` |
| LLS secret | `12345678` |

Source of truth: [DLMSMeter.cs](MeterSimulator.Core/Models/DLMSMeter.cs) and
`InitializeSecuritySetup` / `InitializeAssociation` in
[DLMSServerSession.cs](MeterSimulator.Core/DLMS/DLMSServerSession.cs).

### Associations

| Association | LN | ClientSAP | Authentication |
|---|---|---|---|
| Public | `0.0.40.0.1.255` | 10 | None |
| Management | `0.0.40.0.0.255` | 30 | High (HLS) |

`Brain:ClientAddress` defaults to **16**, which matches neither declared ClientSAP. GXDLMSDirector is
known to work against this build, so it resolves in practice — **confirm empirically at D3 and record
the working value here** before configuring the HES for a whole fleet (tracker R-5).

### Per-meter values

| Field | Rule | Index 1 | Index 42 |
|---|---|---|---|
| IPv6 address | meter `/64` + index in the low 64 bits | `<prefix>::1` | `<prefix>::2a` |
| Serial (OBIS `0.0.96.1.0.255`) | `MY` + index, 9 digits | `MY000000001` | `MY000000042` |

Both derive from the same index, so the HES can reconcile serial against IP — which is exactly what
D4 verifies. If the HES database constrains serial format, settle that **before** registering
(tracker R-6): changing `FormatSerial` renumbers the entire fleet.

---

## Part F — Troubleshooting

| Symptom | Most likely cause |
|---|---|
| Service fails with `203/EXEC` | Missing execute bit — `sudo chmod +x /opt/maya-sim/ManyMeterSimulator` (C2) |
| Startup throws `Invalid Tcp:AddressPrefix` | Prefix missing, not a `/64`, or has non-zero host bits. Working as designed — fix the value. |
| App will not bind port 80 | `AmbientCapabilities=CAP_NET_BIND_SERVICE` missing from the unit (B4) |
| UI unreachable, service is active | `ASPNETCORE_URLS` still defaulting to localhost, or security group does not allow your IP on 80 |
| UI loads unstyled | `wwwroot/` did not deploy — re-extract the full publish output |
| UI loads then endlessly reconnects | Blazor WebSocket blocked on the network path |
| `ping6` to the instance's own IPv6 fails | A1–A4: IPv6 not assigned, no IGW, or no `::/0` route |
| Instance reachable, meter addresses are not | A6 source/dest check still enabled, A5 route missing, or B2 `local` route missing. Check `ip -6 route get <meter>` reports `local`. |
| Meter reachable by TCP, connection closes immediately | Gate rejection. `journalctl` names which one: no batch, batch not Started, template unresolvable, or a collision with an existing connection. |
| `rejectedNoTemplate` climbing | Meter address outside every batch's range, or the batch's template file is missing from `Templates/` — **filenames are case-sensitive on Linux and were not on Windows** |
| `rejectedCollision` climbing | Two clients on one meter IP. One connection per meter is enforced by design. |
| Association fails, TCP succeeds | Key/auth mismatch (Part E), or the client address lands in the wrong association (R-5) |
| Every meter reports the same serial | Serial override did not apply — inspect the template's `0.0.96.1.0.255` object |
| Connections drop mid-session | `Tcp:IdleTimeoutSeconds` elapsed. Raise it if the HES legitimately idles (R-7). |
| Process vanishes and restarts, batches gone | OOM killer. `sudo dmesg -T \| grep -i oom`. This is the expected ceiling — grow RAM, shrink the batch, or build the SQLite offload. |
| Disk filling fast | Per-frame logging (P0-1/P0-2). Check `du -sh /opt/maya-sim/logs` and `journalctl --disk-usage`. |

### Useful commands

```bash
sudo journalctl -u maya-sim -f                      # live log
sudo journalctl -u maya-sim --since "10 min ago"    # recent history
ss -6 -tn state established '( sport = :4059 )' | wc -l   # live meter connections
sudo systemctl status maya-sim
ps -o rss= -p "$(systemctl show -p MainPID --value maya-sim)"   # RSS in KB
```

`ps -o rss=` before and after starting a batch is how you measure RAM per live meter session
(tracker P6-2) — the number that determines how large a fleet a given instance can hold.

---

## Part G — Deployment record

Copy this per deployment and keep it filled in.

```
Date:                        Deployed by:
Git commit:                  Purpose:
Meter /64:                   Instance type:
Config changed:              Batches configured:
D1 R1 systemd:      pass/fail       D2 R2 UI:        pass/fail
D3 R3 Gurux:        pass/fail       D4 R4 HES pull:  pass/fail
Rollback needed:             Notes:
```
