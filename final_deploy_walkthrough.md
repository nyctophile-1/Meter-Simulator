# Meter Simulator — Deployment, With The Theory

The complete picture: what the system is, why the networking works the way it does, and how to
deploy it. Written so someone who wasn't there can deploy this without rediscovering any of it.

Companions: [deploy_checklist.md](deploy_checklist.md) is the one-page version;
[deploy_task.md](deploy_task.md) is the tracker with everything that failed and why;
[walkthrough.md](walkthrough.md) covers the application architecture in depth.

**Reference deployment** (used for concrete examples throughout):

| | |
|---|---|
| Region / AZ | `ap-south-1` / `ap-south-1a` |
| VPC IPv6 | `2406:da1a:1c29:500::/56` |
| Instance subnet | `2406:da1a:1c29:500::/64` |
| **Delegated meter prefix** | **`2406:da1a:1c29:500:bc96::/80`** |
| Meter 1 / meter 100 | `…:bc96::1` / `…:bc96::64` |
| Instance | `t3.micro`, Ubuntu 24.04 LTS |

---

# Part 1 — What the system is

One process (`ManyMeterSimulator`, .NET 10) doing three jobs:

| Job | Listens on | Talks to |
|---|---|---|
| Blazor Server control panel | TCP 80 | Your browser |
| DLMS/COSEM meter fleet | TCP 4059, `[::]` wildcard | HES, Gurux/GXDLMSDirector |
| DLMS brain (in-process engine) | — | Neither — it sits behind the listener |

A **head-end system (HES)** believes it is polling a fleet of independent smart meters, each at its
own IP address. In reality one program answers for all of them.

```
HES / Gurux  ──TCP──►  [::]:4059  ──►  TcpNicListenerService
                                         │  accept(): local endpoint = which meter was dialled
                                         │  gate: batch exists? Running? template resolvable?
                                         ▼
                                   DlmsWpduFramer  →  one complete WPDU frame
                                         ▼
                                   MeterSessionManager.GetOrCreate(meterIp)
                                         ▼
                                   DLMSServerSession.HandleRequest(frame)  (Gurux)
                                         ▼
                                   reply bytes written back verbatim
```

## 1.1 The IP address *is* the meter's identity

This is the load-bearing idea. There is no lookup table mapping connections to meters. When a
connection is accepted, the socket's **local endpoint** — the address the client dialled — *is* the
meter. Everything about that meter derives from it:

```
IPv6 address  ──►  index (low bits)  ──┬──►  serial number   MY000000042
                                       └──►  DLMS session, object model, live values
```

Meter 42 is `<prefix>::2a` and reports serial `MY000000042`, deterministically, forever. No state
needs storing to make that true — which is why a 100-meter registration CSV can be generated offline
with nothing but arithmetic, and why it will match what the server actually serves.

## 1.2 Batches

Meters are provisioned in **batches**: a name, a count, and a DLMS template (an XML object model).
A batch reserves a contiguous run of indices. Nothing per-meter is stored — `AddBatch` is O(1)
whether the batch holds 10 meters or 10 million.

A batch must be **Started** before its meters accept connections. Meters outside any batch are
rejected outright.

---

# Part 2 — The core problem: many addresses, one host

## 2.1 Why you can't just assign the addresses

The obvious approach — give the network interface all the meter addresses — fails immediately. AWS
caps IPv6 addresses per interface by instance type: **2 on `t3.micro`, 12 on `t3.large`**. Even the
largest instances top out around 50. You need thousands or millions.

## 2.2 The Linux answer: one route, 2⁶⁴ addresses

```bash
ip -6 route add local 2406:da1a:1c29:500:bc96::/80 dev ens5
```

The `local` route type tells the kernel *"every address in this range is mine — treat it as a valid
local destination."* One route covers the entire block. Nothing is assigned to any interface.

Then a single socket bound to the wildcard `[::]:4059` accepts connections to **any** of those
addresses, and `accept()` reports which one was dialled.

This capability is why production is Linux. Windows has no equivalent — it requires assigning each
address individually (`netsh interface ipv6 add address`), which is what caps the Windows dev setup
at ~100 meters.

**Consequence worth internalising:** `ip -6 addr show` will **not** list your meter addresses. They
are not interface addresses. Check with `ip -6 route get <address>` instead — the output must
contain the word `local`. `ip -6 route show` won't show it either; `local` routes live in a separate
routing table (`ip -6 route show table local`).

---

# Part 3 — How AWS delivers packets

This is the part that is genuinely counter-intuitive, and it cost a full day.

## 3.1 A VPC is not a network — it is a lookup table

On ordinary Ethernet, a machine claims an address and announces it via neighbour discovery.
Delivery is discovery-based and somewhat self-organising.

**AWS works nothing like that.** A VPC is software-defined: every delivery decision is a lookup in
tables AWS maintains. No broadcast, no discovery. If AWS has not been told where an address lives,
the packet is dropped — silently, with no log anywhere.

## 3.2 Ownership is checked before routing

For traffic arriving from the internet, AWS asks:

> *Which network interface in this VPC **owns** this address?*

That is an **ownership** lookup, not a routing lookup. The register it consults is built only when
addresses (or prefixes) are **assigned to an interface**. Nothing else adds to it.

Only after ownership resolves does anything else — route tables, security groups — come into play.

## 3.3 Why route tables cannot solve this

A route table entry says *"traffic for range X → send it to interface Y."* That is a **delivery
instruction**, and it is consulted for traffic **leaving** a subnet.

For internet-inbound traffic, AWS never reaches that step for an unowned address. The packet fails
the ownership lookup and is discarded first. The route is correct; it simply sits behind a door the
packet never opens.

**The office-building analogy:**

- The route table is an instruction to the mailroom: *"mail for floors 10–20 goes to this tenant."*
- But security at the front desk checks every letter against a register of who works in the
  building. A letter addressed to "Room 1547" is rejected there, because nobody by that room number
  is registered.
- The mailroom instruction was fine. The letter never got past the front desk.

Four variations were tried against the reference deployment; **all four failed**:

| Attempt | Result |
|---|---|
| Route `<meter-/64>` → ENI in the subnet's route table | Rejected: *"destination doesn't match any subnet CIDR blocks"* |
| Created a real subnet to satisfy that, then added the route | Saved, showed `Active` — **no traffic** |
| IGW **edge association** (gateway route table / ingress routing) | Accepted by AWS — **no traffic** |
| Disabling the ENI source/destination check | Necessary for the route approach, irrelevant once it failed |

Ingress routing exists to redirect traffic destined for **real instance addresses** through an
inspection appliance. Meter addresses belong to no interface, so there is nothing to redirect.

## 3.4 What actually works: ENI prefix delegation

```
EC2 → Launch instance → Advanced network configuration → IPv6 prefixes: Auto-assign, count 1
```

AWS attaches a **`/80` prefix** to the network interface. This writes into the **ownership**
register: *"this entire range belongs to this interface."* Delivery then follows automatically.

What disappears as a result:

- ✗ No route table entries
- ✗ No edge associations
- ✗ No extra subnet
- ✗ **No source/destination check change** — the interface genuinely *is* the destination now

Registering ownership was always the right operation. Routing was the wrong tool.

## 3.5 The four layers, end to end

```
Gurux laptop / HES  ──TCP──►  [2406:da1a:1c29:500:bc96::2a]:4059
        ▼
  Internet (BGP)          AWS advertises the block containing your /56 from AS16509.
        ▼                 You advertise nothing — you inherit this.
  AWS edge / IGW          Internal lookup: which VPC owns this /56?
        ▼
❶ Ownership lookup        The /80 is REGISTERED to your ENI  ← prefix delegation
        ▼                 Without this: dropped, silently, no log
❷ Security group          Inbound TCP 4059 from ::/0 permitted
        ▼
❸ Linux kernel            ip -6 route add local <prefix> dev ens5
        ▼                 Without this: "no route to host"
❹ Socket on [::]:4059     accept() → local endpoint = the meter identity
        ▼
  MeterSessionManager  →  that meter's DLMSServerSession
```

❶ and ❷ are AWS. ❸ and ❹ are the instance.

**This split is your diagnostic tool.** ❸ and ❹ are purely local, so you can prove the simulator
works from the instance itself, with no AWS involvement:

```bash
curl -sv --max-time 5 "http://[2406:da1a:1c29:500:bc96::1]:4059" 2>&1 | head -5
```

`Connected to` means ❸ and ❹ are good — the HTTP error afterwards is expected, since the port speaks
DLMS. If that passes but an external client cannot reach the same address, the fault is provably ❶
or ❷, and no amount of application debugging will help.

## 3.6 Why your addresses are reachable from the internet at all

You never advertised anything. APNIC allocated a large block to Amazon; Amazon announces it via BGP
from AS16509; every network on the internet learned that route long before your account existed.
When you selected "Amazon-provided IPv6 CIDR block," AWS carved your `/56` from that already-routed
space and recorded which VPC owns it.

**This is why the meter prefix must come from your VPC's `/56`.** Pick an arbitrary range and the
internet will faithfully deliver it to whoever actually owns it.

---

# Part 4 — The address math

## 4.1 Index into address

A meter's index is written into the **low 48 bits** of the prefix:

```
Prefix   2406:da1a:1c29:0500:bc96:0000:0000:0000  /80
                                    └──────────────┘
bytes    0                    9  10              15
         └── prefix, AWS owns ─┘  └── index, 48 bits ─┘

index 1   →  2406:da1a:1c29:500:bc96::1
index 100 →  2406:da1a:1c29:500:bc96::64      (100 = 0x64)
```

## 4.2 Why 48 bits and not 64

The original code wrote a 64-bit index into bytes 8–15, which is correct for a `/64`. Under a `/80`,
**bytes 8–9 belong to the prefix** (`bc96` above). Overwriting them produces addresses outside the
delegated range — addresses that look plausible, that the app happily serves, and that are
completely unreachable.

Narrowing the index to the low 48 bits (bytes 10–15) leaves the prefix intact and supports both
prefix lengths from one code path.

**Nothing is lost.** 48 bits is 281 trillion addresses; the serial format `MY` + 9 digits caps the
fleet at 999,999,999. And because indices in the supported range never set bytes 8–9 anyway,
`/64` addresses are bit-for-bit identical to before the change.

Implemented in [MeterAddressing.cs](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterAddressing.cs):
`TryValidatePrefix` accepts `/64`–`/80` and requires all host bits zero; `ComputeAddress` and
`ExtractIndex` operate on bytes 10–15.

## 4.3 The base-alignment trap

A `/80` whose bytes 8–9 are zero — e.g. `2406:da1a:1c29:500::/80` — would let the original code work
unchanged. **AWS always refuses it:**

```
The prefix 2406:da1a:1c29:500::/80 in subnet subnet-… overlaps with reserved addresses.
```

A base-aligned `/80` is by definition the first `/80` of a subnet, so it always contains the
addresses AWS reserves at the start of every subnet. There is no way around it — hence the code
change is mandatory, not optional.

## 4.4 Config must match reality, exactly

`Tcp:AddressPrefix` must equal the delegated prefix character for character. It is validated at
startup and the app **refuses to start** on a malformed value — deliberate, because a wrong prefix
produces silently unreachable meters rather than a visible error. A *valid but wrong* prefix will
start happily and serve nothing, so check the logged prefix after every deploy.

---

# Part 5 — What the HES needs

## 5.1 One identity, many serials

Every meter shares **one** DLMS cryptographic identity. Only the serial differs. Registration is
therefore a single credential set applied to N serials.

| Setting | Value |
|---|---|
| Framing | **DLMS WRAPPER over TCP/IP** (IEC 62056-47) — not HDLC |
| Port | **4059** |
| Server / logical device address | **1** (fixed — the IP is the distinguisher) |
| Max PDU size | 65535 |
| Authentication | **High (HLS)** |
| Security policy | Authenticated **and** encrypted, Suite 0 |
| System title | `53 49 4D 00 00 00 00 01` (`"SIM"` + `0x00` + BE int32 `1`) |
| GUEK / GAK / HLS secret | `AAAAAAAAAAAAAAAA` (16 ASCII `A`) |
| LLS secret | `12345678` |

Associations: public `0.0.40.0.1.255` (ClientSAP 10, no auth); management `0.0.40.0.0.255`
(ClientSAP 30, HLS). `Brain:ClientAddress` defaults to 16, which matches neither declared ClientSAP —
GXDLMSDirector works against this build regardless, but **confirm the working client address against
one meter before configuring a fleet.**

Source of truth: [DLMSMeter.cs](MeterSimulator.Core/Models/DLMSMeter.cs) and
`InitializeSecuritySetup` / `InitializeAssociation` in
[DLMSServerSession.cs](MeterSimulator.Core/DLMS/DLMSServerSession.cs).

## 5.2 Per-meter serial

Each meter's session rewrites OBIS **`0.0.96.1.0.255`** to its own serial, so the HES can reconcile
the serial in the DLMS payload against the IP it dialled. Both derive from the same index, so they
always agree.

## 5.3 Generating the registration list

Because addressing is pure arithmetic, the meter list can be produced offline — no export endpoint
needed:

```powershell
$prefix = '2406:da1a:1c29:500:bc96::'
$base = [System.Net.IPAddress]::Parse($prefix).GetAddressBytes()
1..100 | ForEach-Object {
  $b = $base.Clone()
  for ($k = 0; $k -lt 6; $k++) { $b[10+$k] = [byte](([int64]$_ -shr (40 - 8*$k)) -band 0xFF) }
  [pscustomobject]@{ serial = 'MY{0:D9}' -f $_; ipv6 = ([System.Net.IPAddress]::new($b)).ToString(); port = 4059 }
} | Export-Csv meters.csv -NoTypeInformation
```

## 5.4 Restart caveat — important before you register

Batches live **in RAM** and the index counter restarts at 1. Recreating an identical *first* batch
reproduces identical addresses and serials, so a restart is survivable today. That stops being true
once you have multiple batches whose creation order must be replayed exactly. Declaring batches in
configuration (tracker item P0-7) is what makes registration durable at that point.

---

# Part 6 — Deploying

## 6.1 Build (Windows dev box)

```bash
dotnet test ManyMeterSimulator/ManyMeterSimulator.Tests/ManyMeterSimulator.Tests.csproj -c Release
```

```bash
dotnet publish ManyMeterSimulator/ManyMeterSimulator/ManyMeterSimulator.csproj -c Release -r linux-x64 --self-contained true -o publish/linux-x64
```

Self-contained means the .NET runtime ships inside the folder — **nothing to install on the server**.
~114 MB, ~48 MB compressed.

Set `Tcp:AddressPrefix` in `deploy/appsettings.Production.json` to the delegated `/80`, copy it into
the publish folder, and tar it.

## 6.2 Ship and run

```bash
scp -i <key.pem> publish\maya-sim.tar.gz deploy\host-prep.sh deploy\deploy.sh ubuntu@[<instance-ipv6>]:/tmp/
```

```bash
sudo bash /tmp/host-prep.sh
```

```bash
sudo bash /tmp/deploy.sh /tmp/maya-sim.tar.gz
```

[host-prep.sh](deploy/host-prep.sh) is one-time: libicu, service user, swapfile, IPv6 forwarding,
kernel tuning, the `local` route, and both systemd units. [deploy.sh](deploy/deploy.sh) runs every
deployment: snapshot the previous release, extract, `chmod +x`, start, verify.

## 6.3 Two details that will bite

**`chmod +x`** — the publish is produced on NTFS, which carries no execute bit. Without it systemd
fails with `203/EXEC`. `deploy.sh` handles it.

**`AmbientCapabilities=CAP_NET_BIND_SERVICE`** in the systemd unit is what lets a non-root user bind
port 80, so the UI answers at `http://<ip>/` with no port suffix and without running as root.

`Type=simple`, not `notify` — readiness notification would need `builder.Host.UseSystemd()` in
`Program.cs`, which doesn't exist; with `notify` the start would hang and time out.

---

# Part 7 — Verification, in order

Each step depends on the previous, so failures localise.

| # | Check | Where |
|---|---|---|
| 1 | `systemctl is-active maya-sim` → active | instance |
| 2 | Log shows `TCP NIC listener bound to [::]:4059` **and the delegated `/80`** | instance |
| 3 | `ip -6 route get <prefix>::1` contains `local` | instance |
| 4 | `curl "http://[<prefix>::1]:4059"` → `Connected to` | instance |
| 5 | UI loads at `http://<public-ipv4>/` or `http://[<instance-ipv6>]/` | laptop |
| 6 | `Test-NetConnection <prefix>::1 -Port 4059` → `True` | **laptop** |
| 7 | Batch created + **Started**; preview addresses match the prefix | UI |
| 8 | Gurux associates and reads the object list; serial matches the index | laptop |
| 9 | Same TCP test, then a pull | **HES box** |

Steps 3–4 prove the instance. Step 6 proves AWS. Step 8 proves DLMS. Keep them separate.

## Reading the logs

`journalctl -u maya-sim -f` during a test. The periodic metrics line is the fastest read:

| Counter | Meaning |
|---|---|
| `accepted` climbing | Connections are landing — network is fine |
| `rejectedNoTemplate` | Meter outside any batch, or its template file is missing (**filenames are case-sensitive on Linux and were not on Windows**) |
| `rejectedBatchNotRunning` | Batch was never Started |
| `rejectedCollision` | Something is already connected to that meter — one connection per meter is enforced by design |

A rejection line is **good news** during network testing: it means the connection arrived and was
processed.

---

# Part 8 — What actually limits scale

**RAM, and it isn't close.** Each live meter holds a fully parsed DLMS object model. Connections are
cheap by comparison.

**The template matters more than the instance type.** The bundled templates span 128 KB to 4.2 MB — a
33× range in per-meter cost. Choosing `SA1231166HP_values.xml` over `Values_SZ0000014HP.xml` buys
more headroom than any instance upgrade.

Measure rather than estimate:

```bash
ps -o rss= -p "$(systemctl show -p MainPID --value maya-sim)"
```

Before and after starting a small batch. The delta × target count is your required RAM.

**Resizing is easy, with one gotcha:** stop, change type, start. The ENI survives, so the delegated
prefix and all routing are untouched, and the **IPv6 address persists**. But an auto-assigned
**public IPv4 changes on every stop/start**.

Beyond RAM, four code-level items cap useful scale and cannot be fixed by resizing — logging volume
(39 `Console.Write` calls, some per DLMS object per meter), an unbounded task collection, swallowed
exchange exceptions, and a hardcoded listen backlog. All are tracked as Phase 0 in
[deploy_task.md](deploy_task.md).

---

# Part 9 — Traps

**AWS**
- The IPv6 **prefix** can only be set at launch or via CLI — the console's *Manage IP addresses* page
  has no prefix section.
- A **base-aligned `/80`** is always refused (§4.3).
- "Launch more like this" + expanding *Advanced network configuration* **silently drops auto-assign
  public IPv4 and IPv6**.
- Assigning an IPv6 address to a **running** instance requires a **reboot** — Ubuntu configures IPv6
  via DHCPv6 at boot only.
- An instance with no public IPv4 has **no fallback way in** if IPv6 breaks. Keep IPv4 enabled, or be
  ready to attach an Elastic IP.
- CloudShell is unavailable for ~2 days on brand-new accounts, and a restricted IAM user may not be
  able to create CLI access keys. Plan the console path accordingly.

**Testing**
- **The address under test must be one that can only work via the mechanism being tested.** Testing
  the instance's own IPv6 proves nothing and produces confident false positives.
- `tcpdump 'dst net <cidr>'` is unreliable for IPv6 — use `dst <address>`, and prove the filter works
  with locally generated traffic before trusting its silence.
- **Fast failure = arrived and refused. Slow timeout = never arrived.** Different causes.
- `ping` is not a TCP test — ICMPv6 needs its own security group rule, and its absence makes a
  healthy host look dead.

**Windows**
- `icacls /inheritance:r` on a **folder** strips access to the files inside; it is the correct fix for
  an SSH key **file** only.
- `$KEY = "$env:C:\..."` — PowerShell parses `$env:C` as an empty variable. No `$env:` before an
  absolute path.
- Publishing from NTFS loses the execute bit (§6.3).

---

# Part 10 — Security posture

Recorded plainly, because it was a deliberate decision rather than an oversight.

- **Port 80 is open to the internet, over plain HTTP.** Role passwords cross the wire in clear.
  IP-restricting it was proposed and rejected: browser access from *any* laptop is a requirement, and
  the operator's connection is mobile IPv6 with a rotating prefix. **The password is therefore the
  only control**, which makes rotating the git-committed defaults into `secrets.env` mandatory rather
  than optional.
- **Port 22 open to the internet is fine** — the Ubuntu AMI is key-only (`PasswordAuthentication no`).
- **Port 4059 is open to `::/0`**, exposing a DLMS server with shared, in-repo keys. Narrow it to
  known source prefixes once the HES's egress address is known to be stable.
- Revisit with TLS if this host ever carries anything beyond a load-test fleet.
