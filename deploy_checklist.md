# Linux Server Setup — Short Checklist

What was **actually** needed, in hindsight, to get the meter simulator reachable on AWS.
Dead ends removed. For detail see [deploy_walkthrough.md](deploy_walkthrough.md); for the full
history including what failed, [deploy_task.md](deploy_task.md).

**The one thing that makes this work: AWS ENI IPv6 prefix delegation.** Everything else is ordinary
server setup.

---

## A. AWS

- [ ] VPC with **Amazon-provided IPv6 CIDR** (a `/56`)
- [ ] One public subnet, IPv6 enabled, **auto-assign IPv6** and **auto-assign public IPv4** both ON
- [ ] Internet gateway attached; subnet route table has `0.0.0.0/0` → IGW and `::/0` → IGW
- [ ] Security group — 22 and 80 from `0.0.0.0/0` **and** `::/0`; 4059 from `::/0`; **ICMPv6** from `::/0`
- [ ] Launch instance: Ubuntu 24.04 LTS, **x86_64**, key pair selected, 30 GiB gp3
- [ ] **At launch**, under *Advanced network configuration* → **IPv6 prefixes = Auto-assign, count 1**
- [ ] After launch, read the delegated `/80` from **Network Interfaces → ENI → Details → IPv6 Prefix Delegation**

### Not needed — do not repeat these
- ✗ Route table entry sending the meter range to the ENI
- ✗ IGW edge association / gateway route table
- ✗ A separate subnet for the meter range
- ✗ Disabling the ENI source/destination check

All four were tried and none delivered traffic. Prefix delegation registers the range as **owned by
the ENI**, which is what AWS actually checks — route tables only say where to *send* traffic that
AWS has already accepted.

---

## B. Linux host (`deploy/host-prep.sh` does all of this)

- [ ] `libicu` installed — needed even by a self-contained .NET build
- [ ] Service user + `/opt/maya-sim` with writable `logs/` and `Templates/`
- [ ] Swapfile (2 GB) on small instances — turns an OOM kill into a slowdown
- [ ] `net.ipv6.conf.all.forwarding = 1`
- [ ] `ip -6 route add local <delegated-/80> dev ens5`, persisted via a systemd unit
- [ ] Kernel tuning: `fs.file-max`, `somaxconn`, `net.ipv6.route.max_size`, TCP buffers
- [ ] systemd unit: `Type=simple`, `Restart=always`, `LimitNOFILE=2000000`,
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` (lets a non-root user bind port 80),
      `ASPNETCORE_URLS=http://*:80`

---

## C. Application

- [ ] `MeterAddressing` accepts `/64`–`/80` and writes the meter index into the **low 48 bits**
      (delegated prefixes are `/80`; writing the low 64 would overwrite prefix bytes and silently
      emit unreachable addresses)
- [ ] `appsettings.Production.json` → `Tcp:AddressPrefix` = **the delegated `/80`**, exactly
- [ ] Self-contained publish: `dotnet publish -c Release -r linux-x64 --self-contained true`
- [ ] **`chmod +x ManyMeterSimulator`** after extracting — the exec bit doesn't survive a publish from Windows

---

## D. Verify in this order

- [ ] `systemctl is-active maya-sim` → active
- [ ] Log shows `TCP NIC listener bound to [::]:4059` **and the delegated `/80`**, not a default
- [ ] UI loads at `http://<public-ipv4>/` or `http://[<instance-ipv6>]/`
- [ ] From the instance: `ip -6 route get <prefix>::1` contains `local`
- [ ] **From a laptop:** `Test-NetConnection <prefix>::1 -Port 4059` → `True`
- [ ] Batch created and **Started** in the UI; preview addresses match the delegated prefix
- [ ] Gurux/GXDLMSDirector associates with a meter and reads its object list

---

## E. Traps that cost real time

**AWS**
- The IPv6 **prefix** can only be set at launch, or via CLI. The console's *Manage IP addresses* page
  has no prefix section.
- A **base-aligned `/80`** (e.g. `…:500::/80`) is always refused — it overlaps the addresses AWS
  reserves at the start of every subnet. Use auto-assign and make the app fit the prefix.
- "Launch more like this" + expanding *Advanced network configuration* **silently drops auto-assign
  public IPv4 and IPv6**. Set them inside that section.
- Assigning an IPv6 address to a **running** instance needs a **reboot** — Ubuntu only picks it up via
  DHCPv6 at boot.
- An instance with no public IPv4 has no fallback way in if IPv6 breaks. Keep IPv4 on, or be ready to
  attach an Elastic IP.

**Testing**
- The address under test must be one that can **only** work via the mechanism being tested. Testing
  the instance's own IPv6 proves nothing and produces false positives.
- `tcpdump 'dst net <cidr>'` is unreliable for IPv6 — use `dst <address>`. Prove the filter works with
  locally generated traffic before trusting its silence.
- **Fast failure = packet arrived and was refused. Slow timeout = packet never arrived.** Different
  causes, different fixes.
- `ping` is not a substitute for a TCP test — ICMPv6 needs its own security group rule.

**Windows**
- `icacls /inheritance:r` on a **folder** strips access to the files inside. It's the correct fix for
  an SSH key *file* only.
- `$KEY = "$env:C:\..."` — PowerShell parses `$env:C` as an empty variable. No `$env:` before an
  absolute path.
