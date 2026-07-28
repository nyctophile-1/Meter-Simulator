# Linux Deployment — Task Tracker

Taking the merged simulator (Blazor UI + TCP listener + DLMS brain, one process — see
[walkthrough.md](walkthrough.md)) from "works on the dev laptop" to a **dedicated AWS Linux box**
that a browser, a Gurux client, and a real HES can all reach.

For the repeatable step-by-step procedure see [deploy_walkthrough.md](deploy_walkthrough.md).
For the distilled "what was actually needed" list see [deploy_checklist.md](deploy_checklist.md).
This file is the tracker: decisions, checklist, open risks, running log.

**Status 2026-07-27: R1, R2, R3 done.** Service running on Ubuntu 24.04, UI reachable from a browser,
and **GXDLMSDirector associates with a simulated meter from a laptop over public IPv6**. R4 (HES pull)
is unblocked — the network path it needs is the one R3 just proved.

## Goal (the four requirements)

| # | Requirement | Gate |
|---|---|---|
| **R1** | Deployed and running on a Linux server | `systemctl is-active maya-sim` = active, survives reboot |
| **R2** | UI usable from any web browser, no DNS | `http://<sim-public-ipv4>/` loads and logs in from a laptop |
| **R3** | Gurux (GXDLMSDirector) from any laptop can associate with any simulated meter | Full read of a meter's object list from a laptop over public IPv6 |
| **R4** | HES (AWS Windows, other account, public, no VPN) runs pull commands on registered meters | HES pulls a profile from ≥2 registered meters and reconciles serial vs IP |

## Confirmed decisions

- **Topology: cross-account, over the public internet via IPv6.** Sim box on a **new AWS personal
  account**; HES on an existing AWS Windows instance in a **different VPC/account**. No VPN, no
  peering. Both the HES box and the test laptops have working IPv6 — so public IPv6 is the
  transport for all meter traffic, and no IPv4 fallback is needed on the primary path.
- **Meter prefix: a second `/64` carved from the VPC's Amazon-provided `/56`, routed to the sim
  instance's ENI** (not a subnet). Keeps the app's existing `/64` requirement intact — zero code
  change. ENI prefix delegation is the documented fallback (see R-4 in Risks).
- **UI: Kestrel serving HTTP directly on port 80** — reached at `http://<public-ipv4>/`, exactly as
  asked, no port suffix, no DNS, no nginx. Kestrel is the web server built into the app; binding 80
  as a non-root user is handled by a systemd capability, not by running as root.
- **Deploy artifact: self-contained `linux-x64` publish, built on the Windows dev box and copied
  over.** No .NET SDK/runtime install on the server, no CI/CD. **Verified working** — publish
  succeeds, Gurux resolves to non-Windows TFMs (`net60`/`net90`), templates are included, 32/32
  tests pass.
- **Every tunable gets its final, scale-ready value at first deploy.** Explicit user requirement:
  after this deployment, the only levers pulled are RAM/CPU/instance size, or the (unbuilt) SQLite
  offload. Nothing gets re-tuned per test run.
- **OOM is the accepted ceiling.** No pre-emptive RAM-per-session budgeting. Small batches prove the
  basics; the box is grown until it holds the target fleet, or the SQLite offload gets built.
- **Manual deployments.** No pipelines. The walkthrough is the pipeline.

## Deployment invariants

- **The meter `/64` is infrastructure, not a preference.** `Tcp:AddressPrefix` must equal the `/64`
  actually routed to the ENI. It is validated at startup and fails fast — see
  [MeterAddressing.TryValidatePrefix](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterAddressing.cs:15).
- **IP↔serial is a pure function of the meter index**, and the index counter starts at 1 in RAM.
  **The mapping HES registers is only stable if batches are recreated in the identical order and
  size after any restart.** This is why P0-7 (config-seeded batches) is a blocker for R4, not a
  nice-to-have.
- **All meters share one DLMS crypto identity** (GUEK/GAK/HLS = `AAAAAAAAAAAAAAAA`, LLS =
  `12345678`, system title `SIM\0\0\0\0\x01`). Only the serial differs. HES registration is
  therefore uniform across the fleet — one credential set, N serials.
- **One connection per meter at a time**, enforced by `ConnectionRegistry`. A second concurrent
  connection to the same meter IP is rejected, by design (mirrors real meter firmware).
- **Nothing is persisted.** Batches, sessions, metrics are all RAM. A restart is a clean slate.

---

## Checklist

### Phase 0 — Pre-deploy code changes

These are **code-level**, so "just add RAM later" cannot fix them. Given the decision that config is
set once and never re-tuned, they belong before the first deploy, not after.

- [ ] **P0-1 Kill the per-object / per-frame log storm.**
      [DLMSServerSession.cs](MeterSimulator.Core/DLMS/DLMSServerSession.cs) has **27**
      `Console.Write*` calls and [MeterObjectLoader.cs](MeterSimulator.Core/DLMS/MeterObjectLoader.cs)
      has **12** — including one *per DLMS object per session build*
      ([DLMSServerSession.cs:109](MeterSimulator.Core/DLMS/DLMSServerSession.cs:109)). A 4 MB
      template holds thousands of objects, so every new meter emits thousands of synchronous,
      lock-contended console writes, all captured by journald. Additionally
      [TcpNicListenerService.cs:284](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:284)
      and [:302](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:302) log
      at `Information` **twice per DLMS frame**. Route through `ILogger` at `Debug`, or delete.
- [ ] **P0-2 Make the log level configurable.** Serilog's minimum level is hardcoded at
      `Information` in [Program.cs:14](ManyMeterSimulator/ManyMeterSimulator/Program.cs:14) — today
      turning down logging requires a rebuild, which contradicts "set config once". Bind it from
      configuration.
- [ ] **P0-3 Drain `_connectionHandlerTasks`.** It is a `ConcurrentBag<Task>`
      ([TcpNicListenerService.cs:31](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:31))
      that retains one completed `Task` for **every connection ever accepted** and is never cleared
      — unbounded growth across a long load test, and a huge `Task.WhenAll` at shutdown
      ([:88](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:88)).
- [ ] **P0-4 Log unexpected exchange failures.** The session loop catches only
      `OperationCanceled`/`InvalidData`/`SocketException`
      ([TcpNicListenerService.cs:306-328](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:306)),
      and `HandleConnectionAsync` has no catch at all. Anything else — a template failure, a Gurux
      bug, **an `OutOfMemoryException` from `MeterSessionManager.Build`** — faults the connection
      task, which nobody observes, so the connection dies **with no log line**. Since OOM is the
      accepted scaling ceiling, it must at minimum be *visible* when it happens.
- [ ] **P0-5 Make the listen backlog configurable.** Hardcoded `Listen(backlog: 512)`
      ([TcpNicListenerService.cs:60](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs:60))
      caps the accept queue regardless of `net.core.somaxconn`, so connect storms get refused before
      the app ever sees them.
- [ ] **P0-6 Bulk meter export (CSV) per batch. — blocks R4.** HES DB registration needs every
      meter's serial + IPv6; the UI renders at most 50 rows
      ([Setup.razor:126](ManyMeterSimulator/ManyMeterSimulator/Components/Pages/Setup.razor:126)).
      Add a download endpoint streaming `index,serial,ipv6,port` for a batch.
      `MeterRegistry.GetMeters` is already lazy, so this streams without materializing the fleet.
- [ ] **P0-7 Seed batches from configuration at startup. — blocks R4.** Batches live in RAM and
      `_nextIndex` restarts at 1
      ([MeterRegistry.cs:21](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterRegistry.cs:21)),
      so any restart (deploy, reboot, OOM-kill) invalidates every IP↔serial pair already registered
      in the HES database unless the batches are re-added in exactly the same order and sizes.
      Declaring them in `appsettings.Production.json` makes a restart reproducible by construction.
- [ ] **P0-8 Move the three role passwords out of the committed
      [appsettings.json](ManyMeterSimulator/ManyMeterSimulator/appsettings.json:24)** into
      environment variables, and rotate them. They are currently in git history, and the UI will be
      served over plain HTTP on a public port.
- [ ] **P0-9 Resolve the missing `/Error` page.**
      [Program.cs:84](ManyMeterSimulator/ManyMeterSimulator/Program.cs:84) registers
      `UseExceptionHandler("/Error")` for non-Development, but no `/Error` route exists — a path
      that has never executed, because the app has only ever run in Development. Add the page or
      drop the handler.
- [ ] **P0-10 Correct the stale identity docs.** [walkthrough.md](walkthrough.md) §6 documents
      `Brain:PerMeterIdentity` / `Brain:OverrideSerial` flags that **no longer exist** in the code.
      Current behaviour: one fixed shared crypto identity for all meters, serial always overridden
      per meter. R4's registration reference must describe what the code actually does.

### Phase 1 — AWS infrastructure (new sim account)

- [ ] **P1-1** New AWS account; region chosen (same region as the HES account keeps latency sane)
- [ ] **P1-2** VPC created **with an Amazon-provided IPv6 `/56`**; record the `/56`
- [ ] **P1-3** Subnet for the instance using the **first `/64`**; auto-assign IPv6 enabled
- [ ] **P1-4** Internet Gateway attached; subnet route table has `::/0` → IGW and `0.0.0.0/0` → IGW
- [ ] **P1-5** **Meter `/64` chosen** from the same `/56`, deliberately left with no subnet. Record it.
- [ ] **P1-6** Route added: `<meter-/64>` → target = **sim instance's ENI**, in the main route table
      *and* the sim subnet's route table
- [ ] **P1-7** **Source/destination check disabled** on the sim ENI (mandatory — the instance
      receives traffic for addresses that are not its own)
- [ ] **P1-8** Security group: TCP **22** and TCP **80** from `0.0.0.0/0` **and** `::/0` (both
      families — "any laptop" spans IPv6-only mobile and IPv4-only corporate networks); TCP **4059**
      from `::/0` only. See R-2 — this makes password rotation (P0-8) mandatory.
- [ ] **P1-9** Ubuntu 24.04 LTS instance launched, public IPv4 (UI + SSH) and IPv6 both assigned
- [ ] **P1-10** **Verification gate:** from the laptop, `ping6` the instance's *own* IPv6 address.
      Public IPv6 into the VPC works before any meter routing is trusted.

### Phase 2 — Linux host preparation

- [ ] **P2-1** `libicu` installed (self-contained .NET still needs it)
- [ ] **P2-2** Non-root service user + `/opt/maya-sim` with writable `logs/` and `Templates/`
- [ ] **P2-3** `net.ipv6.conf.all.forwarding=1`, persisted
- [ ] **P2-4** `ip -6 route add local <meter-/64> dev ens5`, persisted across reboot
- [ ] **P2-5** Scale-final sysctls applied and persisted (file descriptors, socket backlog, IPv6
      route cache, TCP buffers, conntrack)
- [ ] **P2-6** systemd unit installed: `Restart=always`, `LimitNOFILE` raised,
      `AmbientCapabilities=CAP_NET_BIND_SERVICE` (this is what lets a non-root user bind port 80)
- [ ] **P2-7** **Verification gate:** `ip -6 route get <a-meter-address>` reports `local`

### Phase 3 — Application deploy (R1 + R2)

- [ ] **P3-1** Self-contained `linux-x64` publish produced on the dev box
- [ ] **P3-2** Copied to `/opt/maya-sim`; `chmod +x ManyMeterSimulator` (the exec bit does not
      survive a publish from Windows)
- [ ] **P3-3** `appsettings.Production.json` written with the real meter prefix and scale-final
      values; secrets supplied via the systemd environment file
- [ ] **P3-4** Service enabled and started; boot survival confirmed with a real reboot
- [ ] **P3-5** Startup log verified: bound `[::]:4059`, correct active prefix, template folder found,
      Brain mode (not Simulated)
- [ ] **P3-6** ✅ **R1 gate** — `systemctl is-active maya-sim` active after a reboot
- [ ] **P3-7** ✅ **R2 gate** — `http://<public-ipv4>/` loads from a laptop; login works for all
      three roles; a batch can be added and started

### Phase 4 — Gurux from a laptop (R3)

- [ ] **P4-1** One small batch (e.g. 10 meters) added and **Started** via the UI
- [ ] **P4-2** TCP reachability proven first: `Test-NetConnection <meter-ipv6> -Port 4059` from the
      laptop
- [ ] **P4-3** GXDLMSDirector configured: WRAPPER / TCP-IP, port 4059, meter IPv6 as host, HLS with
      the shared keys (exact values in the walkthrough's registration reference)
- [ ] **P4-4** ✅ **R3 gate** — association succeeds and the object list reads back; **repeat against
      a second meter IP** to prove per-IP routing, and confirm each reports **its own** serial
- [ ] **P4-5** Confirm which client address / association the tool lands in — see R-5 in Risks

### Phase 5 — HES registration and pull (R4)

- [ ] **P5-1** HES-side AWS: its VPC has IPv6 + IGW, its ENI has an IPv6 address, SG egress permits
      TCP 4059 to `::/0`, Windows outbound firewall permits it
- [ ] **P5-2** **Verification gate:** from the HES Windows box,
      `Test-NetConnection <meter-ipv6> -Port 4059` succeeds — *before* touching the HES database
- [ ] **P5-3** Batch defined in `appsettings.Production.json` (P0-7) so the mapping is restart-stable,
      service restarted, batch confirmed present and Started
- [ ] **P5-4** Meter list exported (P0-6) and loaded into the HES database: serial, IPv6, port 4059,
      shared DLMS credentials
- [ ] **P5-5** Single-meter smoke pull from HES before any bulk run
- [ ] **P5-6** ✅ **R4 gate** — HES pulls successfully from ≥2 registered meters and the serial in the
      DLMS payload reconciles against the IP it dialled
- [ ] **P5-7** Restart-survival check: restart the service, re-run the same HES pull **without
      re-registering anything**. Proves P0-7 actually protects the registration.

### Phase 6 — Scale-up

- [ ] **P6-1** Baseline: RSS and startup time with zero meters
- [ ] **P6-2** Measure **RSS delta per live meter session** for the template actually in use (this
      one number determines the fleet a given instance size can hold — a 4 MB template parsed into a
      live object model per meter is the binding constraint, not connections)
- [ ] **P6-3** Grow the batch by ~10× per step, recording RSS, CPU, accepted/rejected counters and
      bridge latency at each step
- [ ] **P6-4** Record the observed ceiling and what hit first (RAM / CPU / file descriptors)
- [ ] **P6-5** Decide from real numbers: bigger instance, shard the prefix across hosts, or build the
      SQLite offload

---

## Risks and open questions

- **R-1 — ~~Does internet-inbound traffic for the meter `/64` reach the ENI?~~ RESOLVED: NO.**
  *(2026-07-27 — materialized and closed; route-based approaches are a dead end)* Two attempts, both
  failed:
  1. **Route `<meter-/64>` → ENI in the subnet's route table.** Rejected outright: *"Route destination
     doesn't match any subnet CIDR blocks."* AWS permits a more-specific-than-local route only when
     the destination exactly matches a subnet CIDR. Worked around by creating a real subnet
     (`maya-sim-meters`, `2406:da1a:1c29:501::/64`, no instances) purely to satisfy validation — the
     route then saved and showed `Active`. Traffic still never arrived.
  2. **IGW edge association** (gateway route table, AWS "ingress routing"). Accepted by AWS; still no
     traffic.

  **Diagnosis is airtight.** `tcpdump -i any -n 'ip6 and dst <meter-addr>'` on the instance shows a
  *complete* TCP handshake for a locally-originated `curl` to a meter address (SYN/ACK/PUSH/FIN, app
  accepts and gates the connection) — so kernel `local` route and app are both correct — while an
  external `Test-NetConnection` to the same address produces **zero** captured packets. AWS discards
  meter traffic at the VPC edge.

  **Root cause:** ingress routing exists to redirect traffic destined for *real* instance addresses
  through an inspection appliance. Meter addresses belong to no ENI, so AWS drops them before any
  route table is consulted. The mechanism does not cover this case. **Do not spend more time on route
  variations.** The path forward is R-4 (ENI prefix delegation).

  *Note: the `dst net <cidr>` form of the tcpdump filter is unreliable for IPv6 — use `dst <address>`.
  An hour was nearly lost to reading a broken filter's silence as a network failure.*
- **R-2 — Plain HTTP on port 80, open to the internet.** *(accepted, 2026-07-27)* Role passwords
  cross the wire in clear and the Blazor circuit is unencrypted. IP-restricting port 80 was proposed
  and **rejected by the user**: browser access from *any* laptop is an original requirement (R2), and
  the operator's own connection is mobile IPv6 with a rotating prefix, so a pinned rule would both
  defeat the requirement and self-inflict lockouts. **The password is therefore the only control**,
  which makes P0-8 (rotate the committed passwords into `secrets.env`) mandatory rather than
  optional — it is config-only, so it lands even under the no-code-change constraint. Revisit with
  TLS if this box ever holds more than a load-test fleet.
- **R-3 — Port 4059 is open to `::/0`.** Required: the HES box's egress IP is in another account and
  laptops roam. It exposes a DLMS server with well-known shared keys to the internet. Narrow to
  known source prefixes if the HES's egress address turns out to be stable.
- **R-4 — ★ NOW THE PRIMARY PATH (R-1 is closed): AWS ENI IPv6 prefix delegation.** AWS attaches an
  IPv6 prefix directly to an ENI and routes it natively — no route-table entry, no source/dest-check
  dependency. This is the mechanism AWS built for "one ENI fronting a large address range" (it is what
  container networking uses), which is exactly this architecture.

  **Blocked on a small code change.** Delegated prefixes are **`/80`, not `/64`**, and the app rejects
  anything that is not a `/64`
  ([MeterAddressing.cs:26](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterAddressing.cs:26)).
  Worse, `ComputeAddress` writes 8 bytes at offset 8
  ([:70](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterAddressing.cs:70)), which under a
  `/80` overwrites two prefix bytes and would silently emit addresses **outside** the delegated range
  — reachable-looking config that quietly doesn't work. Three functions change:
  `TryValidatePrefix` (accept `/64`–`/80`), `ComputeAddress` (mask the index into the available host
  bits rather than clobbering the prefix), `ExtractIndex` (matching inverse). ~30 lines plus tests.
  A `/80` still leaves 2^48 addresses — far past the 999,999,999 serial-format cap, so the scale
  target is unaffected.

  **Rejected alternative:** assigning individual IPv6 addresses to the ENI needs no code change, but
  the per-ENI IPv6 limit is 2 on `t3.micro` and 12 on `t3.large` — enough to prove one meter answers,
  never enough for 100. Does not scale, so not worth the detour.
- **R-5 — Client address vs declared ClientSAP.** `Brain:ClientAddress` defaults to **16**, but the
  associations declare **ClientSAP 10** (public, no auth) and **30** (HLS)
  ([DLMSServerSession.cs](MeterSimulator.Core/DLMS/DLMSServerSession.cs)). GXDLMSDirector is known to
  work against this build, so the current combination evidently resolves — but which association a
  given client address lands in must be pinned down empirically at P4-5 and written into the
  registration reference, otherwise HES gets configured wrong at scale.
- **R-6 — Serial format vs what the HES expects.** Simulated serials are `MY` + 9 digits
  ([MeterRegistry.cs:157](ManyMeterSimulator/ManyMeterSimulator/Provisioning/MeterRegistry.cs:157)).
  If the HES database constrains serial format or length, either the HES side accommodates `MY…` or
  `FormatSerial` changes — and changing it **renumbers the whole fleet**, so decide before P5-4, not
  after.
- **R-7 — Idle timeout vs HES session behaviour.** Connections idle beyond
  `Tcp:IdleTimeoutSeconds` (default 120) are force-closed. If the HES holds a connection open
  between commands, it will see drops that a real meter would not. Pick the final value knowing how
  the HES actually behaves.
- **R-8 — OOM kills the process, not the request.** With OOM accepted as the ceiling, note what
  actually happens: the Linux OOM killer `SIGKILL`s the process and `Restart=always` brings it back
  **empty** — every batch gone. With P0-7 the batches return automatically; without it, silent
  divergence from whatever HES has registered.

## Notes / log

*(append findings, actual values, and surprises here as each phase is executed)*

- **2026-07-27 — R1 and R2 green.** Service active on Ubuntu 24.04 (`t3.micro`), both sockets bound
  (`[::]:4059`, `*:80`), UI reachable from a laptop at `http://<public-ipv4>/`. Zero code changes, as
  scoped. R3/R4 blocked on meter reachability (see R-1).
- **2026-07-27 — testing discipline, learned twice the hard way.** Two false readings cost real time:
  1. `tcpdump 'dst net <cidr>'` is unreliable for IPv6 — its silence was read as "no traffic" when the
     filter simply wasn't matching. Use `dst <address>`.
  2. A prefix-delegation test was reported successful, but the address tested was the **instance's own
     IPv6**, which answers regardless. Prefix delegation was recorded as proven when it had never
     actually been exercised.

  **Rule for every reachability test from here: the address under test must be one that can ONLY work
  via the mechanism being tested** — never the instance's own address, and never an address that
  already worked before the change. State the address explicitly when reporting a result.
- Pre-flight verification on the dev box (2026-07-25): `dotnet publish -r linux-x64
  --self-contained` succeeds → 114 MB / 408 files, `Templates/` included, Gurux resolves to
  `net60` (DLMS) and `net90` (Net) so no WinForms dependency reaches Linux. `dotnet test` → 32/32
  pass. The published apphost has **no execute bit** (NTFS source) — `chmod +x` on the server is a
  required step, not an optional one.
