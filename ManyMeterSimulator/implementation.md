# ManyMeterSimulator: Implementation Doc

**Naming**: the product/brand name is **MAYA** — it appears only as UI branding in the Blazor
dashboard (page title, header), nowhere in code. The codebase, solution, and every namespace/class
stay brand-free and descriptive: solution `ManyMeterSimulator.sln`, main project
`ManyMeterSimulator` (namespace root `ManyMeterSimulator.*`). See §10 for the full UI/product
architecture.

## 1. Purpose

Simulate the NIC-card layer between HES and `meter_sim` for load testing. HES believes it is
talking to ~1M independent meters, each reachable at its own IPv6 address over TCP. This service
intercepts those TCP connections, bridges request/response payloads to the existing `meter_sim`
service over MQTT, and returns the response to HES on the same connection.

Scope of this doc: **TCP NIC only**. RF NIC and MQTT/4G NIC simulation are separate, later phases
and are not addressed here.

## 2. Problem Being Solved

HES opens a distinct IPv6 TCP connection per meter (IP:port unique per meter) and does
`stream.write` / `stream.read` against a listener it expects to be running on that meter. Running
one OS-level listening socket per meter (millions) is not viable. We need one process that can
accept connections addressed to any of ~1M distinct IPv6 addresses.

## 3. Architecture

### 3.1 Addressing scheme

- Reserve an IPv6 ULA prefix for the simulated fleet, e.g. `fd00:6d65:7472::/64`.
- Every simulated meter gets one address from this prefix. All meters share **one fixed TCP
  port** (simplifies the problem to "many IPs, one port").
- **The IPv6 address itself is the meter identity.** No separate `unique_id` mapping/lookup table
  is needed — confirmed with the team that `meter_sim` treats the IP as the identifier and does
  not care about a stable meter number (NIC cards/SIMs are swappable in the real world; HES
  already reconciles IP-vs-meterno mismatches independently using the meter number inside the
  DLMS payload).

### 3.2 Single listener over many virtual IPs

- Host-level route: `ip -6 route add local <prefix>/64 dev lo` (or `dev eth0` depending on how
  traffic actually arrives) — tells the kernel every address in the prefix is local, without
  assigning a million interface addresses.
- The .NET service binds **one** `Socket` (`AddressFamily.InterNetworkV6`, `IPv6Only = true`) to
  `[::]:<port>` (wildcard) and listens. Because of the route above, this single socket accepts
  inbound connections addressed to any meter IP in the prefix.
- On `accept()`, `((IPEndPoint)socket.LocalEndPoint).Address` gives the exact address HES dialed
  → that IPAddress (canonical string form) is used directly as the identifier in MQTT
  topics/payloads to `meter_sim`. No dictionary, no encoding scheme.

### 3.3 Wire framing (DLMS/COSEM)

- **Assumption (to confirm before/at start of Phase 3 coding):** payloads use the standard
  DLMS-over-TCP/IP **Wrapper Protocol Data Unit (WPDU)** framing per **IEC 62056-47**: an 8-byte
  header (version, source wPort, destination wPort, payload length) followed by the DLMS APDU.
  This is already length-prefixed, which makes stream parsing straightforward.
- If the real meters instead tunnel raw **HDLC** frames over TCP (flag bytes + FCS, no clean
  length prefix), framing logic changes materially — needs to be confirmed against actual
  `meter_sim` / HES payload samples before Phase 3 is implemented.
- Parsing implemented with `System.IO.Pipelines` for efficient handling of partial reads over TCP.

### 3.4 MQTT bridge to meter_sim

**Confirmed contract (meter_sim side is already built and fixed):**

| | Topic | Notes |
|---|---|---|
| meter_sim subscribes to | `sim_request/+` | |
| meter_sim replies to | `sim_response/{unique_ip}` | |
| NIC sim publishes to | `sim_request/{unique_ip}` | |
| NIC sim subscribes to | `sim_response/+` | |

Both sides get the identity from the **topic** (`topic.Split('/')[1]`), not the payload — the
payload is the raw DLMS APDU bytes only, no envelope/correlation id field. Broker connection
details to be supplied when we implement this (Phase 4).

- On a fully-framed request: publish the raw APDU payload to `sim_request/{unique_ip}`.
- Await the response on `sim_response/{unique_ip}` (single shared subscription to
  `sim_response/+`, dispatched internally by topic suffix to the connection currently registered
  for that IP in `ConnectionRegistry`).
- Re-wrap the response APDU in WPDU framing and write it back on the originating TCP connection.
- Timeout if `meter_sim` doesn't respond within a configurable window.
- **Correlation is IP-only — no wire-level request id, since meter_sim's contract doesn't carry
  one.** Combined with single-session-per-meter enforcement and DLMS being sequential per
  connection, this is safe in the normal case (at most one in-flight request per meter at a
  time). **Known accepted limitation:** in the narrow race where a connection closes with a
  request still in flight and a new connection for the same meter starts before meter_sim's
  (stale) response for the old request arrives, that stale response could be delivered to the
  new session instead of discarded. Not fixable without a wire-level correlation id, which the
  fixed meter_sim contract doesn't support — documented here rather than engineered around.

### 3.5 Connection lifecycle

- One async handler per accepted connection (no thread-per-connection).
- **Sessions are persistent and multi-round-trip, not one-shot.** Real DLMS sessions (e.g. via
  Gurux) open the TCP connection once, then do an arbitrary, variable number of sequential
  request/response exchanges over it before HES closes it. The NIC sim doesn't need to interpret
  any of that sequence (auth handshake, secured requests, etc.) — it's opaque bytes in, opaque
  bytes out, per frame, for as many frames as arrive. The per-connection handler loop reads one
  WPDU frame, bridges it to `meter_sim` over MQTT, writes the response, then loops back to read
  the next frame — repeat until the client closes or the connection is deemed stale.
- `ConcurrentDictionary<IPAddress, ConnectionState>` — **load-bearing, not just observability.**
  Used for:
  - **Single-session-per-meter enforcement**: on accept, `TryAdd(meterId, state)`. Success →
    proceed normally. Failure (entry already exists) → close the new socket immediately, no
    protocol handling. Mimics real meter firmware, which only accepts one concurrent TCP session;
    first connection wins. Entry is removed in a `finally` block when the winning session ends,
    for any reason, so a later reconnect succeeds normally.
  - **MQTT response correlation** across a session's lifetime (see 3.4).
  - **Stale connection cleanup**: track `LastActivity`, updated on every completed read/write.
    A low-frequency background sweep force-closes connections idle past a configurable threshold.
    Per-frame read timeouts would be wrong here — HES can legitimately pause mid-session (e.g.
    during the auth handshake) without the connection being dead.

## 4. Project Structure

**Update**: `ManyMeterSimulator` is now `Microsoft.NET.Sdk.Web` (Phase 9, done) — `Program.cs` uses
`WebApplication.CreateBuilder`, hosts Blazor Server (`AddRazorComponents().AddInteractiveServerComponents()`)
alongside the exact same `TcpNicListenerService` as a hosted `BackgroundService`, unchanged. Verified
running both at once: the TCP listener binds and logs exactly as before, Kestrel serves the dashboard
on `http://localhost:5000`.

```
ManyMeterSimulator/                    (.NET 8, Web SDK — see §10)
  Program.cs                    (WebApplication host; TCP listener + Blazor Server, same process) [done]
  appsettings.json
  Networking/
    TcpOptions.cs                (Tcp:ListenPort, Tcp:AddressPrefix config) [done]
    TcpNicListenerService.cs     (accept loop, session loop, registry wiring) [done]
  Framing/
    WpduFrame.cs                 (parsed frame record) [done]
    DlmsWpduFramer.cs            (WPDU header parse/build, System.IO.Pipelines) [done]
  Diagnostics/
    ConnectionRegistry.cs        (single-session enforcement, response routing) [done]
    ConnectionState.cs           (per-meter session state, LastActivity tracking) [done]
    SimulatorMetrics.cs          (in-memory counters: accepted/rejected/idle-timeouts/
                                   exchanges/bridge latency, logged periodically + at shutdown) [done]
  MqttBridge/
    IMeterSimBridge.cs           (one-method seam: ExchangeAsync(meterId, requestPayload)) [done]
    SimulatedBridgeOptions.cs    (RoundTripDelayMs, MaxRequestsPerSession) [done]
    SimulatedMeterSimBridge.cs   (temporary stand-in - delay + echo, no MQTT) [done]
    MeterSimClient.cs            (real MQTTnet implementation of IMeterSimBridge) [deferred - user will implement]
  Provisioning/
    MeterAddressing.cs           (shared index<->IPv6 address math - byte-level, spans the full
                                   64-bit host portion of a /64; used by MeterRegistry AND
                                   HESTestClient so both generate identical addresses) [done]
    MeterBatch.cs, BatchStatus.cs (batch entity: Name, StartIndex, Count, Status) [done]
    MeterRegistry.cs             (the real provisioning unit is the BATCH, not a flat address
                                   list - AddBatch/TryStart/TryStop/Delete, each batch continues
                                   from wherever the last one left off, capped at MaxIndex =
                                   999,999,999 to match the "MYnnnnnnnnn" 9-digit serial format) [done]
  Components/                    (Blazor Server UI)
    App.razor, Routes.razor      (host page, router, CascadingAuthenticationState + AuthorizeRouteView) [done]
    RedirectToLogin.razor        (unauthenticated -> /login, via NavigateTo forceLoad) [done]
    Layout/MainLayout.razor      (MAYA branding - the only place the brand name appears; shows
                                   current role + log out link when authenticated) [done]
    Layout/LoginLayout.razor     (bare layout for the login page - no session-info to show) [done]
    Pages/Login.razor            (plain HTML form POST, not a Blazor interactive component -
                                   avoids SignalR entirely for the actual sign-in step) [done]
    Pages/Setup.razor            (@attribute [Authorize]; batch name + N inputs (Admin only),
                                   live preview of IP range AND meter# range the next Add Batch
                                   would reserve, batch table with Start/Stop (Utility+) and
                                   Delete (Admin only), click-to-expand IP<->meter# detail) [done]
    Pages/Dashboard.razor        (live connections + metrics, from ConnectionRegistry/SimulatorMetrics) [not started]
  LiveLogSink.cs                 (Serilog sink → in-memory ring buffer the UI reads from) [not started]
  Auth/                          (shared-password-per-role cookie auth) [done]
    AuthOptions.cs                (AdminPassword/UtilityPassword/ViewerPassword, from appsettings.json)
    AppRoles.cs                   (Admin/Utility/Viewer role name constants)
    AuthEndpoints.cs               (POST /login: matches password -> role, grants that role's full
                                   claim set (Admin gets Admin+Utility+Viewer, etc.) so downstream
                                   checks are single IsInRole calls; GET /logout)
  wwwroot/css/site.css           (minimal, utilitarian styling) [done]

ManyMeterSimulator.Tests/               (xUnit)
  DlmsWpduFramerTests.cs         (partial-read, malformed header, EOF handling) [done, 7/7 passing]
  MeterRegistryTests.cs          (addressing boundary/carry-over, sequential batches, cap
                                   enforcement, status transitions) [done, 9/9 passing]

HESTestClient/                    (.NET 8 console app, references ManyMeterSimulator for
                                   DlmsWpduFramer AND MeterAddressing - same address generation
                                   as the real registry, not a separate/divergent scheme)
  Program.cs                     (local HES stand-in: N concurrent meter sessions, each doing
                                   M request/response exchanges, then closing) [done]
```

A second console app, standing in for `meter_sim` over MQTT to test the real bridge in
isolation, is a good idea once Phase 4's real bridge exists — not built yet since
`SimulatedMeterSimBridge` already covers that role internally for now.

### 4.1 Dev environment

Developing on a Windows laptop, deploying to Linux. Plain Windows has no equivalent of the
kernel `local route` trick for a *real* network interface (only a loopback-scoped "weak host
model" trick exists, which never sees externally-arriving HES traffic).

**WSL2 is only needed for two things**: validating the local-route/multi-IP mechanism itself
(accepting connections to an arbitrary address in the prefix, not just loopback), and Phase 6
scale/load testing. Everything else — DLMS framing (Phase 3), MQTT bridge (Phase 4), session
lifecycle and single-session collision handling (Phase 5) — is pure C# logic operating on a
`Socket`/stream that doesn't care whether the address is `::1` or a prefix address, and is fully
buildable and testable on plain Windows against loopback, same as the Phase 2 smoke test.
**Decision: deferred by choice**, not blocking current work. When we do set it up: run the
service inside WSL2 with `networkingMode=mirrored` — a real Linux kernel sharing the host's
network interface directly, so the exact `ip route add local` command used in prod also works
in dev.

### 4.2 Windows loopback multi-address setup (100-meter local milestone)

For the "100 meters, HES-like traffic originating from the same laptop" milestone (see
`HESTestClient`), traffic never leaves the machine, so the plain-Windows loopback trick is
usable — but getting it working took two corrections beyond the original plan:

1. **`netsh add route <prefix> "Loopback Pseudo-Interface 1"` + weak-host-model alone was
   insufficient.** It lets outbound packets to the prefix get sent via loopback, but the
   destination addresses were never *owned* by anything, so nothing accepted them as valid local
   destinations — every connection attempt timed out, confirmed via `Test-NetConnection`
   returning false. Windows doesn't have a real equivalent of Linux's `local` route type (any
   address in the prefix is mine, no ownership needed). **Fix**: assign each address
   individually to the loopback interface —
   `netsh interface ipv6 add address "Loopback Pseudo-Interface 1" <address>` — which makes it a
   genuinely owned local address. Fine at n=100; would not scale to "1 million," which is exactly
   why this was never going to be the long-term answer (that's what the real Linux deployment is
   for).
2. **Windows Firewall's auto-created inbound rule is scoped to the specific exe**, not to
   `dotnet.exe`. Running nic_sim via `dotnet ManyMeterSimulator.dll` puts the listening process behind
   `dotnet.exe`, which has no rule, so packets were silently dropped for non-true-loopback
   addresses (genuine `127.0.0.1`/`::1` traffic is OS-exempt from firewall policy regardless of
   process, which is why every earlier loopback-only test worked without this ever surfacing).
   **Fix**: run the built `.exe` directly (`ManyMeterSimulator.exe`, not `dotnet ManyMeterSimulator.dll`) —
   this is also exactly what Visual Studio's F5/Ctrl+F5 does, so no special handling needed there.

With both fixes applied: 100/100 meters succeeded in ~5.2s (10 sequential exchanges each, ~500ms
apart, all 100 running concurrently), verified against nic_sim's logs showing 100 distinct meter
identities accepted and 100 session-limit closures.

If/when Docker support is added (can be done anytime via VS's "Add → Docker Support" — no need
to decide now): default bridge networking will break the wildcard-accept trick since only
published ports/addresses get NATed through. Will need `--network host` (Linux-only) or a
macvlan/ipvlan network so the container has real presence on the routed prefix.

## 5. Configuration (`appsettings.json`)

- `Tcp:ListenPort` (default 4059, standard DLMS/COSEM wrapper port)
- `Tcp:AddressPrefix` (for logging/validation, not for binding — binding is wildcard)
- `Tcp:IdleTimeoutSeconds` (default 120), `Tcp:IdleSweepIntervalSeconds` (default 30) — idle connection cleanup
- `Tcp:MaxConcurrentConnections` (default 10,000) — backpressure guardrail
- `Tcp:MetricsIntervalSeconds` (default 15) — how often a metrics summary is logged
- `Tcp:ShutdownDrainSeconds` (default 10) — grace window for in-flight sessions on shutdown; the host's own `HostOptions.ShutdownTimeout` is set to this + 5s in `Program.cs` so the host doesn't abandon the drain early
- `SimulatedBridge:RoundTripDelayMs` (default 500), `SimulatedBridge:MaxRequestsPerSession` (default 10) — temporary, only relevant while `SimulatedMeterSimBridge` is in use
- Real MQTT bridge config (broker host/port/credentials, topic templates) — deferred, to be added when the real bridge is implemented
- Logging: Serilog, console + rolling daily file at `logs/nicsim-<date>.log` (configured directly in `Program.cs`, not via `appsettings.json`)

## 6. Key Design Decisions

| Decision | Rationale | Alternative considered |
|---|---|---|
| IPv6 address = `unique_id`, no lookup table | `meter_sim`/HES don't need a stable meter number from the NIC layer; simplest possible design | Bit-pack a numeric id into the address; dictionary lookup — both unnecessary given the confirmed requirement |
| Single wildcard-bound socket + kernel local-route | Standard technique for fronting huge virtual-IP ranges with one listener; avoids per-address bind/interface config | One socket per meter (doesn't scale); DNAT/iptables REDIRECT + `SO_ORIGINAL_DST` (more moving parts, same end result) |
| One fixed TCP port for all meters | Reduces the problem to one dimension (IP only); avoids needing N listening sockets | Per-meter port (would require a listening socket per distinct port value in use) |
| `System.IO.Pipelines` for stream parsing | Efficient handling of partial/fragmented TCP reads without repeated buffer copies | Raw `NetworkStream` + manual buffering |
| Deploy on Linux | The kernel local-route trick for wildcard-accepting a huge IPv6 range is Linux-native and tunable at scale; not well supported on Windows | Windows Server (would need a different/unproven mechanism for the "any IP" listening piece) |
| ~~Worker Service (Generic Host), not ASP.NET Core/Kestrel~~ **SUPERSEDED — see §10** | Originally: this isn't HTTP, raw `Socket` + `BackgroundService` avoids pulling in HTTP machinery we don't need. Reversed once a control-panel UI became a requirement (§10) — ASP.NET Core hosts the exact same `BackgroundService` just as well, and now also serves the dashboard from the same process | Kestrel generic TCP transport via custom `ConnectionHandler` (still not used — our raw `Socket` listener stays as-is, ASP.NET Core just hosts it) |
| WSL2 (mirrored networking) as the primary dev environment | Real Linux kernel, so the prod `local route` trick works identically in dev; plain Windows has no equivalent for real (non-loopback) network interfaces | Windows loopback "weak host model" trick — only helps same-machine testing, never sees real HES traffic |
| .NET 8 LTS now, upgrade to .NET 10 LTS later | Design only uses stable, long-standing APIs (`Socket`, `Pipelines`, `BackgroundService`) with nothing version-pinned, so the bump is a low-risk TFM change whenever convenient | Starting on .NET 10 immediately — no material benefit given current SDK availability |

## 7. Assumptions & Open Questions

- [x] **Framing**: confirmed DLMS/COSEM wrapper (WPDU per IEC 62056-47), Indian smart meter
  profile over TCP/IP — 8-byte header (version, source wPort, destination wPort, length), all
  big-endian `uint16`, followed by the opaque DLMS APDU (NIC sim doesn't need to interpret APDU
  content — that's `meter_sim`'s job).
- [ ] **wPort values**: exact source/destination wPort values HES uses, and whether the response
  frame mirrors them swapped — need a sample captured frame before finalizing Phase 3.
- [ ] **Response correlation**: is `unique_id` (IP) alone sufficient to correlate an MQTT response
  to the right in-flight TCP request, or can a single meter have multiple concurrent outstanding
  requests requiring an additional correlation id?
- [x] **.NET version**: .NET 8 LTS now (`ManyMeterSimulator.csproj`), upgrade to .NET 10 LTS later —
  low risk, see decisions table.
- [ ] **MQTT topic convention**: exact topic naming `meter_sim` expects (per-meter topic vs.
  shared topic with id in payload).
- [ ] Confirm HES-sim ↔ NIC-sim network path so the correct `local route` device (`lo` vs a real
  interface) is used.

## 8. Non-functional Targets

- Concurrency: up to ~1M simultaneous open TCP connections on a single host (further scaled
  horizontally by sharding the address prefix across hosts if one host's limits are reached).
- Deployment target: a dedicated AWS Linux VM (see §10.5) running `nic_sim` + dashboard (+ later
  `brain_sim`) continuously; development and local double-click testing stays on Windows.

## 9. Out of Scope (this phase)

- RF NIC simulation
- MQTT/4G NIC simulation
- `meter_sim` internals (already implemented separately)
- Windows production deployment

## 10. UI & All-In-One Architecture (control plane pivot)

### 10.1 Why

Original plan: headless `nic_sim`, scriptable, deployed to Linux for load testing, controlled via
config files and log files. That's still true for the *engine*, but the deployment target
changed: the dedicated Linux/AWS box (see §10.5) will run `nic_sim` **and** `brain_sim` in one
process, and needs a control surface for things config files don't do well — starting/stopping,
seeing live state, and (later) authoring meter behavior. Inspiration: Kalkitech's Million Meter
Simulator and the Gurux open-source simulator, both of which present the simulation as something
you drive from an application, not just a background process you SSH in to check on.

### 10.2 Why not a native desktop GUI

WinForms/WPF were the first instinct (buttons, dropdowns, textboxes, a console-log panel — a
uTorrent/installer feel) but **neither can run on Linux** — Microsoft never ported the Windows
Forms/WPF rendering layer off Windows; only the .NET runtime itself is cross-platform. Since the
dedicated box for this is Linux and headless (no desktop environment), a native GUI would need
either abandoning Linux or bolting on a desktop environment + remote display just to show a
window — real complexity for no benefit over the alternative below.

### 10.3 Decision: ASP.NET Core + Blazor Server web dashboard

- Runs natively on the Linux box, no desktop environment needed there at all.
- "Use the UI" becomes: open a browser pointed at the box's address, from wherever (laptop,
  anywhere) — this is *more* accessible than a native app would have been, not less.
- Blazor Server specifically (over plain Razor/MVC + hand-rolled JS, or a heavier SPA framework):
  C# end-to-end, live UI updates (connection counts, log panel) come for free over its built-in
  persistent connection — no separate JS layer to maintain. Chosen for "good code experience" +
  speed, per explicit ask; doesn't need to look polished, needs to be fast — Blazor Server adds
  negligible overhead over the raw TCP engine, which is unaffected by the UI's presence.
- **Runs in the same process as `nic_sim`**, not a separate app talking over some API — the
  dashboard reads/controls the actual live `ConnectionRegistry`, `SimulatorMetrics`, and (later)
  `brain_sim` objects directly, in-process. Confirmed: this is not a mock/preview layer, it's the
  real running simulation.
- The original "closing the window shouldn't kill the process, need explicit Quit" instinct
  (uTorrent-style tray behavior) is solved *by* this architecture rather than needing separate
  implementation: the server process on the Linux box runs independently of whether any browser
  tab is open. Closing a tab doesn't stop anything; there's no separate "Quit" action to build.

### 10.4 Auth & data

- **Auth (done)**: two layers. (1) AWS Security Group restricts the dashboard's port to
  the operator's own IP — the DLMS port (4059) stays open to HES, the dashboard port doesn't need
  to be public at all (not done yet - still developing locally, tracked in task.md). (2)
  Implemented: cookie auth, three shared passwords (one per role, not per-user accounts - this is
  a small-team internal tool, not something that needs individual identity/audit trails).
  Permission model, additive: **Viewer** (view only) ⊂ **Utility** (+ Start/Stop) ⊂ **Admin** (+
  Add Batch/Delete). Enforced both in the UI (controls hidden per role) and re-checked
  server-side in the handler methods - never trust client-side hiding alone. Verified live for
  all three roles, including that Utility's Start button genuinely transitions a batch to
  `Running`, not just that the button is visible.
- **Data**: no database for the foundation — live state (connections, metrics, meter registry)
  stays in-memory, same as what's already built. SQLite (lightweight, no separate server process)
  is the natural choice **later**, specifically for large DLMS objects that won't fit in RAM —
  explicitly deferred, not part of the foundation.

### 10.5 Deployment target

The AWS/Linux box (see the AWS setup discussion — VPC with IPv6, `/64` or smaller subnet, IPv6
*prefix* assigned to the instance's ENI for the real `ip route add local` trick, Ubuntu 22.04/24.04
LTS, .NET 8 runtime) is now **dedicated to this application** — nic_sim + (later) brain_sim +
dashboard, all one process, all the time. The Windows laptop remains the dev environment and
keeps the existing double-click console workflow (`dist/ManyMeterSimulator`, `dist/HESTestClient`) for
local testing — an ASP.NET Core app still publishes to a runnable `.exe` on Windows too, so
nothing already built breaks; it just gains a browser-based dashboard alongside the console
output.

### 10.6 brain_sim merge — status

**Deferred.** Real brain_sim code is not being merged in now. `SimulatedMeterSimBridge` (§ Phase
4) continues to stand in. When the merge happens: brain_sim's logic gets called directly in-process
(a new `IMeterSimBridge` implementation making direct calls instead of MQTT), which the existing
seam already supports cleanly — no rework needed in `TcpNicListenerService` when that day comes.

### 10.7 Batches - provisioning unit (done)

The Setup page's real unit of work is the **batch**, not a raw address count: `Name` + `N` →
`Add Batch` reserves a contiguous index range (IP address + meter serial number `MYnnnnnnnnn` per
index, both derived from the same 1-based position - see `Provisioning/MeterAddressing.cs`)
without starting it. Each batch gets independent `Start`/`Stop`/`Delete` controls, and **Stop is
not just a UI label** - it actually gates `TcpNicListenerService`'s accept path, rejecting new
connections to that batch's meters (meters never assigned to any batch keep the old permissive
behavior, so ad-hoc/loopback testing is unaffected). Clicking a batch row expands an IP↔meter#
detail list (capped at 50 shown). Deleting a batch does not reclaim its range - allocation only
ever advances; reclaiming would need a real interval allocator, not worth the complexity for a
"delete, for now" action. Capped at `MeterRegistry.MaxIndex = 999,999,999` ("MY999999999", one
shy of a billion), matching the 9-digit serial format. (Originally 9,999,999/7 digits; bumped
100x — the network layer trivially supports far more than this via the /64's full 64-bit host
space, this cap is purely a property of the serial number format we chose, and `AddBatch` is O(1)
regardless of batch size since it doesn't enumerate meters, so the bump cost nothing structurally.)

A real bug surfaced and got fixed during this work: the original single-IPv6-group address
scheme (`$"{prefix}{index:x}"`) threw `FormatException` past index 65,535 (a hex string longer
than 4 digits isn't a valid IPv6 group) - this crashed the whole Blazor circuit, which looked
like the page silently "getting stuck." Fixed by computing addresses at the byte level instead
(`MeterAddressing.ComputeAddress`), which correctly spans the full 64-bit host portion of a /64;
covered by unit tests at the exact 65,535/65,536 boundary. `HESTestClient` uses the same shared
helper now too, so there's one correct address scheme, not two.

### 10.8 Explicitly future (foundation should not block these, not building them now)

- Real brain_sim merge (§10.6)
- Meter behavior features: events, alarms, power outages, internet outages/bandwidth issues, etc.,
  driven from the UI
- Batch **templates** (which DLMS data model a batch's meters use) — explicitly deferred; depends
  on brain_sim's template logic once merged. The batch entity itself (§10.7) is done and doesn't
  need rework to add this later.
- SQLite for large DLMS objects that don't fit in RAM
- Deploying/managing multiple simulator instances from the UI ("the one testing can connect to the
  linux env and use the UI to deploy new instances etc") — foundation (§10.3) should keep this
  plausible, not implement it yet
- Live dashboard (connections/metrics), console log panel, auth — see task.md Phase 9 for what's
  still outstanding from the original UI foundation scope
