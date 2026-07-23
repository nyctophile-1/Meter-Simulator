# Meter Simulator — Architecture Walkthrough

This document explains the merged system: how the **NIC/MMS host** and the **DLMS brain** fit
together, how a request flows end to end, where meter state lives, and how to configure and run it.

For the merge task tracker see [merge_task.md](merge_task.md). For the original NIC design rationale
see [ManyMeterSimulator/implementation.md](ManyMeterSimulator/implementation.md).

---

## 1. What this system is

It simulates a large fleet of smart meters so a **HES** (Head-End System) can be load-tested without
physical hardware. HES believes it is talking to up to ~1 billion independent DLMS/COSEM meters, each
reachable at its **own IPv6 address** over TCP on port **4059**.

Two halves, now merged into one process:

| Half | Project | Role |
|---|---|---|
| **NIC / MMS host** | `ManyMeterSimulator` (ASP.NET Core Web) | Blazor control-panel UI, the single TCP listener that fronts every meter IP, batch provisioning, connection lifecycle. |
| **DLMS brain** | `MeterSimulator.Core` (class library) | The Gurux-based DLMS/COSEM server engine: parses requests, applies the meter's object model, produces replies. |
| Shared dep | `Gurux.DLMS.Net`, `Gurux.Net` | DLMS protocol libraries. |
| Test HES | `HESTestClient` | Local stand-in HES that opens sessions and does read exchanges. |

The brain used to be a standalone console app with its own TCP code. In the merge that TCP code was
removed — **the NIC owns all HES-facing networking**, and the brain is called **in-process** as the
engine behind a one-method seam (`IMeterSimBridge`).

---

## 2. Solution layout

```
Meter-Simulator.slnx                 (unified solution: Gurux / Brain / NIC)
├─ Gurux/                            DLMS protocol libraries (unchanged)
├─ MeterSimulator.Core/             THE BRAIN (net10.0 class library)
│   ├─ DLMS/DLMSServerSession.cs     Gurux WRAPPER server: one instance per meter
│   ├─ DLMS/MeterObjectLoader.cs     Loads + normalizes a meter's object model from template XML
│   ├─ Models/DLMSMeter.cs           One meter's identity + live value store
│   ├─ Models/MeterIdentity.cs       Per-meter system title / keys derived from IPv6 index
│   └─ Config/PushConfig.cs          Push settings (push itself is deferred)
└─ ManyMeterSimulator/
    └─ ManyMeterSimulator/           THE HOST (net10.0 ASP.NET Core Web)
        ├─ Program.cs                DI wiring, bridge selection, Blazor + TCP hosted together
        ├─ Networking/               TcpNicListenerService (accept loop, session loop, gating)
        ├─ Framing/                  DlmsWpduFramer + WpduFrame (WPDU length-framing)
        ├─ Brain/                    ★ merge glue
        │   ├─ MeterSessionManager.cs   Authoritative per-meter session store (keyed by IP)
        │   ├─ BrainMeterSimBridge.cs   IMeterSimBridge → brain (the real bridge)
        │   └─ BrainOptions.cs          Client/server address, logical name, bridge mode
        ├─ MqttBridge/               IMeterSimBridge seam + SimulatedMeterSimBridge (echo stand-in)
        ├─ Provisioning/             MeterRegistry (batches), MeterAddressing (IP↔index),
        │                            TemplateRegistry (template XML list/resolve/upload)
        ├─ Components/Pages/Setup.razor  Provisioning UI (batches + template selection/upload)
        ├─ Diagnostics/              ConnectionRegistry, SimulatorMetrics
        └─ Templates/                Meter DLMS template XML files (repo-seeded + uploads)
```

---

## 3. Core concepts

### 3.1 IPv6 address = the meter's identity
Each meter gets one address from an IPv6 `/64` prefix (default `fd00:6d65:7472::/64`). The **host
portion of that address is the meter index** (1-based). This index is the meter's durable identity —
stable for its field life, like a SIM-assigned address that only changes on physical replacement.
Everything about a meter derives from that index:

- **IP address** ↔ **index**: `MeterAddressing.ComputeAddress` / `ExtractIndex`
- **Serial number**: `MeterRegistry.FormatSerial(index)` → `MY` + 9 digits (e.g. `MY000000042`)
- **DLMS crypto identity** (system title, GUEK/GAK/HLS/LLS keys): `MeterIdentity` (see §6)

### 3.2 One listener, many virtual IPs
The host binds **one** socket to `[::]:4059` (wildcard). A host-level route (`ip -6 route add local
<prefix>/64 dev …` on Linux) makes every address in the prefix locally acceptable, so that single
socket accepts connections addressed to any meter IP. On `accept()`, the **local** endpoint address is
the meter HES dialed — that `IPAddress` is the meter key throughout.

### 3.3 Batches — the provisioning unit
Meters aren't created one by one. A **batch** (`Name` + **template** + `N`) reserves a contiguous run
of indices. IP and serial for each meter are computed from the index; nothing per-meter is stored.
Batches have `Start` / `Stop` / `Delete`, and status gates the listener (a Stopped batch's meters are
rejected). A batch is **bound to a template** — see §5.

### 3.4 One meter = one authoritative state
Each live meter has exactly **one** `DLMSServerSession` holding its object model and values, owned by
`MeterSessionManager`, keyed by IP. Both directions use the same instance, so what HES pulls and what a
meter would push always agree. The template is a **seed**: the session is built from it **once**, then
the live model is the source of truth — it is never rebuilt from the template on reconnect (that would
wipe any mutation).

---

## 4. Request flow (end to end)

```
HES  ──TCP──►  [::]:4059  ──►  TcpNicListenerService
                                  │  accept: meterId = local endpoint IP
                                  │  gate: batch exists? Running? template resolvable?   (else reject)
                                  │  register: one session per meter (ConnectionRegistry)
                                  ▼
                            per-connection session loop:
                              DlmsWpduFramer.ReadFrameAsync  →  full WPDU frame (header+payload)
                                  ▼
                              IMeterSimBridge.ExchangeAsync(meterId, fullFrame)
                                  ▼   (BrainMeterSimBridge)
                              MeterSessionManager.GetOrCreate(meterId)   → DLMSServerSession
                                  ▼
                              session.HandleRequest(fullFrame)           → full WPDU reply
                                  ▼
                              write reply bytes back to HES verbatim
                              loop for next frame … until HES closes or idle timeout
```

Key point about framing: the brain is a **Gurux WRAPPER server** — it needs the whole 8-byte WPDU
header (it reads DLMS addresses from it) and returns a complete wrapper reply. So the seam carries the
**full frame** in and out; the listener uses the framer only to find frame boundaries on the stream,
then hands the raw bytes to the brain and writes the brain's reply straight back (no re-wrapping).

---

## 5. Templates

A **template** is a DLMS object-model XML (OBIS values, profiles, associations, push setup). Templates
live in `ManyMeterSimulator/Templates/` (copied next to the app at build) and are also where browser
uploads are saved. `TemplateRegistry` lists/resolves them; a batch stores a `TemplateName`.

Seeded templates:

| File | Notes |
|---|---|
| `SA1231166HP_values.xml` | Values model |
| `SA1231166HP_values_bill.xml` | Values + billing |
| `SZ0000014HP_Only_Push.xml` | Push-only (won't exercise reads while push is deferred) |
| `Values_SZ0000014HP.xml` | Full model (~4 MB) |

**Selecting a template** (Setup page, Admin): pick from the dropdown (any `.xml` in the folder) or
**upload** one via the browser (saved into the folder, auto-selected). Add Batch is disabled until a
template is chosen.

**No template → rejected.** If a connecting meter belongs to no batch, or its batch's template can't be
resolved, the listener refuses the connection (`rejectedNoTemplate` metric). This replaced the earlier
permissive behavior where unassigned meters were accepted.

### Per-meter serial override
Every meter in a batch shares one template, which has a single baked-in serial. On load, the session
rewrites OBIS **`0.0.96.1.0.255`** (Meter Serial Number, a DLMS string) to **this** meter's serial
(`MY…`), so each meter reports a distinct serial that HES can reconcile against the IP.

---

## 6. Per-meter DLMS identity

`Models/MeterIdentity.cs` is the **single source of truth** deriving a meter's crypto identity from its
index, so the simulator and any HES/test client compute identical values:

- `systemTitle(8)` = `"SIM"` (3 bytes) + big-endian low 5 bytes of index
- 16-byte keys = 8-char ASCII label + big-endian 8 bytes of index
  (`GUEKSIM_`→GUEK/block-cipher, `GAK_SIM_`→auth, `HLS_SIM_`→HLS)
- `llsKey(8)` = big-endian 8 bytes of index

This is a simple, replicable scheme — **not** a real KDF. A real HES would get per-meter keys from its
own key management; here both sides share this file.

**DLMS server (lower) address** is deliberately **not** per-meter: routing is already done by IPv6, so
the logical device address stays a fixed configured value (`Brain:ServerAddress`, default 1) and
`DLMSServerSession.IsTarget` accepts whatever the HES dials. The meaningful per-meter distinctness is
the crypto identity above.

---

## 7. Session lifecycle & concurrency

- Sessions are built **lazily on first frame** (`MeterSessionManager.GetOrCreate`), once per meter
  (`Lazy<T>` with execution-and-publication safety), then kept for the process lifetime. Not a cache —
  no eviction/rebuild.
- The listener enforces **one connection per meter** (`ConnectionRegistry`), so a session is only ever
  used by one connection at a time. `BrainMeterSimBridge` additionally `lock`s per session around
  `HandleRequest` (DLMS sessions are stateful/not thread-safe) and offloads the CPU-bound call via
  `Task.Run` so the IO pipeline isn't blocked.
- Idle connections are swept and force-closed after a timeout; a meter outlives any single connection.

---

## 8. Configuration (`appsettings.json`)

```jsonc
"Tcp": {
  "ListenPort": 4059,                    // DLMS wrapper port
  "AddressPrefix": "fd00:6d65:7472::/64" // meter IP prefix — PER-DEPLOYMENT, see below
  // also: IdleTimeoutSeconds, IdleSweepIntervalSeconds, MaxConcurrentConnections,
  //       MetricsIntervalSeconds, ShutdownDrainSeconds
},
"Templates": { "Folder": "Templates" },  // where template XML lives (relative to content root)
"Brain": {
  "Mode": "Brain",                        // "Brain" (real engine, default) | "Simulated" (echo)
  "ClientAddress": 16,                    // DLMS client/HES address
  "ServerAddress": 1,                     // DLMS logical device address (fixed; IP is the key)
  "LogicalName": "1.0.0.0.0.255"
},
"SimulatedBridge": { "RoundTripDelayMs": 500, "MaxRequestsPerSession": 10 }, // only if Mode=Simulated
"Auth": { "AdminPassword": "…", "UtilityPassword": "…", "ViewerPassword": "…" }
```

`Brain:Mode = "Simulated"` swaps the brain for `SimulatedMeterSimBridge`, which just echoes the frame
back after a delay — useful to test framing/session/registry layers without DLMS.

### `Tcp:AddressPrefix` is per-deployment (not hardcoded)
The `fd00:6d65:7472::/64` shipped in `appsettings.json` is only a **ULA example / dev default**. On a
real server it **must** be set to the IPv6 `/64` actually routed to that host (e.g. the AWS ENI-assigned
prefix, paired with `ip -6 route add local <prefix>/64 dev <iface>`). The meter addresses HES connects
to are derived from this prefix, so a wrong value means no meter is reachable. Set it per deployment via:

- `appsettings.Production.json` → `"Tcp": { "AddressPrefix": "<your>::/64" }`, or
- environment variable **`Tcp__AddressPrefix=<your>::/64`** (double underscore).

It is **validated at startup**: must be a valid IPv6 `/64` network address (host bits zero) or the app
fails fast with a clear message (`MeterAddressing.TryValidatePrefix`). The active prefix is logged when
the listener binds.

---

## 9. Running it

- **App (UI + listener):** run the `ManyMeterSimulator` project. Blazor dashboard on the Kestrel URL;
  TCP listener on 4059 in the same process.
- **Provision:** open the dashboard → Setup → choose a template, name a batch, set N, **Add Batch**,
  then **Start** it.
- **Drive traffic:** run `HESTestClient` (local HES stand-in) against the listener.

On Windows, non-loopback meter IPs need the loopback-address + firewall setup described in
implementation.md §4.2; plain loopback (`::1`) works without it. Production is Linux with the kernel
local-route trick.

---

## 10. Deferred (with seams already in place)

- **Push (outbound DataNotification, meter→HES).** The brain's push code stays in the library but no
  timer is wired. When added: a `PushScheduler` drives `DLMSServerSession.StartPush()` over live meters
  from `MeterSessionManager`; `MeterSessionManager.MaterializeBatch(batchId)` (stubbed) will make a
  Started batch's meters live without an inbound connection; and push egress must **bind the outbound
  socket to the meter's own IPv6** (push from meter ABC must originate from ABC's IP, the same IP HES
  pulls from).
- **Persistence / scale.** Per-meter state is in-RAM (test scale). Field scale (millions) backs
  `MeterSessionManager` with SQLite paging behind the same seam — nothing else holds meter state.
- **Batch behavior features** (events, alarms, outages) and per-meter data editing from the UI — all
  target the one authoritative session per meter.
```
