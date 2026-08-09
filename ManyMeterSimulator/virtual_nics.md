# Virtual NICs — Design & Task List

Status: **design, not yet implemented**. Branch `virtual-nics`.

Companion to `implementation.md` (architecture) and `task.md` (delivery). This document covers the
generalisation of the simulator from "a TCP NIC simulator" to "a NIC-virtualisation platform" that
supports five NIC variants sharing one meter brain.

| # | NIC variant | Transport | Status |
|---|-------------|-----------|--------|
| a | RF MQTT Wirepas | MQTT, via gateway | to build |
| b | RF MQTT Kmesh | MQTT, via gateway | to build |
| c | 4G MQTT | MQTT, direct | to build |
| d | 4G IMG MQTT | MQTT, direct (gateway meter) | to build |
| e | 4G TCP | TCP | **done** (`TcpNicListenerService`) |

Only the **pull** direction is in scope (HES polls, meter answers). Push stays deferred.

---

## 1. What the TCP NIC does today — the exact seam

`TcpNicListenerService` is ~340 lines and does eight distinct jobs. Naming them is the whole design,
because only three are TCP-specific:

| Job | TCP-specific? | Where it goes |
|-----|---------------|---------------|
| 1. Bind/accept sockets, one wildcard socket for the whole /64 | **yes** | stays in the TCP NIC |
| 2. Derive the meter identity from the transport (`localEndPoint.Address`) | **yes** | per-NIC address plan |
| 3. Deframe the wire into complete DLMS wrapper frames (`DlmsWpduFramer`) | **yes** (byte-stream only) | per-NIC codec |
| 4. Admission gates: batch exists → batch Running → template resolvable → under max-concurrency → no duplicate session | no | shared `MeterAdmission` |
| 5. Session registry (one live session per meter) | no | shared, generalised `SessionRegistry` |
| 6. Idle sweep | no | shared |
| 7. Metrics + periodic summary log | no | shared, gains a NIC dimension |
| 8. **The funnel**: `bridge.ExchangeAsync(meterId, fullWrapperFrame)` → write reply verbatim | no | **unchanged** |

Job 8 is already the right shape for this. `IMeterSimBridge` takes a *complete DLMS wrapper frame*
and returns a *complete DLMS wrapper frame*, and the listener writes it back byte-for-byte without
interpreting it. That contract is transport-agnostic today; MQTT NICs reuse it as-is.

The chain from wire to brain is currently:

```
localEndPoint.Address (IPAddress)
  → MeterRegistry.GetBatchForAddress(ip)          // MeterAddressing.ExtractIndex(ip) internally
  → IMeterSimBridge.ExchangeAsync(ip, frame)
  → MeterSessionManager.GetOrCreate(ip)           // ExtractIndex(ip) again → DLMSMeter(index)
```

`IPAddress` is threaded through four layers, but **every one of them only actually wants the meter
index**. The IP is a *derived function* of the index (`MeterAddressing.ComputeAddress`), not the
identity itself — `MeterSessionManager.Build` already calls `ExtractIndex` to get back to the real
thing. That is the one refactor this work needs (§4), and it is small.

### Two properties of TCP that MQTT does not give us for free

- **A connection bounds a session.** Accept → serialized request/response loop → close. That single
  socket guarantees (i) exactly one in-flight request per meter, (ii) strict ordering, (iii) an
  explicit end-of-session. MQTT has none of these; §6 rebuilds them.
- **The OS routes to the meter.** The `/64` local route plus the wildcard socket means the kernel
  hands us per-meter identity for free. MQTT NICs need no host networking at all — no prefix, no
  route, no `Tcp:AddressPrefix` validation. That is an operational simplification, not a loss.

---

## 2. Design principle

> One brain funnel, many NIC front-ends. A NIC variant contributes **only**: which topics it owns,
> how to get `(nodeId, dlmsFrame)` out of a message, and how to turn `(dlmsFrame)` back into
> messages. Nothing else.

Everything below the funnel — admission, sessions, brain, templates, batches, metrics, UI — is
shared and NIC-agnostic. If a new codec needs to touch anything outside its own file, the seam is
in the wrong place.

---

## 3. Target architecture

```
                 ┌──────────────────────────────────────────────────────┐
   TCP :4059 ───▶│ TcpNicListenerService     (job 1–3, TCP-specific)    │
                 └──────────────────────────────────────────────────────┘
                 ┌──────────────────────────────────────────────────────┐
  MQTT broker ──▶│ MqttNicListenerService<TCodec>   one per variant     │
                 │   ├─ MqttNicClient      connect / subscribe / publish│
                 │   ├─ INicCodec          ◀── BLACK BOX (topics+wrap)  │
                 │   └─ NodeDispatcher     per-node ordered mailbox     │
                 └──────────────────────────────────────────────────────┘
                                        │
                                        │  MeterRef { Index, Nic, Address }
                                        │  + complete DLMS wrapper frame
                                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │ MeterAdmission     batch? running? template? cap? duplicate?  │
        │ SessionRegistry    one live session per meter, idle sweep     │
        │ SimulatorMetrics   counters, now dimensioned by NIC           │
        └───────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │ IMeterSimBridge → MeterSessionManager → DLMSServerSession     │
        │                  ** completely unchanged **                   │
        └───────────────────────────────────────────────────────────────┘
```

### Project layout

```
Networking/
  Nic/
    NicType.cs                  enum: Tcp4G, Mqtt4G, Mqtt4GImg, MqttWirepas, MqttKmesh
    MeterRef.cs                 (long Index, NicType Nic) + computed NodeId
    IMeterAddressDisplay.cs     index → displayed address, per NIC (UI/preview only)
    MeterAdmission.cs           jobs 4 — hoisted out of the TCP listener
    SessionRegistry.cs          job 5 — was ConnectionRegistry, keyed by Index
  Tcp/
    TcpNicListenerService.cs    (moved; jobs 1–3 only after the hoist)
    TcpOptions.cs
  Mqtt/
    MqttNicOptions.cs           per-variant broker/topic/tuning config
    MqttNicListenerService.cs   generic host: one instance per enabled variant
    MqttNicClient.cs            MQTTnet wrapper: reconnect, subscribe, publish
    NodeDispatcher.cs           per-node mailbox, ordered + serialized (§6)
    NicEnvelope.cs              raw inbound (topic, payload, receivedAt)
    INicCodec.cs                ◀── the black-box contract (§5)
    NicRoute.cs                 (string NodeId, object? Parsed) — parse-once handoff
    NicDecodeResult.cs          Complete | NeedMore | Ignore | Malformed
    NicPublish.cs               (topic, payload, qos, retain)
    Codecs/
      RawCaptureCodec.cs        dev-only: logs everything, answers nothing
      FragmentReassembler.cs    shared helper for length/index/total headers
      Mqtt4GCodec.cs            variant c   ── 5-byte header, nodeId in topic
      Mqtt4GImgCodec.cs         variant d   ── same family as c
      WirepasCodec.cs           variant a   ── protobuf, nodeId in payload
      KmeshCodec.cs             variant b   ── protobuf, nodeId in payload
      Proto/                    .proto files (committed); classes generated at build
```

---

## 4. Identity: from `IPAddress` to `MeterRef`

The only breaking change, and it is mechanical.

```csharp
/// The meter index is the canonical, NIC-agnostic identity: the brain builds a meter from it,
/// the serial is a function of it, and so is the nodeId. Every NIC derives its own transport
/// address from the same number.
public readonly record struct MeterRef(long Index, NicType Nic)
{
    /// The HES-facing node id — universal, on every meter including TCP ones.
    public string NodeId => Index.ToString(CultureInfo.InvariantCulture);
}
```

### nodeId **is** the index — decided

`nodeId` = the meter serial with the alphabetic prefix and leading zeros stripped:
`MY000001005` → `1005`. Since `Serial(index) = "MY" + index:D9`, that is exactly
`index.ToString()`. So:

- **nodeId needs no allocation, no base offset, no lookup table, and no new config.** It is a
  formatting of the existing identity, and it lands in `MeterIdentity` next to `Serial(long)` in
  `MeterSimulator.Core` as the single source of truth both the simulator and HES derive from.
- **Every meter gets one, including TCP meters**, because HES needs a nodeId to register a meter
  regardless of NIC. IP addresses stay TCP-only. The UI shows nodeId on all batches and the IP
  range only on TCP batches.
- **nodeId ↔ serial can never disagree**, so any HES-side cross-check of node id against the serial
  in the DLMS payload holds by construction — the same reconciliation the TCP path relies on today.
- Inbound parsing tolerates zero-padding: `long.TryParse("0001005")` → `1005`, so a topic or
  protobuf field that carries a fixed-width id needs no special handling.

Because the index is already allocated globally and sequentially across every batch
(`MeterRegistry._nextIndex`), nodeIds are fleet-unique across NIC types for free.

Signature changes:

| Before | After |
|--------|-------|
| `IMeterSimBridge.ExchangeAsync(IPAddress, byte[], ct)` | `ExchangeAsync(MeterRef, byte[], ct)` |
| `MeterSessionManager.GetOrCreate(IPAddress)` | `GetOrCreate(MeterRef)` — dictionary keyed by `Index` |
| `MeterRegistry.GetBatchForAddress(IPAddress)` | `GetBatchForIndex(long)`; the IP overload stays as a one-line wrapper for the UI |
| `ConnectionRegistry` keyed by `IPAddress` | `SessionRegistry` keyed by `long Index` |

`MeterSessionManager.Build` gets *simpler* — it already had to call `ExtractIndex`; now the index
arrives directly. Nothing inside `MeterSimulator.Core` changes: `DLMSMeter` has always been built
from `long index`.

**Why key by index and not by the nodeId string**, given the ask for a string contract: a string key
would let the same meter resolve to two sessions if a codec ever emitted `"001005"` and `"1005"` for
the same node, silently forking the meter's state. `MeterRef.NodeId` keeps every contract, log line
and UI surface string-facing as requested — only the dictionary key is the integer, and the two can
never drift because one is computed from the other.

### Address resolution

With nodeId == index, inbound routing is a one-liner per NIC and needs no abstraction at all:

| NIC | wire → index |
|-----|--------------|
| Tcp4G | `MeterAddressing.ExtractIndex(localEndPoint.Address)` (existing, unchanged) |
| Mqtt4G / Mqtt4GImg | `long.TryParse(nodeIdFromTopic)` |
| MqttWirepas / MqttKmesh | `long.TryParse(nodeIdFromProtobufField)` |

Each NIC owns its own line. The only genuinely per-NIC abstraction left is the **display**
direction — what the Setup page previews for a batch — which is one small
`IMeterAddressDisplay { string Describe(long index) }` returning an IPv6 string for TCP and the
nodeId otherwise. `MeterAddressing` is untouched, so existing TCP deployments are bit-identical.

---

## 5. The black boxes: `INicCodec`

A codec is the *entire* variant-specific surface. Split into two steps deliberately:

```csharp
public interface INicCodec
{
    NicType Nic { get; }

    /// Topic filters this codec subscribes to (the 4 "request" topics).
    IReadOnlyList<string> RequestTopicFilters { get; }

    /// STEP 1 — hot path, runs on the MQTT receive callback. Stateless and thread-safe: it only
    /// answers "which node is this for?" so the message can be handed to that node's mailbox.
    /// Return false to drop (not ours / unparseable). Whatever it had to parse to find the node
    /// id is handed forward in `NicRoute.Parsed` so step 2 never parses the same bytes twice.
    bool TryRoute(NicEnvelope envelope, out NicRoute route);

    /// STEP 2 — runs on that node's own serialized worker, so it may hold and mutate per-node
    /// state (fragment reassembly buffers) with no locking. Returns the complete DLMS wrapper
    /// frame once all fragments have arrived.
    NicDecodeResult Decode(NicEnvelope envelope, NicRoute route, NicNodeState state);

    /// STEP 3 — wrap the brain's verbatim DLMS wrapper reply back up, fragmenting if needed.
    /// Gets the decoded request back so it can reuse whatever correlation the variant needs
    /// (gateway id, sequence, request topic, MQTT5 response-topic/correlation-data).
    IReadOnlyList<NicPublish> Encode(NicRequest request, ReadOnlyMemory<byte> dlmsResponse);
}
```

The `TryRoute` / `Decode` split is what makes fragment reassembly lock-free: by the time `Decode`
runs, the dispatcher has already guaranteed that only one thread is touching that node.

`NicRequest` carries an opaque `object? CodecState` alongside `NodeId` and `DlmsFrame`, plus the
source topic. Whatever a codec stashes there on decode comes straight back on encode — see §5.3.

**Contract with the brain, restated:** what `Decode` produces and what `Encode` consumes is exactly
the byte array `TcpNicListenerService` reads off the socket and writes back — the complete
IEC 62056-47 wrapper frame (8-byte WPDU header + APDU). Confirmed: the NIC wraps the **whole**
wrapper frame, not the bare APDU. If a codec's output is a valid input to the existing TCP path, it
is correct.

### 5.1 Variants c and d — 4G MQTT / 4G IMG MQTT

nodeId is **in the topic**; the payload is a **6-byte** header (not 5 — see §14.1) then the DLMS
wrapper frame. `TryRoute` is a topic-string parse — trivial and allocation-light, exactly what the
hot path wants. Full byte-level spec in **§14.1**.

**The real work here is the fragmentation, not the wrapping** — confirmed by the source. HES never
fragments its own requests (it hardcodes `totalFragments = 1`), so *every* multi-fragment path in
HES exists to handle what the **meter** sends. That is precisely the direction we have to produce
and the direction with no reference implementation to copy. `FragmentReassembler` is therefore built
tolerant and configurable: out-of-order arrival, duplicated indices, a restarted/overlapping set, a
partial set abandoned mid-flight, and an optional `InterFragmentDelayMs` for NICs that cannot absorb
a burst. Each is a named unit test.

`Mqtt4GImgCodec` and `Mqtt4GCodec` are the **same codec** — HES serves both from one client, one
topic pair and one header format. The distinction is meter hardware, not wire protocol, so d is a
`NicType` label over the same code, not a second implementation.

### 5.2 Variants a and b — Wirepas / Kmesh, protobuf

nodeId is **inside the payload**. The topic carries gateway/sink ids we do not need for routing.
`TryRoute` must genuinely decode, so it returns `NicRoute.Parsed` and the parsed message travels to
`Decode` rather than being re-parsed. Full spec in **§14.2** (Wirepas) and **§14.3** (Kmesh).

**No `.proto` files are needed — the generated C# already exists** and can be referenced or copied
verbatim from the HES common library. Note the two variants use *different* protobuf stacks:

| Variant | Library | Source file |
|---------|---------|-------------|
| Wirepas | **protobuf-net** (`[ProtoContract]`, `Serializer.Serialize`) | `CrystalHES.Common/Helpers/WirepasProto.cs` |
| Kmesh | **Google.Protobuf** (`IMessage`, `Parser.ParseFrom`) | `CrystalHES.Common/KMeshHelpers/*.cs` |

Both NuGet packages are needed. Copying the generated files (rather than referencing the HES
assembly) keeps the simulator independent of the HES build, which matters because these are the only
files we share and they change rarely.

### 5.3 Gateway routing — not required, and the seam is free

Confirmed: responses can go to any gateway, the topics accept wildcards, so no gateway-level routing
is needed. Your instinct that it would be nearly free is right, and the design keeps it that way
without building anything: `NicRequest` already carries the source topic and the codec's own state
from decode through to encode, because variants c/d need that channel for fragment bookkeeping
anyway. If gateway-specific responses are ever required, the change is confined to one codec's
`Encode` — shared code, the dispatcher and the brain never learn what a gateway is.

---

## 6. Rebuilding the three things TCP gave for free

### 6.1 One in-flight request per meter, in order — `NodeDispatcher`

MQTT delivers every meter's traffic on one shared connection, concurrently. Two requests for the
same node could otherwise be handled out of order, or simultaneously.

Per node: a **bounded `Channel<NicEnvelope>`** (a mailbox) plus a "drain on demand" worker:

```csharp
_mailbox.Writer.TryWrite(envelope);
if (Interlocked.CompareExchange(ref _draining, 1, 0) == 0)
    _ = Task.Run(DrainAsync);   // no dedicated thread/task per meter — only while work exists
```

This gives ordering and single-threadedness per node without 100k parked tasks. A global
`SemaphoreSlim` around the brain call bounds total CPU concurrency. `BrainMeterSimBridge`'s existing
`lock (session)` stays as a belt-and-braces guard.

Mailbox full ⇒ drop with a metric. A real NIC under a request storm drops too; silently queueing
would model the field wrongly and would be an unbounded-memory bug at fleet scale.

### 6.2 A session that ends — virtual sessions

There is no close event, so a session is created on the first request from a node and reaped by the
idle sweep (the same sweep that exists today, generalised). Two notes:

- The DLMS association state lives in the long-lived `DLMSServerSession`, which today already
  survives TCP socket closes and re-associates on the next AARQ. MQTT inherits that proven
  behaviour — **verify** it explicitly rather than assume (task E-6).
- The simulator deliberately does *not* peek at the APDU to detect ReleaseRequest/Disconnect. That
  would breach the "brain owns DLMS" boundary for no gain; idle timeout is enough.

### 6.3 Admission when there is nobody to reject

TCP rejects by refusing/closing the socket. MQTT has no such channel, so admission failures
(unprovisioned nodeId, stopped batch, missing template, over cap) become **silent drops with a
metric and a Debug log** — which is also what a real meter that is powered off looks like to HES.

---

## 7. One MQTT client, or many?

**One client per NIC variant — four total. Never one per meter.**

- Per-meter clients would mean 10k+ broker connections for something the broker already
  multiplexes; every real deployment has far fewer gateways than meters anyway.
- Per-variant rather than one global client because the four variants plausibly differ in broker
  host, credentials, TLS, QoS and keepalive, and because a Wirepas broker outage must not stop 4G
  traffic. It also makes each variant independently enable/disable-able and independently metered.
- If one connection ever saturates, the escape hatch is **N sharded clients per variant** using MQTT
  5 shared subscriptions (`$share/<group>/<filter>`) — a config value, not a redesign.

This assumes the four request topics are wildcard-subscribable by a single subscriber (see Q2/Q1).

---

## 8. Provisioning, config, UI

### Batch gains a NIC type

```csharp
public NicType NicType { get; init; } = NicType.Tcp4G;   // default keeps existing batches valid
```

`PersistedBatch` gains the same field. Because it defaults to `Tcp4G`, the existing `data/batches.json`
rehydrates unchanged — **no migration**. Index allocation stays global and sequential across all NIC
types, so nodeId ranges never overlap and `Index` stays unique fleet-wide.

`MeterRegistry.PreviewNextBatch` / `GetAddressRange` / `GetMeters` return the nodeId range for every
batch and the IPv6 range only for TCP batches, so the Setup page previews "nodeId 1001 – 2000" for
any batch and adds the IP range when the NIC is `Tcp4G`.

### Broker — one broker, and **two** credentials (§14.6)

The EQA broker (`eqa-broker.kimbal.io`, verified reachable on **1883, plaintext, no TLS**) is shared
by all four variants — HES has exactly one broker config plus an unrelated `_SyncRTCV2` one. HES
connects with a **random GUID client id** and `CleanSession = true`, so there is no client-id format
to match and no duplicate-id eviction risk for us.

The critical subtlety: the settings contain two different passwords under the same username, and
they are **not interchangeable** — they belong to opposite ends of the link (§14.6). We are the
meter, so the simulator uses the **meter-side** credential.

### Config shape

```jsonc
"Nics": {
  "Shared": {
    // One broker serves all four variants. Host/credentials from user-secrets or environment.
    "Broker": { "Host": "", "Port": 1883, "UseTls": false, "ClientIdPrefix": "nicsim", "Username": "", "Password": "" }
  },
  "Mqtt4G": {
    "Enabled": true,
    "MaxFragmentPayload": 0,        // 0 = never fragment outbound (matches HES's own request behaviour)
    "InterFragmentDelayMs": 0,
    "PublishQos": 2,                // HES clamps its own QoS setting to 2; match unless told otherwise
    "MailboxCapacity": 32,
    "IdleTimeoutSeconds": 300,
    "FragmentTimeoutSeconds": 30
  },
  "Mqtt4GImg":   { "Enabled": false },   // same codec as Mqtt4G, different NicType label only
  "MqttWirepas": { "Enabled": false, "MaxFragmentPayload": 90 },
  "MqttKmesh":   { "Enabled": false, "MaxFragmentPayload": 90 }
}
```

Already shipped in Phase B, and shared by every NIC:

```jsonc
"Sessions": {
  "IdleTimeoutSeconds": 120,      // also bounds a half-open DLMS association on the MQTT NICs
  "SweepIntervalSeconds": 30,
  "MetricsIntervalSeconds": 15
}
```

Per-variant broker overrides stay possible (a variant section may carry its own `Broker`), but the
default is the shared one — that is what the field actually runs.

Topics live in the codec, not in config, unless they turn out to be deployment-varying.

**Secrets never go in `appsettings.json`.** The project already has a `UserSecretsId`, so for dev:

```bash
dotnet user-secrets set "Nics:Shared:Broker:Password" "<meter-side-password>"
```

and in production, the environment variable `Nics__Shared__Broker__Password`.

### UI

- **Setup** — NIC type selector on batch creation; **nodeId range shown for every batch** (HES needs
  it to register meters on any NIC), IP range shown additionally for TCP batches; the
  `Tcp:AddressPrefix` banner becomes TCP-only.
- **Dashboard** — NIC-type column on batches; broker connection status per enabled variant
  (connected / retry count / last error) — this is the MQTT equivalent of "is the listener bound"
  and is the first thing anyone will ask when nothing is responding.
- **Live logs** — a NIC tag on every NIC-layer log line.
- **New: Codec Probe** (dev/admin page) — paste a topic + hex payload, see `TryRoute` → nodeId,
  `Decode` → DLMS frame; and the reverse. This is the single highest-leverage tool for filling the
  black boxes and is worth building before the codecs themselves.

---

## 9. How the black boxes actually get filled

The wrapping logic is only knowable from the HES pull service. Concrete method, in order:

1. **Raw capture first.** Ship `RawCaptureCodec` in Phase C: it subscribes to the real request
   topics, answers nothing, and appends every message to `data/captures/<nic>-<date>.jsonl` as
   `{ts, topic, payloadHex}`. Point it at a real (or staging) HES and we have ground truth before a
   single line of codec logic exists.
2. **Read HES's publish path** → the *inverse* of our `Decode`. Read HES's receive path → the
   inverse of our `Encode`. **Done — see §14.** The warning that the two paths are written by
   different code and can disagree turned out to be the headline finding: Wirepas genuinely uses
   a trailer one way and a header the other. Trust captures over code wherever they conflict.
3. **Golden vectors.** Every captured message becomes a test case:
   `Decode(topic, payload) == expectedDlmsFrame`. For the response direction, capture a real
   *meter's* published response if one exists; otherwise assert `Decode(Encode(x)) == x` round-trip
   plus a byte-level assertion against a hand-derived expected packet.
4. **Codec Probe page** for interactive iteration without a redeploy.
5. **Replay harness** — feed a capture file through the full funnel offline (no broker), so codec
   work needs neither a broker nor an HES.

Order matters: **transport before codec**. Phase C's only job is to prove we can connect, subscribe
and capture; that de-risks the credentials/TLS unknowns, which are now the *only* remaining
unknowns on the critical path.

With §14 in hand, captures are no longer needed to *write* the codecs — only to validate them and
to fill the cosmetic fields HES never checks (§13 items 3–6). So Phases E–G can be built and
unit-tested against hand-derived vectors before a broker is ever reachable.

---

## 10. Testing

| Level | What |
|-------|------|
| Unit | nodeId ⇄ index round-trip, incl. zero-padded input, boundaries, malformed input, and agreement with `Serial(index)` |
| Unit | `FragmentReassembler`: in-order, out-of-order, duplicate index, missing index + timeout, restarted/overlapping set, single-fragment, max-size |
| Unit | Each codec against captured golden vectors, both directions |
| Unit | `NodeDispatcher`: ordering under concurrent writes, mailbox-full drop, no lost wakeup on the drain race |
| Integration | Embedded MQTTnet broker in-process: publish a real DLMS AARQ, assert an AARE comes back on the response topic |
| Integration | Full pull cycle (AARQ → GET → RELEASE) over MQTT against a real template, asserting the same values the TCP path returns for the same meter |
| Scale | N nodes × M polls/min through one client; watch mailbox depth, brain latency, broker inflight |
| Regression | The entire existing TCP suite must pass untouched after §4 |

A **`HESTestClient` MQTT mode** (publish wrapped requests, subscribe for responses) is needed for
manual/scale testing; the folder exists but is currently empty.

---

## 11. Task list

**Every phase is now unblocked.** The wire formats are known (§14), so E–G need only broker
credentials to go end-to-end — and their unit-testable parts need nothing at all.

### Phase A — identity generalisation (no behaviour change) — **DONE**
- [x] A-1 `NicType` enum, `MeterRef` record struct with computed `NodeId` — `Networking/Nic/`
- [x] A-2 `MeterIdentity.NodeId(long)` in `MeterSimulator.Core`, next to `Serial(long)`, + a test asserting it equals the serial stripped of prefix and leading zeros (not merely "it's the index")
- [x] A-3 `MeterRegistry.GetBatchForIndex(long)`; the `IPAddress` overload is now a one-line wrapper
- [x] A-4 `MeterRef` threaded through `IMeterSimBridge`, `BrainMeterSimBridge`, `SimulatedMeterSimBridge`, `MeterSessionManager` (dictionary keyed by `Index`)
- [x] A-5 `ConnectionRegistry` → `SessionRegistry` keyed by `Index`; `ConnectionState` gains `Meter`, and its TCP-only `MeterAddress`/`RemoteEndPoint` are now nullable for connectionless NICs
- [x] A-6 Verified: 74 tests green (62 pre-existing unchanged, 12 new). New `TcpNicListenerTests` drives a real socket end-to-end — accept → `MeterRef` → admission → registry → framing → bridge → reply — plus a rejection case, so the TCP path is covered by more than unit tests. `MeterSessionManagerTests` pins the property this phase exists for: a meter reached by IPv6 and by node id resolves to the **same** brain session.

Not yet done from A: a manual pull against GXDLMSDirector. The automated socket test covers the
plumbing; the manual run is still worth doing once before Phase B lands on top.

### Phase B — shared NIC plumbing — **DONE**
- [x] B-1 Admission gates hoisted into `MeterAdmission` (`Networking/Nic/`). Returns an `AdmissionResult` + `Reason`; the caller expresses the refusal (TCP closes the socket, MQTT will drop the message). It also **claims** the session, because "is one already live" and "claim it" must be one atomic step — checking then registering is a race.
- [x] B-2 `SimulatorMetrics` keeps counters per NIC (array indexed by `NicType`, so recording is still one interlocked increment) and sums them on demand. `Snapshot()` returns fleet totals — every existing caller is unchanged — and `Snapshot(nic, active)` breaks one NIC out.
- [x] B-3 Idle sweep + metrics reporter moved out of the TCP listener into `SessionMaintenanceService`. Neither was ever TCP-specific; both work on `ConnectionState` via `SessionRegistry`, so every future NIC now gets idle reaping and metrics for free.
- [x] B-4 `MeterBatch.NicType` + `PersistedBatch.NicType`, defaulting to `Tcp4G`. Verified against **literal legacy JSON** with no `NicType` field, asserting it rehydrates as TCP with the allocation cursor intact — the compatibility guarantee, tested against something today's code cannot produce.
- [x] B-5 Done as `MeterRegistry.GetNodeIdRange` + `BatchPreview.First/LastNodeId` rather than an `IMeterAddressDisplay` interface — see the deviation note below.
- [x] B-6 Setup: NIC selector on batch create, NIC column, node-id range for every batch, IP range only for `Tcp4G`. Dashboard: NIC shown per batch row. CSV export gains `nodeid` and `nic` columns, with `ipv6`/`port` blank for MQTT batches.
- [x] B-7 (added) Config: `IdleTimeoutSeconds` / `SweepIntervalSeconds` / `MetricsIntervalSeconds` moved from `Tcp` to a new `Sessions` section, since they are not TCP policy. `TcpOptions` keeps only genuinely TCP settings.

**Deviation from the plan (B-5).** The design called for an `IMeterAddressDisplay` abstraction. Once
nodeId became the index (§4), there was nothing left to abstract: the display rule is "node-id range
always, IP range if `Tcp4G`", and inbound resolution is a one-line `long.TryParse` per NIC. An
interface plus DI registration for a single `if` would be indirection with no second implementation
behind it, so it is two methods on `MeterRegistry` instead. If a NIC ever gets an address form that
is *not* a function of the index, that is the moment to introduce the interface.

Verified: **84 tests green** (74 before, 10 new), app boots clean, and `SessionMaintenanceService`
was observed logging its periodic summary from the running app.

### Phase C — MQTT transport (codec-free) — **DONE except the traffic-dependent captures**
- [x] C-1 MQTTnet 5.2; `NicsOptions` (shared broker + per-transport tuning); credentials in user-secrets / environment, never in `appsettings.json`
- [x] C-2 `MqttNicClient`: connect, auth with **ordered credential fallback**, subscribe, publish, reconnect with backoff, connection-state surface. Resolved the two-password ambiguity on first connect → §14.5
- [x] C-3 `MqttNicListenerService` — one client per enabled **transport**, wired to a codec
- [x] C-4 `NicCaptureWriter` → `data/captures/<nic>-<date>.jsonl` (already gitignored), plus `RawCaptureCodec` / `CaptureOnlyCodec`
- [x] C-5 Dashboard: per-transport broker status strip (connected / credential used / filter count / last error + attempt count)
- [~] C-6 Capture real HES traffic — **Wirepas captured and decoded; nothing seen yet on 4G or Kmesh.** Needs HES actually polling; see below
- [ ] C-7 Capture a deliberately **multi-fragment** exchange for c/d (a profile-generic read, not an AARQ) ← the fragmentation quirks live here

**Transports, not NIC types.** There are four NIC types but only **three** MQTT clients: c and d
share a broker, a topic pair and a framing format, so giving them separate clients would subscribe
to `PollRequest/#` twice and receive — and later answer — every message twice. `NicsOptions` has no
IMG section; `TransportFor()` folds it into `Mqtt4G`, and a batch still records which of the two a
meter is, because that is real hardware. Pinned by a test.

**What the live run proved, and what it did not.** All three transports connected and subscribed
against the EQA broker on the first attempt, and 10 real Wirepas messages were captured and
decoded correctly against §14.2 — so the transport, credential handling, routing seam and capture
pipeline are all verified end to end against production traffic. But **none of it was DLMS pull
traffic**: every message was OTAP (endpoints 255/240), and no `PollRequest/…` or Kmesh message
arrived at all during the run. C-6/C-7 therefore need HES to be actively polling meters on these
NICs — that is an operational trigger, not a code gap.

To re-run a capture (no file changes needed — enable per transport via environment):

```bash
Nics__Mqtt4G__Enabled=true Nics__Mqtt4G__CaptureRawMessages=true dotnet run
```

### Phase D — connectionless session model — **DONE**
- [x] D-1 `NodeDispatcher`: bounded per-meter mailbox, drain-on-demand worker (no task exists while a meter is idle, so 100k meters cost 100k channels rather than 100k parked tasks), global semaphore bounding concurrent brain calls
- [x] D-2 Virtual sessions — opened by the **first message** (a connectionless NIC has no accept event), refreshed by traffic, reaped by the existing idle sweep
- [x] D-3 Drop-with-metric path plus three new per-NIC counters: `droppedMailboxFull`, `malformed`, `fragmentTimeouts`. The unprovisioned/not-running drops reuse the existing rejection counters rather than duplicating them — same decision, now just reached without a socket to close
- [x] D-4 Dispatcher tests: arrival ordering, never-concurrent-per-meter, concurrent-across-meters, mailbox-full drop isolation, handler-throws isolation, drain reporting, and the **lost-wakeup race** hammered from 4 threads × 2000 messages
- [x] D-5 Graceful shutdown: clients stop first (so nothing new arrives), then queued work gets a bounded drain window, then clean disconnect
- [x] D-6 (added) `AdmissionOutcome.WrongNic` — see below

**The reaping bug this phase had to avoid.** On TCP the session loop unregisters in its `finally`
when the socket closes. A virtual session has no such moment, so cancelling it in the sweep without
also removing it would leave it in the registry forever — and every later message from that meter
would be refused as `AlreadyActive`. The meter would go permanently silent after one idle period.
`ConnectionState.IsVirtual` marks the sessions the sweep must remove itself, and both halves are
tested: a virtual session is cancelled **and** removed, a TCP session is cancelled and **left** for
its own loop.

**New gate: `WrongNic`.** Admission now checks that the meter is provisioned for the NIC it arrived
on (`NicTypes.CanServe`). A TCP-provisioned meter answering over MQTT is a provisioning error, and
serving it would put the simulator quietly out of step with how HES has the fleet registered. The
direct-4G transport legitimately serves both `Mqtt4G` and `Mqtt4GImg`, so that pair passes — tested
in both directions.

Verified: **117 tests green**; boots and connects against the live broker with the dispatcher wired
and the new counters visible in the periodic summary.

### Phase E — direct 4G MQTT codec (variants c **and** d — one codec, spec in §14.1) — **BUILT, awaiting live proof**
- [x] E-1 ~~`FragmentReassembler`~~ — **dropped by decision**, see below
- [x] E-2 `Mqtt4GCodec` — `TryRoute` (topic parse) / `Decode` (6-byte header, single fragment) / `Encode` (6-byte header, always one fragment)
- [x] E-3 Framing tests against HES's **own** logic, reimplemented from source
- [x] E-4 Funnel wired: decode → admission/session → `IMeterSimBridge` → encode → publish, all on the meter's serialized worker
- [ ] E-5 **Verify** re-association without an explicit close (back-to-back AARQs on one session)
- [ ] E-6 Full pull cycle against real HES, both as `Mqtt4G` and `Mqtt4GImg`

**Fragmentation dropped, deliberately.** Outbound: the simulator has no radio to constrain it, and
HES's parser short-circuits on `totalFragments == 1` — the single-fragment branch reads only the
frame id and emits the payload, never touching the length field (so even Wirepas's 1-byte length
overflowing on a large message is harmless). Gurux already segments big reads at the DLMS layer, so
individual frames are small anyway. Inbound: HES hardcodes `totalFragments = 1` on this path and
its splitting loop is commented out, so a fragmented 4G request cannot occur.

That leaves exactly one place fragmentation is real — **Wirepas requests**, which HES chunks at 90
bytes with a live loop — and it is deferred to Phase F with the rest of that variant. A fragmented
request is reported as `Unsupported`, not `Malformed`, so a deferred feature is never mistaken for
a decoding bug in the counters. `MaxFragmentPayload` stays in config so outbound fragmentation can
be switched on later purely to exercise HES's reassembler.

**How E-3 was tested without a captured packet.** No real `PollRequest` has ever appeared on the
wire, so the vectors are built by porting HES's own `GetPacketFragments` (writer) and
`IsCompletePacketDirectDLMS` (parser) into the test and asserting our codec interoperates with both
— including a 4000-byte reply that overflows the length byte HES never validates. That is weaker
than a captured packet and much stronger than asserting our encoder against our own decoder, which
would pass however wrong the layout was. **The first live poll is still the real proof.**

Verified: **134 tests green**; sim runs against the live broker with all three transports connected
and four batches (node ids 501–540) provisioned and Running.

### Phase F — RF Wirepas (variant a, spec in §14.2) — **BUILT, awaiting live proof**
- [x] F-1 Vendored to `KimbalSpecifics/Wirepas/` + `protobuf-net`
- [x] F-2 `TryRoute` — parses `GenericMessage`, requires `destination_endpoint == 3`, rejects the broadcast address, forwards the parsed message via `NicRoute.Parsed`
- [x] F-3 `Decode` — **trailer** framing (5 bytes at the END), with HES's index/total swap guard mirrored
- [x] F-4 `Encode` — **header** framing (5 bytes at the FRONT) inside `packet_received_event` with `source_endpoint = 3`, published to `gw-event/received_data/{gw}/{sink}/{node}/3/3`, echoing the request's gateway and sink
- [x] F-5 Asymmetry regression test — decode(trailer) and encode(→header) asserted **independently**, plus an explicit assertion that the framing is NOT at the tail, so collapsing them into one layout fails loudly
- [x] F-6 The OTAP filter, tested against **three real captured packets** from the live broker
- [ ] F-7 End-to-end against real HES
- [ ] F-8 Inbound reassembly (HES chunks requests at 90 bytes) — deferred; currently reported as `Unsupported`

### Phase G — RF Kmesh (variant b, spec in §14.3) — **BUILT, awaiting live proof**
- [x] G-1 Vendored to `KimbalSpecifics/Kmesh/` + `Google.Protobuf` (a different stack from Wirepas — both packages are referenced)
- [x] G-2 `TryRoute` — parses `NodeRequest`, takes `NodeId`
- [x] G-3 `Decode`/`Encode` — no byte framing at all; `RequestId` → `ResponseId`, `RespType = KAP_DLMS_WRAPER_PULL_RESPONSE_DATA`, `FragInfo` 1/1, gateway echoed from the request
- [x] G-4 Vectors both directions, including a test that fails if anyone ever "strips the 7-byte Kmesh header" (`PullHeaderLength == 7` is a **discriminator**, not a length)
- [ ] G-5 End-to-end against real HES
- [ ] G-6 Measure the protobuf parse on the receive callback under load

**Vendored files live in `KimbalSpecifics/`** (`Wirepas/`, `Kmesh/`, plus a README naming the source
of each). They needed separate sub-namespaces: both protos define `ErrorCode` and `NodeRole`, which
only did not collide in HES because they sat in different namespaces there.

**Both are OFF by default** (`Enabled: false`), so nothing changes for the 4G testing in progress
until they are switched on. When they are, note that Wirepas and Kmesh will now **answer** — their
framing is derived from HES's parser alone, never from an observed meter reply, so the first live
exchange is genuinely unproven in a way the 4G one no longer is.

### Phase H — tooling
- [ ] H-1 Codec Probe page (decode/encode a pasted packet)
- [ ] H-2 Capture replay harness (offline, no broker)
- [ ] H-3 `HESTestClient` MQTT mode
- [ ] H-4 Docker Compose Mosquitto for local dev

### Phase I — scale & docs
- [ ] I-1 Mixed-NIC scale run; tune mailbox capacity, semaphore, broker inflight
- [ ] I-2 Fold this document into `implementation.md`; update `task.md`, Documentation and FAQ pages
- [ ] I-3 Deployment notes: MQTT needs no host routing (contrast with the TCP `/64` setup)

---

## 12. Questions — resolved

- **nodeId location.** a/b: inside the payload protobuf. c/d: in the topic. → §14;
  `TryRoute` returns `NicRoute.Parsed` so the protobuf is parsed once.
- **Gateway routing.** Not needed — any gateway will do. Seam retained at zero cost → §5.3.
  (Kmesh still echoes the request's gatewayId, since it appears in the response topic.)
- **nodeId allocation.** nodeId = serial minus prefix and leading zeros = the index. Universal
  across all NICs including TCP; IPs stay TCP-only → §4. Kills `NodeIdBase`, the lookup table and
  the address-plan abstraction on the inbound side.
- **nodeId ↔ serial cross-check.** Holds by construction, since both derive from the index.
- **What the header wraps.** The complete DLMS wrapper frame, all four variants — the same bytes
  the TCP path moves. The funnel is untouched.
- **Registration / heartbeat / birth message.** Out of scope here; will ride on the push
  infrastructure when scheduled push is built.
- **Header layouts, topics, fragmentation, endianness, correlation.** All read out of the HES
  source — full byte-level spec in **§14**. Highlights: c/d is **6** bytes not 5; Wirepas is 5 but
  as a **trailer** on request and a **header** on response; Kmesh has no byte header at all;
  everything little-endian; `frameId` is echoed back; reassembly is count-based.
- **`.proto` files.** Not needed — generated C# already exists in the HES common library and gets
  vendored (protobuf-net for Wirepas, Google.Protobuf for Kmesh) → §5.2.
- **Variant d.** Not a separate codec — same client, topics and framing as c → §14.6.
- **Broker.** One broker for all four variants, plaintext 1883, no TLS, random GUID client id, no
  duplicate-id hazard. Credentials supplied → §14.5. Note there are **two** credentials for opposite
  ends of the link; we use the meter-side one.

## 13. Questions — still open

Blocking the phase named in brackets. Everything through Phase D proceeds without any of these.

**THE OPEN BLOCKER — why HES sees no data (2026-07-30)** [E]

HES polls, we answer correctly, and HES's `ProcessMessage` never runs. Established so far:

- HES's request decodes exactly per §14.1 — confirmed against a live packet.
- Our reply is a well-formed, **accepting** AARE (`association-result = 0`, `diagnostic = 0`),
  proven by replaying HES's captured AARQ against the brain offline.
- The **frame id round-trips byte-identically** in bytes 4–5 (`CB 10` in → `CB 10` out), and the
  node id is in the response topic, so both halves of HES's correlation key `(meterNo, frameId)`
  are present and correctly placed.
- Re-association on a session with no explicit close works (a second AARQ returns an identical
  accepting AARE) — so the connectionless-session concern is **not** the cause.
- HES's own log shows `AARQRequest on PublicClient Completed` for frames 4340/4342/4343 and then
  **no receive-side line at all**.

So the reply is not reaching `ProcessMessage`. Three candidates, unresolved:

1. **Topic shape.** Source says subscribe `PollResponse/#`, read `Split('/')[1]` as node id — which
   is what we publish. But a commented-out `Split('/')[2]` frame-id read proves the topic *used to*
   be `PollResponse/{nodeId}/{frameId}`. A deployed build predating that change would ignore ours.
   Publishing `PollResponse/{nodeId}/{frameId}` satisfies **both** shapes — one-line change, and the
   cheapest thing to try first.
2. **`direct_tcp` routing.** HES's log shows `gateway direct_tcp_9` for these meters; `direct_tcp` is
   written only by `TCPDataReceiverClient`, whereas the 4G path uses `direct_4g` (written by
   `MQTTDataReceiverDirectDLMSClient` when a meter **pushes**). Our push is deferred, so these node
   ids still carry stale TCP routing. No code path was found where this blocks the direct-4G
   receive, so this is an observation, not a diagnosis.
3. **Another service owns `PollResponse/#`** — `MQTTSendFirmwareCommand4GClient` subscribes to the
   identical filter.

**Fastest discriminator:** grep the HES log for `Entered client_mqtt direct dlms` around those frame
ids. Present ⇒ delivery is fine, it drops downstream. Absent ⇒ candidate 1 or 3.

**Lesson recorded:** two wrong calls were made in this session by reading only Information-level
logs — first "HES stalls after the association", then "70 exchanges means a full pull sequence".
Both were artefacts of first-exchange-only logging. Captures now record **both directions** and
broker PUBACK/PUBCOMP results are checked, so the next run needs no inference.

**Also still open:** getting HES to poll Wirepas/Kmesh meters so F/G get golden vectors, and a
multi-fragment exchange for C-7.

**Broker** [C]
2. The value of `CrystalHES.MqttQualityOfServiceLevel` — HES clamps it to 2 when out of range, so
   2 is the assumption in config, but the configured value decides what we publish at. Also: is the
   broker MQTT 5 (shared subscriptions as the sharding escape hatch)? HES's client works either way,
   so its code does not tell us.

**Framing — the gaps the source could not answer** [E/F/G]
3. **Outbound fragment size per variant.** HES imposes no limit when *reading*, so this is a real
   NIC/RF constraint we cannot see from HES code. Wirepas requests use 90-byte chunks, which is a
   reasonable guess for the response direction too — but 4G and Kmesh have no observable value at
   all. A wrong choice still reassembles correctly at HES, so this only matters for realism (and
   for whether a real gateway would have dropped it). Default: 90 for RF, unfragmented for 4G.
4. **Kmesh response topic tail.** HES subscribes `gateway/pull/response/meter/+/#` and never reads
   past the gatewayId, so *anything* works — but a real gateway publishes something specific and
   matching it costs nothing. What does the field actually use? (Guess: `…/{gatewayId}/{nodeId}`.)
5. **Kmesh response `RequestType`.** `KAP_DLMS_WRAPER_PULL_RESPONSE_DATA (3)` is the obvious value
   and HES ignores it on this path, so it is unverifiable from the source. Confirm from a capture.
6. **Wirepas `packet_received_event` fields HES ignores** — `travel_time_ms`, `rx_time_ms_epoch`,
   `hop_count`, `event_id`, `qos`. Plausible values are easy (and RF unreliability modelling would
   use them), but nothing validates them. Fill from one real capture.
7. Any NIC-level ACK expected, separate from the DLMS response? Nothing in the pull path suggests
   one, but the push path might differ.

**Behaviour** [E/F/G]
8. How long does HES hold an association open over MQTT, and what is its retry/timeout behaviour?
   That sets the default virtual-session idle timeout.
9. Should the simulator model RF unreliability (added latency, drop rate, dropped fragments)? Cheap
   at the codec boundary and eventually useful for HES testing — but a deliberate feature, not a
   default. Not needed to ship.

**Scope** [I]
10. Expected fleet size per NIC type and poll frequency? Drives whether one client per variant holds.
11. Confirm one host serves mixed NIC types simultaneously (assumed yes — batches carry the NIC type).

Note that 3–6 are all **"HES does not check this"** items — the codecs work without them; they only
affect how convincingly the simulator impersonates real hardware. One capture per variant closes all
four, which is what C-6/C-7 are for.

---

## 14. Reverse-engineered wire formats

Derived by reading the HES pull service. Sources:

| What | File |
|------|------|
| Wirepas client (a) | `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCommandClient.cs` |
| Direct-DLMS client (b, c, d) | `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCommandDirectDLMSClient.cs` |
| Reassembly (all) | `vayu-common/CrystalHES.Common/Helpers/DLMSHandlingFunctions.cs` |
| Wirepas protobuf | `vayu-common/CrystalHES.Common/Helpers/WirepasProto.cs` (protobuf-net) |
| Kmesh protobuf | `vayu-common/CrystalHES.Common/KMeshHelpers/*.cs` (Google.Protobuf) |
| Wirepas packet builder | `Functions.GetWirepasSendMessagePacket` in `Helpers/Functions.cs` |

**Endianness:** every multi-byte framing field is **little-endian**. HES writes with
`BitConverter.GetBytes` and reads with `BitConverter.ToUInt16` — both LE on x86. This is *framing*
only; the DLMS wrapper inside stays big-endian per IEC 62056-47.

**`frameId` is the correlation token.** HES matches a response to its outstanding command with
`HESCommandRepository.Get(frameId, meterNo)`. The rule is uniform across all four variants:
**echo back the frameId that arrived**. It is opaque to the simulator.

**`PullHeaderLength` is HES's per-template discriminator** — how HES itself decides which framing to
apply: `5` = Wirepas, `6` = direct 4G, `7` = Kmesh (a flag only; Kmesh has no byte header at all).
Worth mirroring as our own NIC-type mapping so the two stay legible against each other.

### 14.1 Variants c / d — direct 4G MQTT

| Direction | Topic |
|-----------|-------|
| HES → meter | `PollRequest/{nodeId}` |
| meter → HES | `PollResponse/{nodeId}` — HES subscribes `PollResponse/#` and takes `topic.Split('/')[1]` as the nodeId |

**6-byte header, same layout both directions**, then the complete DLMS wrapper frame:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | total length, LE (`payloadLength + 6`) |
| 2 | 1 | total fragments |
| 3 | 1 | this fragment (1-based) |
| 4 | 2 | frameId, LE |
| 6 | n | DLMS wrapper frame (8-byte WPDU header + APDU) |

Request side (`GetPacketFragments` in the direct client): HES writes `totalFragments = 1` and
`thisFragment = 1` **always** — its splitting loop is commented out, so a request is always one
message however large. Response side (`IsCompletePacketDirectDLMS`): full multi-fragment
reassembly, so the meter *may* fragment and HES expects to handle it.

Asymmetry to be aware of: HES writes a 2-byte length but reads only **byte 0** back
(`ConvertByteToInt(fragmentBytes[0])`) — and only for bookkeeping, never for reassembly, which is
purely count-based. We still write the correct 2-byte LE value.

### 14.2 Variant a — RF MQTT Wirepas

| Direction | Topic |
|-----------|-------|
| HES → meter | `gw-request/send_data/{gatewayId}/{sinkId}` |
| meter → HES | `gw-event/received_data/{gwId}/{sinkId}/{networkAddress}/3/3` — HES subscribes `gw-event/received_data/+/+/+/3/3`; the trailing `3/3` are source/destination endpoint, and it additionally rejects anything whose `source_endpoint != 3` |

Protobuf envelope (protobuf-net, `GenericMessage`):

- **HES → meter:** `GenericMessage.wirepas.send_packet_req` — `destination_address` = nodeId,
  `source_endpoint` = `destination_endpoint` = 3, `header.req_id` = a monotonic counter (**not** the
  frameId), `header.sink_id`, `payload` = the framed DLMS bytes below.
- **meter → HES:** `GenericMessage.wirepas.packet_received_event` — `source_address` = nodeId,
  `source_endpoint` = 3 (**required**, HES drops otherwise), `payload` = the framed DLMS bytes,
  plus `header.gw_id`, `header.sink_id`, `header.event_id`, `travel_time_ms`, `rx_time_ms_epoch`,
  `qos`, `payload_size`, `hop_count`.

> **CORRECTED 2026-08-08 by live capture — the two directions ARE symmetric.**
>
> This section previously claimed the request was a **trailer**, read out of
> `MQTTSendCommandClient.GetPacketFragments`. A captured request for simulated node 507 disproves it:
>
> ```
> gw-request/send_data/direct_tcp/direct_tcp   (send_packet_req, dst_ep 3, dst_addr 507)
> payload: 2C 01 01 AD 01 | 00 01 00 10 00 01 00 1F | 60 1D … FF FF
>          ^len=44 ^1of1  ^frameId=429    ^DLMS wrapper (8-byte WPDU + 31-byte AARQ)
> ```
>
> Read as a header, every field is self-consistent: the length byte equals the true payload length
> (44) and the fragment counts are 1/1. Read as a trailer, the same bytes claim **255 fragments** —
> so the codec discarded a perfectly good request as unsupported fragmentation, at Debug level and
> with no metric. The symptom was a Wirepas NIC that received traffic and silently answered nothing.
>
> Real meter uplinks in the HES log (`5F 01 09 AC 49` = 95 bytes, fragment 1 of 9, frameId 0x49AC)
> use the same header, which is also what we already emitted — the response direction was always
> right. **Both directions use the 5-byte header below.** The trailer layout is kept here only as a
> record of what the source appeared to say; do not implement it.
>
> This is the case §9 step 2 warned about: *trust captures over code wherever they conflict.*

*The layout HES's source appeared to describe for HES → meter — a **TRAILER**, NOT what the wire shows:*

| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | frameId, LE |
| 2 | n | payload chunk (max **90** bytes) |
| n+2 | 1 | this fragment (1-based) |
| n+3 | 1 | total fragments |
| n+4 | 1 | payload length (`chunkLength + 5`) |

*The real framing, **both directions*** (`DLMSHandlingFunctions.IsCompletePacket`, `PullHeaderLength = 5`):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | total length |
| 1 | 1 | total fragments |
| 2 | 1 | this fragment (1-based) |
| 3 | 2 | frameId, LE |
| 5 | n | payload chunk |

The trailer is the header's fields in reverse order at the opposite end of the packet. Reading only
one direction and assuming symmetry — the obvious trap — produces a codec that decodes correctly and
is never understood by HES. Wirepas is also the **only** variant where HES fragments its own
requests (90-byte chunks).

**Replicate this quirk:** the chunking loop is `for (var i = 0; i <= payload.Length;)`, so a payload
whose length is an exact multiple of 90 produces a trailing **zero-length fragment** — 90 bytes
arrives as 2 fragments, the second empty. Our decoder must tolerate it; if we ever emit Wirepas
requests (test client), replicate it.

**The request topic is NOT only DLMS — confirmed from live capture.** `gw-request/send_data/#`
also carries Wirepas OTAP traffic. Every message captured in the Phase C run had
`source_endpoint = 255`, `destination_endpoint = 240` (the OTAP pair used by
`GetWirepasOtapGeneralMessagePacket`) and a 2-byte payload, addressed either to a specific node or
to `destination_address = 0xFFFFFFFF` (broadcast):

```
gw-request/send_data/DEMO100175/sink2
0A2632240A1208B89CF7C080D6F4ADEF01120573696E6B3210E9EC0618FF0120F001280132021900
                                                    ^dest=112233 ^srcEp=255 ^dstEp=240 ^payload
```

So `WirepasCodec.TryRoute` **must filter on `destination_endpoint == 3`** and ignore everything
else — the mirror of the `source_endpoint == 3` check HES applies to our uplink. Without it the
codec would try to unwrap scratchpad-status polls as DLMS and log a malformed packet every few
seconds on an otherwise healthy system.

This capture also validated the protobuf field mapping above against real bytes: the
`GenericMessage → wirepas → send_packet_req` nesting, `header.req_id`, `header.sink_id`,
`destination_address`, both endpoints, `qos` and `payload` all decoded exactly as documented.

### 14.3 Variant b — RF MQTT Kmesh

| Direction | Topic |
|-----------|-------|
| HES → meter | `gateway/pull/request/meter/{gatewayId}` |
| meter → HES | `gateway/pull/response/meter/{gatewayId}/…` — HES subscribes `gateway/pull/response/meter/+/#`; the `+` is the gatewayId and the tail beyond it is **not read** (nodeId comes from the protobuf) |

Pure Google.Protobuf — **no byte header at all**, and fragmentation lives *inside* the message:

- **HES → meter:** `NodeRequest { NodeId (uint32), Request { GatewayId, RequestId = frameId,
  RequestType = KAP_DLMS_WRAPER_PULL_REQUEST_DATA (2), Payload = raw DLMS wrapper frame } }`
- **meter → HES:** `NodeResponse { Header: CommonHeader { NodeAddr = nodeId, GatewayId, SinkId,
  TraveltimeMs }, Response { ResponseId = frameId, Payload, FragInfo { ThisFrag, TotalFrag } } }`

`Payload` carries the DLMS wrapper frame with **no framing of our own** — for a single-fragment
reply the protobuf `Payload` *is* the brain's output verbatim. Reassembly concatenates
`Response.Payload` across fragments ordered by `ThisFrag`.

Kmesh needs a `gatewayId` to publish to, and HES resolves it per node via
`GetCachedLatestRoutingByNodeId(nodeId).GatewayId`. Answering as the meter, we echo the gatewayId
that arrived on the request rather than inventing one.

### 14.4 Reassembly semantics — shared by a, b, c, d

All four funnel into the same logic, so one `FragmentReassembler` serves all of them:

- **Keyed by** `(nodeId, frameId, direction)`.
- **Completion is count-based**, never length-based: complete when the number of distinct fragments
  received equals `totalFragments`. The length byte is recorded and never checked.
- **Ordering** is by fragment index ascending, then straight concatenation.
- **Duplicates are dropped** — a repeated index is discarded, not overwritten.
- **`totalFragments == 1` short-circuits** entirely: strip framing, emit, no state.
- **The swap quirk:** both byte-header implementations do
  `if (receivedFragmentIndex > totalFragments) swap(...)`. Defensive code in HES against a real NIC
  that emits the two fields the other way round. We emit them correctly; our decoder tolerates
  either, mirroring HES.

### 14.5 Broker topology — one broker, two credentials

> **Superseded for the simulator — see `network_registry.md`.** The "one broker" finding below is
> still an accurate reading of THIS HES deployment's config, but it is not a property of the field:
> RF gateways hold their own broker details and 4G meters carry theirs in OBIS objects, so a real
> fleet is served by several. The simulator therefore keeps a registry of named brokers and each
> batch binds to one; `Nics:Shared:Broker` survives only as the seed for the `default` entry and as
> connection tuning. The two-credential note below is unchanged and still load-bearing — it is why
> a seeded endpoint keeps the configured credential list as fallbacks.

From `MQTTClientHelper.Connect` (`vayu-common/CrystalHES.Common/MQTTHelper/MQTTClientHelper.cs`) and
`GenericHelpers.cs` around the `SetMQTTBrokerDetails` command:

- **One broker for all four NIC variants** *in this deployment's HES config*. `MQTTClientHelper`
  reads `CrystalHES.Broker*` with an optional key suffix, and the only suffix in use is
  `_SyncRTCV2` — an unrelated RTC-sync broker. Every pull client (Wirepas, direct-DLMS, TCP,
  firmware) uses the same unsuffixed settings.
- **No TLS.** `CrystalHES.SecureBroker = false` → plaintext on port 1883.
- **No client-id constraint.** `clientId = Guid.NewGuid().ToString()` with `CleanSession = true`, so
  ids are disposable and there is no duplicate-eviction hazard for our own connections.
- **QoS** comes from `CrystalHES.MqttQualityOfServiceLevel`, clamped to `2` when out of range, and
  is applied to subscriptions. Its configured value was not supplied — see §13.
- HES uses MQTTnet's **managed** client with a 5-second auto-reconnect delay. Our `MqttNicClient`
  should behave the same way; MQTTnet v5 in the simulator is a separate codebase, so version drift
  is not a concern.

**The two credentials are not interchangeable.** The settings dump contains the same username with
two different passwords, and the source shows they belong to opposite ends of the link:

| Setting | Who uses it | Purpose |
|---------|-------------|---------|
| `CrystalHES.BrokerHost` / `BrokerPort` / `BrokerUsername` / `BrokerPassword` | **HES itself** | The credential `MQTTClientHelper` presents when HES connects to the broker |
| `CrystalHES.SetBrokerDetails` (JSON) | **the meter's NIC** | Not a connection setting at all — it is the *payload of a DLMS command*. `SetMQTTBrokerDetails` writes this structure to OBIS `0.0.128.1.17.255` on the meter, telling the NIC which broker, port, username and password **to connect to** |

**Which address to connect to — resolved by measurement, not assumption.** `eqa-broker.kimbal.io`
resolves to `13.234.62.165` (AWS ap-south-1) and `2406:da1a:5f3:cf00:c307:6e48:e4da:a5c`, and
**TCP 1883 is open and reachable** from a developer machine. The `BrokerURL` inside
`SetBrokerDetails` is `2401:4900:a07f:b2e3:…`, which is a *different host entirely* — `2401:4900::/32`
is a Reliance Jio mobile range, not AWS.

That is almost certainly not an error: the meters are 4G SIM devices, so the address HES pushes to a
NIC is plausibly the broker as reachable **from inside the carrier APN**, while `eqa-broker.kimbal.io`
is the same service's public face. Either way the conclusion is the same — the simulator is not on
the carrier network, so it **connects to the hostname**, never to the `SetBrokerDetails` address.

That left only the password ambiguity: same username, two values, and nothing in the source
disambiguates them because they are consumed by different actors. C-2 tries the meter-side password
first (we are impersonating a meter) and the HES-side one as fallback, logging which succeeded.

**Resolved by measurement — the HES-side password is the live one.** On first connect the
meter-side credential was rejected by the broker and the HES-side credential authenticated, on all
three transports:

```
Mqtt4G: credential 'meter-side' rejected by eqa-broker.kimbal.io:1883
Mqtt4G: connected to eqa-broker.kimbal.io:1883 as 'hes-side' (mqttmasteruser); subscribed to PollRequest/#
```

So the `SetBrokerDetails` credential is either stale or only valid from inside the carrier APN —
consistent with its `BrokerURL` being a Jio address rather than the AWS one. The fallback stays in
the code: it costs one failed connect at startup, it documents the ambiguity, and it means a future
credential rotation on either side still connects.

### 14.6 Corrections to earlier sections

1. **"5 bytes" was right for Wirepas, not for 4G.** Direct 4G MQTT (c/d) is **6** bytes — the length
   field is 2 bytes wide there, 1 byte in Wirepas. §5.1 corrected.
2. **c and d are one codec, not two.** HES serves both from a single client, topic pair and header
   format. Phase F collapses into Phase E.

Confirmed unchanged: the DLMS payload really is the complete wrapper frame in every variant (the
funnel is untouched), and gateway routing really is unnecessary — though for Kmesh we echo the
request's gatewayId, since it appears in the response topic.
