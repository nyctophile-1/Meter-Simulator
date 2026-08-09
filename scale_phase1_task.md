# Phase 1 — Shared template model, cheap meters, instant StartBatch

Goal: make a meter cost almost nothing, so a batch can go live on the **StartBatch** click
instead of trickling into existence as the HES polls — and so push has something to push from.

Status: **items 1.1 and the critical half of 1.2 are implemented and green** (277 tests pass).
Items 1.3–1.6 remain.

## Measured result so far

Gate 0 was answered from the vendored Gurux source (see [scale_phase2_task.md](scale_phase2_task.md)):
sharing is safe, with one mandatory precondition — writes must be intercepted, now done.

| Template | Before | After | Build time |
|---|---|---|---|
| `Values_SZ0000014HP.xml` (4 MB) | ~5 MB/meter | **61.6 KB/meter** | 12.9 → **8.2 ms** |
| `SA1231166HP_values.xml` (0.1 MB) | — | **17.4 KB/meter** | → **1.2 ms** |

≈ **80× less memory per meter**, locked in by `SharedTemplateScaleTests`, which fails if per-meter
template loading is ever reintroduced.

**Not yet sufficient for the 2 M target**: 61.6 KB × 2 M ≈ 117 GB. The remaining cost is per-session,
not per-template, so items 1.3 (sparse state) and 1.4 (engine per connection) are still required —
and the next step should be a **memory profile** to locate the 61.6 KB rather than more estimating.

---

## 0. The correction that shapes this whole plan

> "We could copy the same DLMSServerSession by value and assign it to all the meters in that batch."

**Copying by value does not reduce memory — it increases it.** A copy is a second, equally large
object graph. Today only the meters the HES actually polls are built (lazy); copying eagerly at
StartBatch builds *every* meter in the batch. Same per-meter cost × more meters = strictly worse.
For a 2 M batch it is arithmetically impossible on any single machine.

The half of the idea that is right, and valuable: **stop paying the per-meter build cost.**
The fix is not *copy* — it is **share**. One object model per template, referenced by every meter,
with per-meter differences held as a small delta.

What a meter costs today, per `new DLMSServerSession(...)`
([DLMSServerSession.cs:72](MeterSimulator.Core/DLMS/DLMSServerSession.cs#L72) →
[MeterObjectLoader.Load](MeterSimulator.Core/DLMS/MeterObjectLoader.cs#L24)):

| Step | Cost | Per meter today |
|---|---|---|
| `GXDLMSObjectCollection.Load(xml)` | full disk read + XML parse (4 MB for `Values_SZ0000014HP.xml`) | ✗ repeated |
| `Deduplicate` | LINQ GroupBy over every raw object | ✗ repeated |
| `RewireCaptureObjects`, `FixProfileBufferTypes` | O(rows × cols) over every profile buffer | ✗ repeated |
| `ShiftBufferTimestamps` | HashSet of every timestamp + shift | ✗ repeated |
| `SeedRegisters` | sweep every object | ✗ repeated |
| Association `ObjectList.AddRange` ×2 | full object list copied into both associations | ✗ repeated |
| Retained graph | thousands of objects + profile buffers | ✗ retained |

Every one of these is identical for every meter built from the same template. That is the waste.

---

## 1. The enabling fact

**The object graph is already not the source of truth for register/data values.**
`PreRead` ([DLMSServerSession.cs:645](MeterSimulator.Core/DLMS/DLMSServerSession.cs#L645)) intercepts
`GXDLMSRegister` / `GXDLMSData` reads and answers from `_meter.GetValue(obis)` — the small per-meter
dictionary — and `PostWrite` writes back there. The DLMS objects are effectively a *schema*; the
values already live per-meter.

That is the seam the whole design hangs on: if values are served from the per-meter dictionary, the
object graph can be shared read-only across meters.

**Second enabling fact:** serial, node id, IPv6 address (and, on the merged branch, the crypto
identity) are all deterministic functions of the meter index (`MeterIdentity`, `MeterAddressing`).
They never need to be *stored* — only computed. A meter that has never been written to therefore
needs **zero** bytes of per-meter state.

---

## 2. Target model

Three tiers, replacing "one fat session per meter":

```
TemplateModel   (1 per template — immutable, shared)
    parsed once, deduped, rewired, timestamps shifted once
    profile buffers, associations, object list
        ▲
        │ referenced, never copied
        │
MeterState      (1 per DIVERGED meter — sparse, tiny)
    index → { overridden values, invocation counter }
    absent entirely for meters that have never been written
        ▲
        │ overlaid at read time
        │
DlmsEngine      (1 per ACTIVE CONNECTION — pooled, bounded)
    GXDLMSSecureServer + ciphering + block-transfer state
    borrowed on connect, returned on disconnect
```

A "live" meter stops being an object. It becomes *a row in a Running batch* — which is what makes
StartBatch instant and push trivial.

---

## 3. Work items

### 1.1 — Template model cache (biggest single win, lowest risk)

Cache the parsed `GXDLMSObjectCollection` per template path and hand the same instance to every
session instead of re-running `MeterObjectLoader.Load` per meter.

- New component alongside `TemplateRegistry`, keyed by resolved template path.
- Parse on first use; hold for process lifetime (a handful of templates, bounded).
- `ShiftBufferTimestamps` moves to load time — one shift per template, not per meter. This is also
  *more* correct: today every meter shifts to its own build instant, so meters built minutes apart
  disagree on profile timestamps.

**Do this first and measure.** It removes the repeated parse/dedup/rewire cost immediately and is
almost certainly the dominant cause of the current slowdown. It may resolve the reported pain on
its own, before any of the harder items.

### 1.2 — Remove per-meter mutation of the shared graph

Sharing is only safe once nothing writes into it. Known writers to fix:

| Writer | Today | Change |
|---|---|---|
| `ApplySerialOverride` | sets `serial.Value` on the graph | seed the per-meter dict instead — `PreRead` already serves `GXDLMSData` from there |
| `ApplyPushDestinationOverride` | sets `push.Destination` | already superseded: `PushNow` takes the destination as an argument |
| `SyncPushValues` | writes `reg.Value` / `data.Value` / `clk.Time` | build the notification from a per-meter view rather than mutating shared objects |
| Invocation counter | `PreRead`/`PreWrite` mutate `ic0.Value` on the shared object | move into per-meter state |
| `SeedClock` | one shared clock instant | intercept `GXDLMSClock` in `PreRead` and answer "now" |

**Gate**: an audit that no code path writes to a shared object outside these. A shared-graph write
that slips through is a cross-meter data leak — meter A's value appearing on meter B — which is
silent and very hard to trace. Worth a debug-only guard that fails loudly on unexpected mutation.

### 1.3 — Per-meter state becomes sparse

`DLMSMeter` currently allocates a `Dictionary<string, object?>` per meter and is eagerly seeded from
every Register/Data in the template ([DLMSServerSession.cs:89](MeterSimulator.Core/DLMS/DLMSServerSession.cs#L89)) —
so every meter carries a full copy of every value even when identical to the template.

Change to copy-on-write: no dictionary until something is written; reads fall through to the shared
template value. Serial/keys computed from the index, never stored.

Result: an untouched meter costs ~0 bytes beyond its index.

### 1.4 — Engine per connection, not per meter

`GXDLMSSecureServer` carries genuinely per-connection state (ciphering, invocation counter,
block-transfer buffers, connection state) and cannot be shared by concurrent connections. But it
*can* be created per connection over a shared `Items` collection.

- Acquire an engine on connect, release on disconnect; pool to avoid churn.
- Ceiling becomes `MaxConcurrentConnections`, not fleet size.

**This item carries the real technical risk and must be spiked before it is committed to — see
[scale_phase2_task.md](scale_phase2_task.md) Gate 0.** `GXDLMSServer.Initialize()` may mutate the
collection it is given (short-name assignment, association wiring). If it does, either the mutation
is idempotent and safe to run once per template, or this item needs a different shape.

### 1.5 — StartBatch semantics

Once 1.1–1.4 land, StartBatch does not build anything:

- flip batch status to Running (already the case),
- warm the template model if it is not cached yet (one parse, bounded),
- meters are addressable immediately — pull *and* push.

`MeterSessionManager.MaterializeBatch` (added for push) collapses to a status check, and the current
RAM-bound behaviour disappears.

### 1.6 — Dashboard meaning

"Live meters" currently counts built sessions. Under this model that number stops being meaningful —
it will either be zero or equal to the connection count. Replace with:

- **Provisioned** (sum of Running batch counts) — what the fleet is,
- **Active connections** — what is actually in flight,
- **Diverged meters** — meters carrying state, i.e. the only per-meter memory that exists.

---

## 4. Sequencing and gates

| Step | Item | Gate before moving on |
|---|---|---|
| 0 | Measure current per-meter RSS and build time | A number, not an estimate. Batch of 100, measure delta. |
| 1 | 1.1 Template cache | Build time per meter → ~0. Re-measure RSS; pull still passes for 10 K. |
| 2 | 1.2 De-mutation audit | No cross-meter leakage: write to meter A, read meter B, confirm unaffected. |
| 3 | 1.3 Sparse state | Untouched meter allocates nothing measurable. |
| 4 | 1.4 Engine pooling (**after Gate 0 spike**) | 10 K pull green; concurrency ceiling independent of fleet size. |
| 5 | 1.5 / 1.6 | StartBatch on a large batch returns immediately. |

Regression bar at every step: the existing 10 K pull test must stay green, and a push to a local
listener must still show correct per-meter source IPs.

---

## 5. What this does *not* solve

Phase 1 makes a meter cheap. It does not by itself make 2 M meters work — connection concurrency,
per-meter divergence at scale, sharding and load generation are
[scale_phase2_task.md](scale_phase2_task.md).
