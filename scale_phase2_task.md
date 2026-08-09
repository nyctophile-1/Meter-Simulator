# Phase 2 — Scaling the fleet to 2 million meters

Builds on [scale_phase1_task.md](scale_phase1_task.md), which makes a single meter cheap. This
document is about everything that only becomes a problem once there are millions of them.

Status: strategy only. No code written.

---

## 0. The question that decides the whole architecture

**2 million *provisioned* meters, or 2 million *concurrent connections*?**

These are different problems by two orders of magnitude, and the answer changes the plan:

| | Provisioned | Concurrent |
|---|---|---|
| What it costs | per-meter state (Phase 1 drives to ~0) | socket + kernel buffers + DLMS engine + PDU buffers |
| 2 M feasible on one box? | **Yes**, after Phase 1 | **No** — see §2 |
| Dominant constraint | RAM for diverged state | RAM per live connection, FDs, accept rate |

A real 2 M-meter HES does not poll 2 M meters simultaneously; it sweeps in waves. **Get the actual
expected concurrency from the HES team before building anything in §2.** If the answer is
"50 K concurrent out of a 2 M fleet", one adequately-sized instance plus Phase 1 is likely enough,
and the sharding work in §4 can be deferred entirely.

Everything below is ordered so the cheap answers are tried before the expensive ones.

---

## Gate 0 — The Gurux spike (blocks Phase 1 item 1.4)

Before committing to a shared object model, confirm the library tolerates it. One afternoon's work,
and the outcome changes the design.

Verify:

1. Does `GXDLMSServer.Initialize()` **mutate** the `GXDLMSObjectCollection` it is given
   (short-name assignment, association wiring, data-type fixups)? If yes — is it idempotent, so it
   can be run once per template rather than once per meter?
2. Can two `GXDLMSSecureServer` instances serve **concurrent** connections over the *same* `Items`
   collection without interfering? Drive two associations in parallel against one shared model and
   diff the responses against the per-meter-model baseline.
3. Does `GXDLMSProfileGeneric` read `Buffer` directly during encoding, or through the server's
   read path? This decides whether profile data can be shared or must be per-meter (it is the
   single largest memory item — `Values_SZ0000014HP.xml` is 4 MB, mostly buffer rows).
4. Does selective access (range/entry) mutate profile state during a read?

**If the answer to (2) is no**, the fallback is a *pool of complete engines* — N fully-built sessions
(N = concurrency ceiling, not fleet size), each rebound to whichever meter's state it is serving for
the duration of a connection. More per-engine memory, same asymptotics, no shared-mutation risk.
Plan for this branch; do not discover it late.

---

## 1. Measure before optimising

No target is meaningful without a current baseline. Establish, on the EQA box:

| Metric | How |
|---|---|
| Bytes per provisioned (untouched) meter | RSS delta over a batch of 100 / 1 000 |
| Bytes per active connection | RSS delta with N connections held open |
| Meter build time | log timing around session construction |
| Accept rate ceiling | connections/sec before the accept loop saturates |
| GC pressure | gen-2 collections + pause time under load |

Then the budget is arithmetic:

```
RAM ≈ (provisioned × per_meter) + (concurrent × per_connection) + shared templates + runtime
```

Re-measure after **each** Phase 1 item. The template cache (item 1.1) alone may move this enough
that most of §2 becomes unnecessary.

---

## 2. Connection-side scaling

Per active connection today: kernel socket buffers, the `PipeReader`/`PipeWriter` pair, the
`ConnectionState`, task machinery, and the DLMS engine — whose `Settings.MaxPduSize = 65535`
([DLMSServerSession.cs:66](MeterSimulator.Core/DLMS/DLMSServerSession.cs#L66)) can mean a 64 KB
buffer *per connection*. At 50 K concurrent that term alone is multi-GB.

Work items, cheapest first:

1. **Right-size PDU buffers.** 65535 is the maximum, not a requirement. Check what the HES
   negotiates and whether buffers are allocated eagerly or on demand.
2. **Make `listen(backlog)` configurable.** Hardcoded at 512
   ([TcpNicListenerService.cs:66](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs#L66));
   `host-prep.sh` already raises `somaxconn` to 65535 and flags this as P0-5. At high connect rates
   a 512 backlog silently drops SYNs, which looks like HES-side timeouts.
3. **Parallelise accept.** The accept loop is a single `while` + `AcceptAsync`
   ([TcpNicListenerService.cs:75](ManyMeterSimulator/ManyMeterSimulator/Networking/TcpNicListenerService.cs#L75)).
   Under a mass-reconnect storm this is a bottleneck — several listener sockets with `SO_REUSEPORT`,
   or several accept tasks on one socket.
4. **Pool buffers.** `ArrayPool`/`MemoryPool` for frame buffers to keep large arrays off the LOH.
5. **Bound and shed deliberately.** `MaxConcurrentConnections` is set to 2 000 000 in
   `appsettings.Production.json` — effectively unbounded, so overload becomes an OOM kill rather
   than a clean rejection. Set it to a number the box has actually been measured to survive.
6. **Idle reaping.** Already present (`SessionMaintenanceService`); at scale the sweep interval and
   idle timeout become the main lever on steady-state connection count. Verify the sweep itself is
   not O(fleet).

---

## 3. Per-meter state at scale

After Phase 1, only *diverged* meters cost anything. Two failure modes remain:

- **Divergence grows over time.** Every HES write and every push adds state. Over a long soak,
  "sparse" trends toward "dense". Track diverged-meter count as a first-class metric.
- **`Dictionary<string, object?>` per meter is heavy** — boxed values, string OBIS keys, hashtable
  overhead. At 1 M diverged meters this dominates. If measurement shows it matters, move to a
  columnar layout (OBIS interned to an int id; values in typed arrays indexed by meter) or spill
  cold meters to SQLite, which `MeterSessionManager`'s doc comment already anticipates as the
  intended persistence seam.

Don't build either until the numbers justify it.

---

## 4. Horizontal sharding (the answer if concurrency really is millions)

The index→address scheme makes this unusually clean: **a meter's identity is a pure function of its
index**, so a fleet splits by index range with no shared state and no coordination.

- Instance *k* owns indices `[k·R, (k+1)·R)` and a disjoint IPv6 prefix.
- No cross-instance communication: no meter exists on two instances.
- `batches.json` stays per-instance; give each instance a configured index offset so allocation
  cannot collide.
- The HES registration CSV (`/batches/{id}/meters.csv`) is already the hand-off artefact — it just
  gets produced per instance.

Open questions to settle before building: how batches are created across a shard set (per-instance
UI vs. one control plane), and whether the dashboard needs a fleet-wide aggregate view.

**Sequence this after §1–3.** Sharding multiplies operational cost (N hosts, N deploys, N
dashboards); it is the right answer only once a single well-tuned instance is proven insufficient.

---

## 5. Push at fleet scale

Push has the opposite shape to pull: pull is demand-driven by the HES, push is a **thundering herd
the simulator creates itself**. One click on a 2 M batch = 2 M outbound connections.

- Current `MaxConcurrency` (256) caps simultaneous sockets but still runs the whole batch to
  completion, with no progress, no cancellation, and no partial result.
- Needed before this is usable at scale: chunking, a progress surface in the UI, a cancel button,
  and an explicit rate limit (pushes/sec) so the receiver is not overwhelmed.
- Consider whether "push a batch" should even be synchronous — a queued background job with a
  status page fits the operation better than an HTTP-lifetime await.
- Receiver capacity is a real constraint: confirm what ingest rate the head-end sustains before
  aiming a million notifications at it.

---

## 6. Load generation

A 2 M-meter test cannot use a real HES. `ManyMeterSimulator/HESTestClient` is the existing lever —
scale it into a proper load generator with a defined connection profile (ramp rate, hold time,
exchanges per session, think time), reporting achieved concurrency, exchange rate and error rate.

Ramp: **10 K (known-good today) → 50 K → 250 K → 1 M → 2 M**, re-measuring the §1 metrics at each
step and stopping at the first step that degrades. The step that breaks tells you which constraint
binds — which is the only reliable way to know whether §2, §3 or §4 is the work that matters.

---

## 7. Observability

To debug at this scale you need, at minimum:

- provisioned / diverged / active-connection counts as distinct numbers (see Phase 1 item 1.6),
- accept rate, rejection reasons (already in `SimulatorMetrics`), exchange latency percentiles —
  p50/p95/p99, not just the current avg/max,
- GC gen-2 count and pause time,
- RSS and swap-in rate (host-prep provisions 2 GB of swap; swapping under load will present as
  mysterious latency rather than an error).

The dashboard's 2-second sample loop and its per-batch enumeration should be checked for
O(fleet) work before the fleet gets large.

---

## 8. Recommended order

1. **Gate 0 spike** — decides Phase 1 item 1.4's shape.
2. **Phase 1 item 1.1** (template cache) — likely fixes today's pain on its own; measure after.
3. **§1 baseline** at 10 K, then remaining Phase 1 items.
4. **§2 connection tuning**, then ramp per §6 until something breaks.
5. **§3 state compaction** only if divergence measurement demands it.
6. **§4 sharding** only if a single tuned instance provably cannot meet the *real* concurrency
   requirement from §0.
