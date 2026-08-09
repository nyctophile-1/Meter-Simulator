# BadComm — Field Communication Impairment Simulation

Implementation plan and task tracker.

**Goal:** make the simulated fleet behave like a real one, where a slice of meters never answer
and another slice answers slowly and unreliably — so HES retry logic and SLA budgets can be
exercised against realistic failure, not against a fleet that always responds in microseconds.

**Scope:** entirely NIC-level. The brain (DLMS engine) is untouched — this models field
communication, not meter behaviour.

---

## 1. What is being simulated

| Class | Behaviour | Default population |
|---|---|---|
| **Non-comm** | Never responds. Every command fails once the HES exhausts `max_tries`. | `nm` = 0.1% |
| **Bad-comm** | Latency multiplied 25× (≈5 s), **plus** a per-exchange drop chance. | `bm` = 5% |
| **Healthy** | Current behaviour: global network delay only. | remainder |

Bad-comm compounding, for reference: a command needs ~10 exchanges, so at `fr` = 5% per exchange
the command succeeds `0.95¹⁰ = 59.9%` of the time — roughly **40% of commands need a retry**.

`fr = 100%` requires no special case: every exchange drops, which is non-comm by definition.

### Global knobs

| Symbol | Meaning | Default |
|---|---|---|
| `nd` | Network delay range, all meters (already built) | **100–300 ms** (mean 200) |
| `nm` | Auto-allocated non-comm share | 0.1% |
| `bm` | Auto-allocated bad-comm share | 5% |
| `fr` | Per-exchange drop chance for bad-comm | 5% |
| `mult` | Latency multiplier range for bad-comm | **25×** (allowed 1–**100**) |
| `seed` | Reshuffles which meters are affected | 1 |

Validation ceilings: `nd` ≤ 10 000 ms, `mult` ≤ 100×. Enforced in the UI **and** clamped
server-side.

At these defaults a bad-comm meter sits at **2.5–7.5 s, mean 5 s** (`200 × 25`), and the worst case
(`300 × 25 = 7.5 s`) stays **below the 10 s saturation threshold** — so the multiplier keeps its
full meaning and the §2.3b band is only reached if an operator raises `nd` or the multiplier.

`mult` defaults to a degenerate range (25–25), so every bad-comm meter is equally slow. Widening it
(e.g. 20–30) is what creates meter-to-meter variety, since the multiplier is drawn once per meter
and then fixed.

All are global, applied retroactively to every batch.

---

## 2. Settled design decisions

Recorded with rationale so they are not relitigated.

### 2.1 Assignment is computed, never stored

A million meters rules out a per-meter flag, and "stays affected" rules out anything random at
runtime. Classification is a **pure function of the meter index**:

```
h = hash₁(seed, index) → [0, 1_000_000)      // parts per million
h <  nm_ppm              → NON-COMM
h <  nm_ppm + bm_ppm     → BAD-COMM
else                     → HEALTHY
```

Consequences, all of which are requirements:

- **Stable** — survives restart, redeploy, and rebuild. No state to persist or migrate.
- **Retroactive** — changing `nm` reclassifies the entire fleet instantly.
- **Nested** — a meter is non-comm *iff* `h < nm`, so raising `nm` only ever adds meters and never
  releases one that was already affected. This property is why both bands share **one** hash with
  cumulative thresholds; two independent hashes would break it.
- **O(1), allocation-free** — viable on the hot path at fleet scale.

⚠️ Must be a stable hash (SplitMix64 or FNV-1a). `Object.GetHashCode()` is randomised per process
and would silently reshuffle the affected population on every restart.

### 2.2 Per-meter severity, per-exchange jitter

A bad meter is *consistently* bad, but not identically slow every time:

```
mult  = hash₂(seed, index) → [multMin, multMax]     // fixed for this meter, forever
delay = rand(ndLower × mult, ndUpper × mult)        // fresh draw per exchange
```

⚠️ `hash₂` must use a different salt from `hash₁`. Sharing one stream correlates severity with
band position, making every meter near the band edge the slowest one.

### 2.3 `nd = 0` is treated as 1 ms

With `nd` at 0–0 the multiplier has nothing to act on, so the effective base is
`max(1, ndDraw)`.

### 2.3b Delay ceiling: saturate into an 8–12 s band

`SaturationThresholdMs = 10_000`, and beyond it the delay is **not** clipped to a constant — it is
redrawn in a jittered band around the threshold:

```
healthy   delay = ndDraw                       // nd is bounded ≤ 10 s by validation
bad-comm  raw   = max(1, ndDraw) × mult
                  raw ≤ 10_000 → delay = raw
                  raw >  10_000 → delay = rand(8_000, 12_000)     // mean 10 s

FINAL     delay = min(delay, 12_000)           // unconditional hard ceiling
```

**No delay ever exceeds 12 000 ms**, whatever the arithmetic produces. The final `min` is redundant
today (the band already tops out at 12 000) and is kept deliberately: it makes the ceiling a
property of the code rather than of the current formula, so a future change to the band or the
multiplier cannot quietly breach it. That is the number the idle timeout must stay clear of (§4).

Why a band rather than a clip: clipping collapses the tail onto exactly 10.000 s, so every
saturated exchange reports an identical value and the latency histogram becomes a single spike. The
8–12 s band keeps the same mean while preserving variance, which is what makes the tail look like
real jittered timeouts.

Saturation occurs when `ndDraw > 10_000 / mult`. **At the shipped defaults it never fires**
(`300 × 25 = 7.5 s`). It is easily reached once an operator raises either knob though: at the
maximum multiplier of 100×, any `nd` draw above 100 ms saturates, so the default `nd` band alone
(100–300 ms) would put essentially every bad-comm exchange into the 8–12 s band. Hence the
mandatory warning in P4-7.

Minor discontinuity, accepted: `raw` just under the threshold gives ~10 s, while just over it can
give 8 s. Harmless, and indistinguishable from jitter in practice.

`nd` itself is bounded at 10 s by validation (UI `Max` plus a server-side clamp), so a healthy
meter never reaches saturation — the band only ever applies to the bad-comm product.

**The UI must warn when saturation will occur**, since a saturated configuration silently discards
the multiplier's meaning. See P4-7.

### 2.4 Non-comm = accept then stay silent

The app **cannot** produce a genuine SYN-drop: one wildcard socket on `[::]:4059` means the kernel
completes the handshake before `accept()` returns. Available options and why silence wins:

| Approach | HES sees | Cost to HES |
|---|---|---|
| Accept then close | connection reset — fast | ~0 ms |
| **Accept then stay silent** ✅ | read timeout | **full HES timeout** |
| SYN drop (blackhole /128 routes) | connect timeout | full timeout, but needs root + sync |

Silence is chosen for **SLA fidelity**: a real non-comm meter costs the HES its whole timeout on
every retry. Fast-failing would burn `max_tries` in milliseconds and understate the SLA impact,
which is the specific thing this feature exists to measure.

Held connections are self-limiting — the HES closes the socket when its own timeout fires, so a
connection is held for one HES timeout, not until the idle sweep. ~1,000 sockets at the default
`nm` against a 2,000,000 `LimitNOFILE`.

*Future option if the HES ever needs to distinguish connect-timeout from read-timeout:* a
`blackhole` /128 route per non-comm meter beats the `/80` local route and is silently discarded by
the kernel. Deferred — it needs root and a sync job, breaking the NIC-level-only constraint.

### 2.5 Rules operate on the numeric index

Serial and index are the same number, so every matcher is an integer predicate and no string
matching reaches the hot path.

### 2.6 Manual beats auto

```
first matching enabled rule (by Order) → else auto classifier → else healthy
```

A `Healthy` rule effect exists specifically to carve a known-good demo meter out of an auto band.

---

## 3. Architecture

### 3.1 Config (new `MayaRuntimeConfig` section)

```json
"BadComm": {
  "Enabled": true,
  "Seed": 1,
  "Auto":     { "NonCommPercent": 0.1, "BadCommPercent": 5.0 },
  "Defaults": { "FailureRatePercent": 5.0, "MultiplierMin": 25, "MultiplierMax": 25 },
  "Rules": [
    { "Id": 1, "Name": "Feeder-7", "Enabled": true, "Order": 1,
      "Match":  { "Kind": "Range", "From": 5000, "To": 5999 },
      "Effect": { "Kind": "BadComm", "FailureRatePercent": 30, "MultiplierMin": 200, "MultiplierMax": 400 } }
  ]
}
```

Matchers: `Range(from,to)` · `Modulo(m,r)` · `List(ids)`
Effects: `NonComm` · `BadComm(fr, multMin, multMax)` · `Healthy`

### 3.2 Classification is cached per connection

Classification depends only on the index, so it is evaluated **once at accept()** and cached on
`ConnectionState` — keeping rule evaluation off the per-exchange path entirely.

Retroactivity is preserved with a **generation counter** on the config snapshot: if it differs from
the one cached on the connection, re-evaluate. One `int` comparison per exchange.

### 3.3 Hot path

Same place the network delay already sits — NIC holds the frame, brain has not seen it.

```
NON-COMM   → swallow. No reply, no exception, connection left open.
BAD-COMM   → delay = max(1, ndDraw) × meterMultiplier
             then P(fr%) → swallow, else forward to brain
HEALTHY    → unchanged
```

---

## 4. Idle sweep interaction — resolved by the 10 s cap

`ConnectionState.Touch()` is called when a frame arrives and after a reply is written, so nothing
touches during a delay: a delayed exchange looks idle for its whole duration.

Without a ceiling this was a real hazard — `200 ms × 500 = 100 s` would be reaped mid-exchange by a
45 s timeout. **The saturation band (§2.3b) removes it.** Maximum time without a `Touch()` is now
**12 s** (the top of the band) plus brain time, comfortably inside any timeout ≥ 30 s.

Consequences:

- `IdleTimeoutSeconds` 300 → 45 is safe with no other change.
- Marking connections busy during an exchange is **no longer required**. Retained in the backlog
  as defensive hardening only, in case the cap is ever raised.

⚠️ The invariant only holds while the ceiling is enforced on **both** `nd` (≤ 10 s) and the
bad-comm product (→ 8–12 s band). Raising either above the idle timeout reintroduces the bug — the
values are coupled and must be changed together.

---

## 5. Task list

### P0 — Delay cap (no dependencies)

- [x] **P0-1** Enforce the 10 s bound on the network delay: clamp in
      `NetworkDelaySettings.TryUpdate` **and** set `Max="10000"` on both dialog inputs.
      *Accept:* 20000 cannot be saved from the UI, and is clamped if injected via config.
- [x] **P0-3** Change the shipped `nd` default from `0–0` to **100–300 ms** in
      `NetworkDelayOptions`. ⚠️ Behaviour change for fresh deployments: meters stop answering
      instantly out of the box. Existing hosts are unaffected — a persisted value in
      `maya-runtime-config.json` outranks the config default.
- [x] **P0-2** Reduce `IdleTimeoutSeconds` 300 → 45 in `appsettings.Production.json`.
      Safe once P0-1 holds; no other change needed.
- [ ] *(Deferred)* Mark connections busy during an exchange — defensive only, needed solely if
      `MaxDelayMs` is ever raised above the idle timeout.

### P1 — Classifier and config (no behaviour change)

- [x] **P1-1** `BadComm/StableHash.cs` — SplitMix64 with salt. *Accept:* unit-tested identical
      output across processes.
- [x] **P1-2** `BadComm/BadCommConfig.cs` — config section, matchers, effects, added to
      `MayaRuntimeConfig`. *Accept:* an existing `maya-runtime-config.json` without the section
      still loads (missing section → defaults).
- [x] **P1-3** `BadComm/MeterClassifier.cs` — immutable compiled snapshot + generation counter;
      `Classify(index) → Healthy | BadComm(fr, mult) | NonComm`. Rules first, then auto bands.
- [x] **P1-4** `BadCommSettings` singleton mirroring `NetworkDelaySettings`: loads from the runtime
      config store, `TryUpdate` writes through, volatile snapshot swap.
- [x] **P1-5** Unit tests — determinism, distribution within ±10% of target at 1M samples,
      **nesting** (raising `nm` never releases a meter), rule precedence, `hash₁`/`hash₂`
      independence.

### P2 — NIC integration (behaviour)

- [x] **P2-1** Classify at `accept()`, cache on `ConnectionState` with the config generation.
- [x] **P2-2** Non-comm: swallow the request, no reply.
- [x] **P2-3** Bad-comm: multiplied delay + per-exchange drop.
- [x] **P2-4** `max(1, ndDraw)` base so the multiplier works at `nd = 0`, the saturation band
      (`raw > 10_000 → rand(8_000, 12_000)`), and the unconditional final `min(delay, 12_000)`.
      *Accept:* property test over the full input space (`nd` 0–10 000 × `mult` 1–100) asserts
      `delay ≤ 12_000` in every case, and that saturated draws are spread across 8–12 s rather
      than constant.

### P3 — Metrics

- [x] **P3-1** Counters: exchanges dropped (non-comm), dropped (bad-comm), delayed; avg/max
      bad-comm latency tracked **separately** from `AvgNetworkLatency` — a 500× outlier would
      otherwise make that average meaningless.
- [x] **P3-2** Fleet composition (healthy / bad-comm / non-comm) computed by walking batch index
      ranges; **cached**, recomputed on config change, not per dashboard refresh.
- [x] **P3-3** Add the new counters to the periodic metrics log line.

### P4 — BadComm page

- [x] **P4-1** New page `/badcomm` + nav entry after Setup.
- [x] **P4-2** Move the global network delay control here from Setup.
- [x] **P4-3** Auto allocation controls: `nm`, `bm`, default `fr`, multiplier range (`Min="1"`
      `Max="100"`), seed. Same validation server-side.
- [x] **P4-4** Manual rules table: add / edit / delete / reorder / enable.
- [x] **P4-5** **Explain a meter** — enter `MY000000216` → shows classification and the reason
      ("rule #3 Feeder-7" or "auto band, h=312 ppm"). This is what makes a hash-based classifier
      operationally acceptable.
- [x] **P4-6** Live preview of fleet composition before applying, plus the existing confirm-popup
      pattern.
- [x] **P4-7** **Saturation warning.** Show the effective bad-comm delay range as the operator
      types, and warn when the configured `nd` × multiplier crosses 10 s — a saturated setup throws
      the multiplier away, so the operator should know before applying, not after reading a
      histogram. Three states:

      | Condition | UI |
      |---|---|
      | `ndUpper × multMax ≤ 10_000` | plain text: `Effective delay 2.5 – 7.5 s` (the default case) |
      | partially above | warning: `Some exchanges saturate → 8–12 s band` |
      | `ndLower × multMin ≥ 10_000` | warning: `Every bad-comm exchange saturates; the multiplier has no effect. Lower nd or the multiplier to see variation below 8 s.` |

### P5 — Dashboard

- [x] **P5-1** "Comms health" card: composition bar + dropped-exchange counters + avg bad-comm
      latency.

### P6 — Verification

- [x] **P6-1** Classification identical before and after a restart. *Verified:* 420/20/0 split and
      every setting identical after a full process restart.
- [ ] **P6-2** Non-comm meter: HES sees a read timeout, command fails after `max_tries`.
- [ ] **P6-3** Bad-comm meter: measured latency inside the multiplied band; observed drop rate
      within tolerance of `fr`.
- [ ] **P6-4** Changing `nm` live reclassifies without restart, including open connections
      (generation counter).
- [x] **P6-5** No regression for healthy meters; all 50 pre-existing tests still pass (69 total).

### Remaining verification needs a live HES

P6-2 to P6-4 exercise HES retry behaviour and cannot be proven from the simulator side alone.
Run them against the QA HES once the fleet is registered.

---

## 6. Open question

**Does the HES distinguish connect-timeout from read-timeout** in retry logic or SLA accounting?
If identical, §2.4 silence is strictly correct and the blackhole-route option can be dropped
permanently. If different, non-comm may need to move to the routing layer.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Unstable hash reshuffles the population on restart | P1-5 determinism test |
| Idle sweep reaps slow exchanges | Resolved by the 10 s cap (§2.3b, §4) |
| Cap raised later without raising the idle timeout | Documented coupling in §4; P6-3 asserts the cap |
| Rule evaluation on the hot path at 1M meters | Per-connection caching (P2-1); integer matchers only |
| Bad-comm latency distorts the existing latency average | Separate counters (P3-1) |
| Operator cannot tell why a meter is impaired | Explain-a-meter tool (P4-5) |
