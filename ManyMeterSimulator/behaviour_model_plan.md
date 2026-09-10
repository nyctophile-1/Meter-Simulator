# Deterministic Meter Behaviour Model — Plan

## Purpose

Make a simulator meter an evolving, reproducible digital twin without retaining a full
DLMS object graph or 35–45 days of profile rows for every provisioned meter.

For a normal meter, the same inputs must always return the same result, even after a
process restart or from a different simulator instance:

```text
(template descriptor, behaviour-model version, node id, UTC timestamp, sparse overrides)
    -> effective meter snapshot
```

The snapshot is the single truth used by DLMS pull, profile reads, scheduled push,
alarm/event push, and the Meter Inspector. Hot/cold is a memory-lifecycle concern only;
it must never create different realities for pull and push.

## Why this is needed

The current merged brain correctly shares each parsed XML model across the meters that
use it, but every materialized `DLMSServerSession` still costs about 20–30 KB in current
operation. Keeping one such session per meter is not compatible with a fleet of
1,000,000 meters (roughly 20–30 GB before profile history).

Large secure HTCT/LTCT templates can also contain substantial profile data. Copying
profile buffers or Gurux object graphs per meter would turn a multi-GB shared template
into a TB-scale per-fleet memory requirement.

The design target is therefore:

> Provisioned meter count costs close to zero RAM. Active connections, bounded worker
> pools, shared models, and explicitly retained deviations determine RAM use.

## Domain model

```text
Batch
├─ Template fingerprint
│  └─ shared template descriptor: objects, OBIS bindings, profiles, push layouts
├─ Behaviour model artifact (pinned version)
│  └─ deterministic baseline of how this family/project behaves
├─ Scenario overlays
│  └─ batch/range/time-based outages, tariff changes, etc.
└─ Sparse meter overlays
   └─ HES writes, manual overrides, acknowledgements, exceptional state

EffectiveMeterSnapshot
├─ availability / response eligibility
├─ capture and push eligibility
├─ register/data values and clock value
├─ relay/tamper/alarm state
├─ profile-quality flags and profile rows
└─ generated event transitions
```

An XML answers **what the meter exposes**. A behaviour model answers **how that meter
type/project behaves over time**. The two are deliberately separate: the same HTCT
template can be used by two projects with materially different consumption and outage
behaviour.

## Shared template descriptor

Build and cache one descriptor for each distinct XML/template fingerprint. It maps
template-specific object names to semantic capabilities:

```text
Semantic capability          Template-specific mapping
---------------------------  --------------------------------
ImportEnergy                 1.0.1.8.0.255 (or template variant)
ExportEnergy                 template-specific OBIS
InstantaneousVoltage         one or three phase objects
LoadProfile                  profile logical name + typed columns
EventLog                     profile logical name + event columns
PushProfile                  PushSetup object / payload projection
```

Behaviour profiles must validate against this descriptor. A profile requiring three
phase voltage/current cannot be assigned to a single-phase XML that lacks those
objects.

## Behaviour model artifact

The brain only *serves* immutable artifacts. Training/calibration is a separate module
and is never performed while handling DLMS traffic.

Each artifact is versioned and records:

- template fingerprint and compatible descriptor version;
- model id/version and stable master seed;
- training-source hash and time range;
- timezone and daylight-saving policy;
- trainer/calibrator version and validation metrics;
- semantic capability/profile mappings;
- model parameters and output bounds.

Once assigned to a batch, an artifact version is immutable. Replacing it silently
would make a historical profile query return different rows after a restart.

### Model evolution

The serving interface must not depend on a particular algorithm. Start with an
explainable deterministic statistical/generative model:

- daily/weekly/seasonal load shape;
- node-specific stable variation;
- correlated voltage, current, power factor, and active power;
- cumulative import/export energy derived by integration;
- empirical event/outage distributions;
- project-specific calibration.

Later, a trained ML model may implement the same interface when sufficient historical
data across many real meters exists. One XML exported from one meter is generally an
excellent schema/sample source but not by itself enough evidence for fleet-wide ML.

## Deterministic serving API

The central contract is conceptually:

```csharp
MeterSnapshot ResolveAndAdvance(
    MeterRef meter,
    DateTimeOffset utc,
    MeterOperation operation);

ProfilePage GetProfile(
    MeterRef meter,
    ProfileId profile,
    DateTimeOffset fromUtc,
    DateTimeOffset toUtc);

IReadOnlyList<MeterEvent> GetEvents(
    MeterRef meter,
    DateTimeOffset fromUtc,
    DateTimeOffset toUtc);
```

`MeterOperation` distinguishes Pull, ProfileCapture, ScheduledPush, AlarmPush, and
Inspect for observability, but must not lead to incompatible values. All paths use the
same `MeterSnapshot` for a given meter and timestamp.

Node-specific variation is based on stable hashing of model version/seed, node id,
signal, and time bucket—not `Random()` or mutable process state. Generated quantities
must remain physically coherent: power drives cumulative energy, and voltage/current/
power-factor agree with active power.

### Energy-integrability invariant

The energy-bearing active-power function must be a small closed-form analytic curve,
or a small piecewise analytic curve, with an antiderivative. A bounded harmonic/Fourier
series with node-derived coefficients is an appropriate initial form:

```text
P_energy(node, t) = baseline + trend(t) + sum(amplitude_i(node) * sin(omega_i * t + phase_i(node)))
E(node, T) = E_at_epoch(node) + integral of P_energy(node, t) from epoch to T
```

Consequently, cumulative import/export registers at any timestamp are evaluated in
O(1) (or O(number of configured piecewise schedule boundaries)), never by summing
profile intervals since an epoch. Daily/weekly tariffs and seasonal regimes may be
piecewise analytic; their number of rules is bounded by the shared behaviour artifact,
not by fleet size or elapsed time.

Per-interval hash noise may be used only for non-integrated instantaneous/display
quantities, such as a realistic flicker in displayed voltage or instantaneous demand.
It must never feed integrated/cumulative energy registers. The snapshot should
explicitly distinguish `EnergyBearingPower` from any `DisplayedInstantaneousPower`
variation so this deliberate distinction is testable and does not create accidental
energy drift.

## State and parity rules

Availability is resolved before any operation:

| Effective state | DLMS pull | Profile capture | Scheduled push |
|---|---|---|---|
| Powered off | no response / configured disconnect | no normal row | skipped, never sent |
| Available | current snapshot values | capture row | send payload built from that row/snapshot |
| Alarm/tamper | state/event data returned | policy-driven capture | alarm/profile push per policy |
| Relay disconnected | reachable; values reflect relay state | policy-driven capture | policy-driven push |
| Link impairment | meter state remains valid; NIC may drop/delay | capture may continue | send may fail/drop at NIC |

For a capture at time `T`, the profile row and the pushed values both come from one
resolved snapshot at `T`. A later HES profile read regenerates or retrieves that exact
row. This is the required push/pull parity guarantee.

## Events and alarms

Events are state transitions, not independent push-side calculations:

```text
PowerFail begins -> PoweredOff -> create event once -> no normal push/pull/capture
PowerRestore     -> Available  -> create event once -> resume policy-defined operation
```

Common batch/range events are represented declaratively as scenarios rather than one
RAM object per affected meter. Sparse per-meter overlay entries are created only for
individual deviations, acknowledgements, HES writes, or non-derivable history.

## Profiles and history

Profiles use three storage modes:

1. **Deterministic on demand** — generate requested historic rows from the model; zero
   retained per-meter rows.
2. **Hot bounded ring** — recent diagnostics/push verification only; configurable small
   retention.
3. **Persistent history** — SQLite or another partitioned store for audit/billing data
   that cannot be regenerated.

Never use per-meter copies of the XML `ProfileGeneric` buffer. Do not represent profile
history with per-row dictionaries or `object[]`; use compact typed/encoded record
batches and bounded response buffers.

## Runtime memory model

| Item | Target memory behaviour |
|---|---|
| XML and template descriptor | once per distinct XML |
| Behaviour artifact | once per model version, shared |
| Untouched/cold meter | 0 bytes per meter |
| Sparse override/state entry | target 64–256 bytes, only where needed |
| Active inbound session | current ~20–30 KB; bounded by active connection count |
| Scheduled push | fixed-size queue, encoder pool, and buffers; no per-fleet allocation |
| Profile/event history | bounded ring or disk; never unbounded RAM |

The normal fleet must be able to provision one million cold meters without RAM growing
linearly with that count. A million scheduled pushes every 15 minutes is still a
throughput problem (~1,111 pushes/sec), but must be processed as streaming work with
stable RAM, not as one million loaded sessions.

## Scheduled push at fleet scale

Use one scheduler entry per batch/profile cadence, not one timer per meter. A stable
index-derived offset distributes meters throughout the delivery window. A bounded work
pipeline performs:

```text
resolve snapshot -> capture eligible profile row -> build payload -> send -> discard work item
```

The capture snapshot is passed directly to the encoder. A powered-off meter yields a
`SkippedPoweredOff` result rather than a payload or transport failure.

The existing push path builds data through `DLMSServerSession` and temporarily mutates
shared template objects under a process-wide lock. That is suitable for small manual
pushes but must be refactored before fleet scheduled push. Create a bounded, isolated
push encoder/projection path that does not allocate a server session for each send and
does not mutate shared template objects.

## Session lifecycle

`DLMSServerSession` becomes inbound protocol/association machinery, not the owner of
durable meter life. Keep it during an active association, then evict it using a bounded
idle policy. Rebuild it from the shared template plus the effective runtime state when
needed. This is only safe once mutable meter state no longer resides exclusively inside
the session.

## Meter Inspector

Build the Inspector early, against the same resolver used by DLMS and push. It must
inspect a cold meter without materializing a full server session.

It shows:

- batch, XML/template fingerprint, behaviour model/version, and deterministic seed;
- effective operational state and why it applies;
- values with source: template default, derived model, scenario, HES write, or override;
- current/profile/event snapshot and retention source;
- compare view for selected meters; and
- admin controls for sparse overrides and reset.

## Non-goals for the foundation

- No ML model training inside the runtime brain.
- No full profile history resident in memory for every meter.
- No one timer/task/server session per provisioned meter.
- No silent changes to a batch's pinned behaviour model.
- No independently calculated pull and push values.
