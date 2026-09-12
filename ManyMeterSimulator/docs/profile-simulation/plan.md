# Profile simulation plan

Date: 2026-09-12. Status: proposal; implementation awaits the supplied XML and confirmation of the open contracts below.

## Outcome

Use an old meter XML as a schema and seed for continuously generated meter data. Generate block, daily, billing, and event records at their own capture times, retain consistent history for pulls, and push each newly captured record through the selected existing transport.

The simple public operation is `AdvanceMeter(meterId, simulationTime)`. Internally, scheduling, value generation, record storage, and transport are separate so a failed push never changes the captured reading.

## Existing source and integration points

- `MeterSimulator.Core/DLMS/MeterObjectLoader.cs`: loads XML and currently shifts historical timestamps toward now. Continuous simulation must use an explicit mode that bypasses repeated timestamp shifting for its history.
- `MeterSimulator.Core/DLMS/TemplateModelCache.cs`: shares template objects across meters. Keep schema shared; do not append per-meter generated rows into shared buffers.
- `MeterSimulator.Core/DLMS/DLMSServerSession.cs`: builds DLMS pushes from non-empty push setups and has special handling for the latest block row. Extend encoding to accept a specific captured record, including historical records queued for retry, rather than always selecting the latest row.
- `ManyMeterSimulator/Brain/PushScheduleService.cs`: an in-memory operator loop, not a durable calendar scheduler. Add a separate simulation scheduler without changing that testing feature's meaning.
- `ManyMeterSimulator/Brain/PushCoordinator.cs` and `.Mqtt.cs`: reuse TCP/MQTT delivery, identity, routing, ciphering, concurrency limits, and pacing.
- `ManyMeterSimulator/Networking/SmartNic/CustomProfileDataGenerator.cs`: has deterministic values but custom pull timestamp generation hardcodes 15-minute blocks. Reconcile this with the common meter data source so custom pulls and pushes cannot disagree.
- `ManyMeterSimulator/Brain/MqttPushProfiles.cs` and `PushCoordinator.Mqtt.cs`: template discovery exists; the custom template 93 path currently supports daily push only. Other custom profiles need verified packet layouts, not just new timers.

These findings are from local source inspection only. No live receiver behavior was verified.

## 1. Inspect and compile the supplied XML

Produce a capability table for every profile: logical name, semantic type, ordered capture objects and attribute indices, data types, scaler/unit, capture period, capacity, seed timestamp range, matching push setup, and supported transport encoding.

Resolve columns by explicit OBIS/class/attribute mappings. Distinguish interval energy from cumulative registers, capture timestamps from demand timestamps, and normal measurements from event/status codes. Do not guess unknown semantics from column position or silently replace unknown fields with random values.

Use XML readings as baseline values and optional load-shape samples. Keep the original XML unchanged. Missing profile buffers can still be supported if the schema and configured initial values are complete. Missing push setups require an agreed HES-compatible layout; a readable profile alone does not establish push support.

## 2. Choose the initial timeline

Recommended starting mode: initialize at a configured simulation start time, use validated old values as the baseline, and generate from the next completed boundary. Do not automatically create and push years of historical data.

Optional history mode: generate an explicitly selected recent window using the same model. If historical seed rows are retained or rebased, define a one-time mapping for each profile's calendar and timestamp fields. Never repeatedly move existing records forward. Show the resulting earliest/latest timestamps before enabling simulation.

## 3. Scheduling rules

All calendar boundaries use a configured meter timezone; storage keys use UTC instants. Capture time and send time are distinct.

Push actions in the table below apply only when automatic push is enabled for that profile. Generation and saving continue when automatic push is off.

| Profile | Proposed capture behavior | Push behavior |
|---|---|---|
| Block | XML capture period of 900/1800/3600 seconds, aligned to local day boundaries. Emit only completed intervals. | Queue one new record at each boundary. |
| DP / daily | At local midnight, close the previous day and capture the required daily registers/totals. Exact timestamp convention requires confirmation. | Queue after capture. |
| Billing | At 00:00 on the first local calendar day of each month, close the prior month. Use calendar months, never a fixed 30-day timer. | Queue once per monthly close. |
| Events | Seeded random occurrence times with configurable rates and enabled event categories; restore paired events after a configured duration. | Queue at occurrence and restoration where supported. |
| Instantaneous, if required | Read current model state at a separately configured interval. | Interval or on-demand; XML alone may not specify a schedule. |

For 15-minute blocks, captures are 00:15, 00:30, 00:45, 01:00, etc., assuming end-of-interval timestamps. Confirm that convention. Zero/missing block capture period is a configuration error requiring an explicit value; event and billing profiles can legitimately use calendar/event rules instead of a numeric period.

At midnight/month rollover, advance energy through the boundary, finish the final block, take daily and billing snapshots, then reset only the applicable period accumulators. Preserve lifetime cumulative energy. Define DST, clock-change, and mid-run capture-period-change behavior before enabling those scenarios.

## 4. One coherent value model

### Confirmed control semantics (2026-09-12)

The user approved these separate controls:

| Control | Required behavior |
|---|---|
| Start simulation | Generate scheduled records and save working state; does not itself enable automatic push. |
| Enable automatic push per profile | After a new capture is successfully saved, enqueue that exact record for delivery. |
| Send Push Now | Send the latest saved record for the selected profiles without creating a new capture or changing its timestamp. Report an empty/unsupported profile explicitly. |
| Push saved history | Explicitly send selected retained historical records. Enabling automatic push must not implicitly replay history. |

Enabling automatic push applies to future captures only. Records whose delivery failed while automatic push was enabled remain eligible for retry; they are distinct from records captured while push was off. The existing repeated-push testing loop remains a separate tool, not the simulation scheduler.

Example: for 15-minute LS, the 10:15 record is generated and saved at the completed boundary. Automatic push off means no send; on means that record is queued. Send Push Now at 10:22 sends the saved 10:15 record with its original capture timestamp.

Make capture commit and push-enablement evaluation consistent so a concurrent toggle cannot ambiguously enqueue a record. Still confirm how disabling automatic push affects already queued retries/in-flight sends, and whether enablement is restored after restart; the approval above does not settle those lifecycle details. A saved-history action needs an explicit bounded range/profile selection and must respect normal delivery pacing.

The read-only meter viewer is a separate workstream described in [meter-data-viewer/plan.md](../meter-data-viewer/plan.md). The simulation workstream owns the authoritative snapshot reader described there; the viewer must not generate data or trigger pushes just by being opened.

### Value generation

Maintain small per-meter state: seed, baseline registers, generation version, last processed boundary, period accumulators, demand state, and active events. Reuse immutable template schema across the fleet.

Generate a repeatable daily load curve with bounded per-meter variation. Derive interval energy by integrating power over elapsed time; update cumulative registers from that same energy. Daily/monthly interval totals must reconcile with their constituent intervals within rounding tolerances. If the XML captures cumulative daily/billing registers, snapshot those registers instead of substituting interval totals.

Example: a constant 2 kW load adds 0.5 kWh over a 15-minute interval. From a 1,000 kWh baseline, the next cumulative reading is 1,000.5 kWh. Changing the interval to 30 minutes adds 1 kWh under that same load.

Apply encoding scalers once at the boundary to the wire format. Preserve signedness, numeric limits, phase/category, import/export meaning, tariff registers, and maximum-demand semantics according to confirmed mappings. Events that imply an electrical change must affect subsequent readings consistently. Unsupported physical scenarios remain disabled.

## 5. Simple engine contract

Illustrative pseudocode, not an implemented API:

```text
AdvanceMeter(meterId, now):
    load meter checkpoint and compiled template
    enumerate due boundaries/events in chronological order, in bounded pages
    for each due item:
        advance shared electrical model to its capture time
        generate immutable profile record and updated meter state
        atomically save record, checkpoint, and pending-push item if automatic push is enabled
    return capture summary and next due time

PushWorker():
    claim pending item
    encode that exact record using its profile's verified push layout
    send through the existing TCP/MQTT path
    record transport outcome; retry with bounded backoff when appropriate
```

Generation identity includes meter, template/model version, profile, and capture instant; event identity also includes a stable sequence. Make generation idempotent across duplicate scheduler ticks and crashes. Persist RNG state or use deterministic event indexing so restart does not redraw events.

Use one coordinated scheduler and bounded workers, not one permanent timer per meter. Pace outbound sends without changing capture timestamps. At 100,000 meters and 15-minute capture, block pushes alone average about 111 records/second; measure actual encoding, storage, and transport capacity, including midnight bursts.

## 6. History, restarts, and delivery

User refinement (2026-09-12): create a separate working XML that saves updated values and the current bounded profile buffers. Keep the source template unchanged. Resume from saved working state on restart.

Proposed XML snapshot design:

- Keep a configurable maximum record count per profile, using the XML's `ProfileEntries` where valid and confirmed, or an explicit override. Do not use the current row count (`EntriesInUse`) as capacity. Confirm zero/missing capacities and any non-rollover event behavior.
- On capture, append the new record, remove the oldest captures exceeding the limit, and update `EntriesInUse`. Use capture time and stable sequence to determine age, not unvalidated XML ordering. Example: a block limit of 96 retains the latest 24 hours with 15-minute capture; it retains 48 hours with 30-minute capture.
- Preserve cumulative registers, daily/monthly accumulators, demand state, active events, and sequence counters when historical rows are evicted. Deleting old rows must not reduce lifetime energy or erase an active event awaiting restoration.
- Save an immutable snapshot of current values and retained buffers to a temporary XML in the destination directory, flush and validate it, then atomically replace the active snapshot using a mechanism verified on the target filesystem. Keep one previous valid snapshot for recovery; serialize saves to avoid an older write replacing newer state.
- Save simulation metadata as part of the same committed snapshot generation: meter identity, template fingerprint, model version, timezone, last captured boundaries, accumulator state, event/RNG state, and pending pushes. If Gurux XML cannot contain that metadata without losing round-trip compatibility, use a sidecar in a versioned snapshot bundle and atomically switch a manifest only after all files are complete. Independently overwriting XML and sidecar files is not an atomic commit.
- For the simple mode, commit after each capture group before releasing its pushes. On restart, load the last complete valid generation, restore metadata, and calculate the next due capture. Do not rebase its timestamps or reload the original template over saved state. Corrupt state should be reported and recovered from a validated backup, never silently reset.
- Keep separate state for meters with different readings. A single mutable XML shared across such meters would mix their history. For a large fleet, measure the cost of per-meter XML files and full-buffer rewrites before selecting save frequency. A durable change journal with periodic XML snapshots is an optional scale design requiring an explicit decision; snapshots alone only recover to their last successful save.

Bound hot memory and serve only the retained history for normal profile range/entry pulls. Both normal DLMS and custom pulls must read the same authoritative records through the meter brain; deterministic reconstruction must not expose records already evicted by the configured retention policy.

Retain history according to configured profile limits. Pending deliveries must retain their record even when normal history rolls over. Pin template/model versions so a later XML replacement cannot reinterpret queued data.

The pending-push queue has its own size/age limit; profile capacity alone does not bound total state during an outage. Confirm whether queue exhaustion pauses capture or drops pending deliveries with an explicit reported count. Do not silently discard unsent records because their profile rows were evicted.

On restart, identify missed captures from checkpoints. Proposed recovery: generate missed records within the configured retention window, with bounded catch-up work. Whether to push every missed record or only the newest requires confirmation. Report skipped history explicitly.

Local generation can be once per record; network delivery cannot be promised exactly once. A crash after send but before marking completion can cause a duplicate. TCP write/MQTT publish completion is transport evidence, not proof of HES ingestion. Track generated, queued, sent, failed, and receiver-confirmed counts separately where receiver evidence exists. Preserve existing protocol-specific security counter requirements during retry and restart.

## 7. Implementation order and acceptance

1. Import XML and display the capability/mapping report and sample generated rows.
2. Implement the deterministic engine, configured clock, capture rules, and history/checkpoints.
3. Prove one block record end to end through the selected transport, then add DP and billing.
4. Add verified event categories with occurrence/restoration and matching pushes.
5. Connect pull history to the same engine; add outbox recovery, pacing, and operator controls.
6. Validate fleet behavior and receiver ingestion before enabling the intended fleet.

Use an injectable simulation clock to test 15/30/60-minute boundaries, midnight, first-of-month, February/leap year, and year rollover without waiting in real time. Verify no future or duplicate captures, monotonic cumulative energy, aggregate reconciliation, event ordering, meter isolation, restart at capture/send boundaries, retained backlog behavior, and XML type/scaler/order fidelity. Decode pushes and compare against pulled records. Test TCP and MQTT independently for the requested scope; a socket write alone is insufficient receiver validation.

Operator controls: template and batch selection, profile enablement, timezone, capture period display/validated override, event rate/seed, retention and recovery policy, preview, start/pause/stop, next captures, queue depth, and delivery outcomes. Define pause semantics explicitly: pausing delivery and pausing the simulation clock are different actions.

## Decisions to confirm before implementation

The supplied AGENTS.md says: "Never assume when implementing critical functionalities, always confirm." This plan proposes behavior but does not implement uncertain contracts.

- The actual XML and any HES push mappings missing from it.
- Meter timezone; exact DP closing time and interval-start/end timestamp convention.
- Initial start/history mode and whether missed records should all be pushed after downtime.
- TCP, MQTT/Wirepas, or both; standard DLMS or custom format for each profile.
- Event categories, rates, restoration rules, and whether instantaneous push is also in scope.
- Fleet size, history retention, and desired realism (repeated seed shape or coherent varying consumption).
- Per-profile record limits, working XML save location, non-rollover event policy, and pending-push overflow behavior. XML snapshots are the requested saved-state format; any journal-based optimization needs a separate decision after scale measurement.
- Effect of disabling automatic push on pending/in-flight deliveries, and restoration of push enablement after restart. Future-capture-only enablement, separate manual push, and explicit history replay are already confirmed.
