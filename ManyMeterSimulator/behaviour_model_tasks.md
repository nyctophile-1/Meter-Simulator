# Deterministic Meter Behaviour Model — Task Checklist

This checklist implements the plan in `behaviour_model_plan.md`. It deliberately
builds the deterministic serving foundation first. ML/calibration is a separately
deployable producer of immutable behaviour artifacts and is not a prerequisite for
correct state, profile, push, or inspector behaviour.

## Phase 0 — Architecture and scale guardrails

- [ ] Agree the fleet-scale target: one million provisioned cold meters, bounded active
  associations, target maximum scheduled-push rate, and profile retention tiers.
- [ ] Add an architecture decision record documenting the cold/warm/inbound-hot/push-work
  distinction and the push/pull parity invariant.
- [ ] Define measurable RAM budgets: zero retained state for an untouched meter;
  64–256 bytes for a sparse mutable overlay; no full session for scheduled push.
- [ ] Add benchmark tests proving one million provisioned meter identities do not
  materialize one million sessions or grow RAM linearly.
- [ ] Add allocation benchmarks for active sessions, resolver calls, profile pages, and
  scheduled-push worker throughput.

## Phase 1 — Shared template descriptors

- [ ] Define a stable template fingerprint based on the XML schema/content that matters
  to serving.
- [ ] Implement `TemplateDescriptor` cached once per XML/template fingerprint.
- [ ] Extract object/profile/push definitions and typed profile column layouts.
- [ ] Add semantic bindings: energy, instantaneous electrical values, clock, relay,
  alarms, event log, load/billing profile, and push objects.
- [ ] Validate a proposed behaviour profile against the descriptor before a batch can use it.
- [ ] Add descriptor tests for every currently supplied XML, including secure HTCT/LTCT
  templates where available.

## Phase 2 — Immutable behaviour artifacts

- [ ] Define artifact metadata: id, version, template fingerprint, timezone, master seed,
  training/calibration-source hash, and creation/validation data.
- [ ] Define `IMeterBehaviourModel` and deterministic `MeterSnapshot` contracts.
- [ ] Implement an explainable baseline model: daily/weekly load, stable node variation,
  cumulative energy, voltage/current/power-factor relationship, and clock behaviour.
- [ ] Require the energy-bearing power curve to be closed-form analytic (or bounded
  piecewise analytic) with an antiderivative; cumulative import/export energy at time T
  must evaluate in O(1), never by summing intervals from an epoch.
- [ ] Permit per-interval hash noise only for non-integrated instantaneous/display values;
  ensure it cannot influence cumulative energy registers.
- [ ] Expose and test separate energy-bearing and display-only instantaneous-power values
  where display variation is enabled, so their different semantics are explicit.
- [ ] Ensure all random-looking values use stable hashes of model version/seed, node id,
  signal, and time bucket.
- [ ] Pin an immutable behaviour artifact version to each batch; export/import it by
  reference and reject incompatible template fingerprints.
- [ ] Add reproducibility tests: same request on a new process/session must yield byte- and
  value-identical results where timestamps and version are identical.

## Phase 3 — Sparse runtime overlays and scenarios

- [ ] Define `IMeterRuntimeStore` for manual overrides, HES writes, acknowledgements,
  security counters, and non-derivable state.
- [ ] Implement compact in-memory sparse storage keyed by meter index.
- [ ] Define persisted representation and add a SQLite-backed implementation behind the
  same interface when persistence is required.
- [ ] Define batch/range/time scenarios with deterministic precedence over baseline state.
- [ ] Implement explicit override precedence and an effective-state explanation suitable
  for the Meter Inspector.
- [ ] Add `ISimulationClock` with real-time, fixed-clock, pause, and speed modes.

## Phase 4 — Unified resolver and DLMS integration

- [ ] Implement one `ResolveAndAdvance(meter, timestamp, operation)` path that returns
  availability, values, capture eligibility, push eligibility, and transitions.
- [ ] Route register/data/clock reads in `DLMSServerSession` through the resolver.
- [ ] Route HES writes into sparse runtime overlays rather than shared template objects.
- [ ] Apply meter availability before the DLMS brain is invoked so powered-off meters do
  not respond.
- [ ] Define active-connection behaviour when a meter powers off: silent timeout versus
  close socket, configurable per scenario/profile.
- [ ] Add parity tests for a meter across pull, profile read, push, restart, and a second
  simulator instance using the same artifact/overlays.

## Phase 5 — Generated profiles and events

- [ ] Implement `IProfileHistoryStore` with deterministic on-demand profile generation.
- [ ] Support typed selective access by range and entry without cloning XML profile buffers.
- [ ] Implement a small configurable hot profile ring for diagnostics only.
- [ ] Implement persistent history for rows that cannot be regenerated, with explicit
  retention and partitioning policy.
- [ ] Implement `IEventHistoryStore` and deterministic event transition generation.
- [ ] Add PowerFail/PowerRestore first: no normal capture, pull response, or push while
  powered off; policy-defined restore behaviour.
- [ ] Define quality/gap/zero-row handling for profile intervals during outage.
- [ ] Add overflow, ordering, duplicate-prevention, and restart-replay tests.

## Phase 6 — Scheduled profile/event push pipeline

- [ ] Define batch/profile schedules with cadence, delivery window, deterministic jitter,
  maximum encode concurrency, maximum send concurrency, retry, and late/skip policy.
- [ ] Implement one schedule/job per batch/profile, never one timer per meter.
- [ ] Process meter indexes as bounded streaming chunks.
- [ ] Extract `IMeterPushEncoder` from the full server session path.
- [ ] Build payloads from the exact resolver snapshot/profile row used for capture.
- [ ] Replace shared-template mutation and the process-wide push encode lock with a bounded
  isolated encoder pool or a projection-based encoder.
- [ ] Record sent, skipped-powered-off, skipped-no-push-setup, delayed, failed, and late
  counters separately.
- [ ] Load-test 15/30/60 minute cadences and prove stable RAM under sustained operation.

## Phase 7 — Meter Inspector and verification

- [ ] Add meter lookup by serial, index, IPv6, and node id.
- [ ] Show batch, XML descriptor, pinned behaviour model/version, and state explanation.
- [ ] Show values and their source: model, scenario, HES write, or manual override.
- [ ] Show current availability, relay/alarm state, clock, profile/event history, and
  scheduled-push eligibility.
- [ ] Add side-by-side comparison for selected meters to demonstrate deterministic
  meter-specific variation.
- [ ] Add privileged actions: force/clear override, reset state, inspect a timestamp, and
  trigger a push verification.
- [ ] Ensure Inspector calls the same resolver as live DLMS and push paths.

## Phase 8 — Model training/calibration module (future producer)

- [ ] Define a supported historical-data import format separate from XML templates.
- [ ] Implement validation: timestamp completeness, timezone, units/scalers, outliers,
  profile layout compatibility, and data coverage.
- [ ] Implement an initial explainable calibrator producing behaviour artifact parameters.
- [ ] Add output validation against held-out historical rows and plausible electrical bounds.
- [ ] Build staged UI: uploaded -> validating -> calibrating -> validating output -> ready ->
  rejected, with diagnostic messages.
- [ ] Preserve every published artifact immutably; batches choose a version rather than
  receiving automatic retraining.
- [ ] Evaluate ML alternatives only after representative multi-meter historical datasets
  exist; retain the same artifact/serving interface.

## Acceptance tests

- [ ] Same node id/time/model/version produces the same values/profile/event result across
  restarts.
- [ ] Cumulative energy at a far-future timestamp is evaluated in bounded time independent
  of the number of elapsed profile intervals.
- [ ] Per-interval display noise does not alter the cumulative-energy result for the same
  node id/timestamp/model version.
- [ ] Different node ids produce stable, plausible, non-identical values.
- [ ] A profile row pushed at time T equals the row returned by a later pull for T.
- [ ] A powered-off meter sends no normal push and returns no normal pull response.
- [ ] A restored meter resumes according to its configured capture/push policy.
- [ ] One million provisioned cold meters do not create one million sessions, timers, or
  per-meter profile buffers.
- [ ] Scheduled push workload retains bounded RAM over many cadence cycles.
- [ ] Replacing a model for future batches cannot change historic results for a batch pinned
  to an earlier artifact.
