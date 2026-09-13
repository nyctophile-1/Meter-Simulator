# Profile simulation tasks

- [x] Inspect local template, profile generation, scheduling, and push code.
- [x] Document proposed architecture, capture rules, integration gaps, and validation.
- [x] Incorporate separate working XML snapshots and bounded per-profile history into the plan.
- [x] Record user-approved Start simulation, per-profile automatic push, Send Push Now, and explicit Push saved history semantics.
- [ ] Receive target XML and confirm critical behavior listed in plan.md.
- [ ] Produce template capability/mapping report and preview records.
- [x] Implement fixed-period, daily-midnight, and calendar-monthly (billing) profile capture, plus an
  Instantaneous rule that updates current scalar values with no buffer/history. Event capture (random
  occurrence + paired restoration) remains out of scope pending event category/rate decisions.
- [x] Redesign working-state storage to be per-BATCH, not per-meter: every meter in a batch generates
  byte-identical simulated data (config-driven increments at the same boundaries), so
  `BatchProfileSimulationState` owns one shared, mutable object graph per batch (via the same
  `TemplateModelCache` sharing mechanism used for static templates), and `ProfileSimulationStateStore`
  persists exactly one working XML per batch. This replaces the original per-meter design, which grew
  to ~20,000 near-duplicate files in production with no cleanup (see `ProfileStateRetentionService`,
  which now sweeps stale batch folders regardless of whether the feature is enabled).
- [x] Implement working XML save/restore, validated atomic replacement, and per-profile oldest-record eviction.
- [~] Verify save/load fidelity, interrupted-save recovery, capacity limits, and pending-push survival after eviction. XML round-trip, recovery, capacity, reload, and idempotency tests exist; there is no pending-push queue yet.
- [x] Connect LS/DP/Billing pushes to exact captured records, reusing the existing generic
  `PushCoordinator.PushBatchAsync(..., pushSetupLogicalName:)` — no new transport/encoding was needed.
  Event pushes remain out of scope (Events itself is unimplemented). IP is deliberately NOT wired to
  auto-push (see below).
- [ ] Reconcile normal/custom pulls with the same meter data source.
- [x] Add operator-configurable automatic push per profile (`ProfileSimulationProfile.AutoPush`,
  default on) reusing the existing push pipeline. IP (Instantaneous) is the one profile kind where
  `AutoPush` is validated to always be false — IP data can only be sent via the existing manual
  "Send Push Now" action until randomized/live-feeling IP generation is designed.
- [ ] Implement Send Push Now from the latest saved record without creating or retimestamping data.
- [x] Generalize DLMS push to work for any profile-backed PushSetup a template defines (Block Load,
  Daily, Billing, Events, ...), not just Block Load specifically. See plan.md §3a — confirmed
  dispatch OBIS codes for all five profile types from `vayu-common`/`vayu-core`, then generalized
  `DLMSServerSession.SyncProfileBackedPushValues` (formerly `SyncBlockLoadPushValues`) to find its
  source profile by CaptureObjects/PushObjectList overlap, gated on a dedicated RTC Clock OBIS
  (`0.0.1.0.1.255`) so a non-profile push (Instant, Alert) is never mistakenly treated as
  profile-backed just because it happens to share a common register. The Testing page's "Send Push"
  dropdown is now computed from whatever PushSetups the batch's template actually defines (via
  `Description`), not a hardcoded list — Daily/Billing/Events show up automatically once a template
  defines their PushSetup. **What's left is a data/config task, not a code blocker**: someone needs
  to supply a real HES-used template XML with correctly authored Daily/Billing/Events
  `GXDLMSPushSetup` blocks (dispatch OBIS + exact field order, mirroring how Block Load's own
  PushSetup already does it in `SA1231166HP_values.xml`) — once that template exists, this mechanism
  needs no further code changes.
- [x] Fixed a latent bug this surfaced: `ProfileSimulationService`'s `AutoPush` was passing a
  profile's own LogicalName as the PushSetup filter — a different OBIS from the actual push dispatch
  channel for every profile type, including the already-shipped Block Load case. Added a required,
  distinct `ProfileSimulationProfile.AutoPushSetupLogicalName` field.
- [ ] Implement explicit bounded saved-history push selection and preserve failed-delivery retry eligibility.
- [ ] Confirm disable/restart behavior for pending deliveries and push enablement.
- [ ] Verify push-off capture/save, push-on capture/send, manual original timestamps, and no implicit history replay on enable.
- [ ] Expose an immutable per-meter snapshot reader for the separate meter-data-viewer workstream; integrate its production adapter here.
- [ ] Validate calendar, data, restart, transport, and receiver acceptance cases.

Implementation details and acceptance criteria: [plan.md](plan.md).

Independent viewer workstream: [viewer plan](../meter-data-viewer/plan.md) and [viewer tasks](../meter-data-viewer/task.md).
