# Profile simulation tasks

- [x] Inspect local template, profile generation, scheduling, and push code.
- [x] Document proposed architecture, capture rules, integration gaps, and validation.
- [x] Incorporate separate working XML snapshots and bounded per-profile history into the plan.
- [x] Record user-approved Start simulation, per-profile automatic push, Send Push Now, and explicit Push saved history semantics.
- [ ] Receive target XML and confirm critical behavior listed in plan.md.
- [ ] Produce template capability/mapping report and preview records.
- [ ] Implement common meter data engine and calendar scheduling.
- [ ] Add history/checkpoints and durable pending delivery.
- [ ] Implement working XML save/restore, atomic snapshot commits, and per-profile oldest-record eviction.
- [ ] Verify save/load fidelity, interrupted-save recovery, capacity limits, and pending-push survival after eviction.
- [ ] Connect block, DP, billing, and event pushes to exact captured records.
- [ ] Reconcile normal/custom pulls with the same meter data source.
- [ ] Add operator controls and bounded fleet scheduling.
- [ ] Implement independent generation and automatic-push controls; queue only future captures while enabled.
- [ ] Implement Send Push Now from the latest saved record without creating or retimestamping data.
- [ ] Implement explicit bounded saved-history push selection and preserve failed-delivery retry eligibility.
- [ ] Confirm disable/restart behavior for pending deliveries and push enablement.
- [ ] Verify push-off capture/save, push-on capture/send, manual original timestamps, and no implicit history replay on enable.
- [ ] Expose an immutable per-meter snapshot reader for the separate meter-data-viewer workstream; integrate its production adapter here.
- [ ] Validate calendar, data, restart, transport, and receiver acceptance cases.

Implementation details and acceptance criteria: [plan.md](plan.md).

Independent viewer workstream: [viewer plan](../meter-data-viewer/plan.md) and [viewer tasks](../meter-data-viewer/task.md).
