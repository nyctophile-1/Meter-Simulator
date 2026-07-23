# Brain ↔ NIC Merge — Task Tracker

Merging the DLMS **brain** (`MeterSimulator.Core`, formerly `Meter-Simulator`) into the
**NIC/MMS host** (`ManyMeterSimulator`: Blazor UI + TCP listener + batch provisioning).
The brain becomes the in-process request/response engine behind `IMeterSimBridge`; the NIC
owns the HES-facing TCP. See `ManyMeterSimulator/implementation.md` §10.6.

## Confirmed decisions

- **Seam:** brain receives the **full WPDU frame** (Gurux `GXDLMSSecureServer`, `InterfaceType.WRAPPER` owns wrapper parse/build).
- **Templates:** per-batch DLMS model (XML) chosen in the UI, from a repo `Templates/` folder **or** browser upload into it.
- **No template on a batch → reject the connection.**
- **Per-meter distinct DLMS identity** (server address / system title / keys) derived from the IPv6 index.
- **Unify on net10.0.** Push **deferred** (code stays, timers unwired).

## Domain invariants (authoritative)

- **IPv6 = durable meter identity** (SIM-assigned, stable for field life). Primary key; outlives any connection.
- **Same IP both directions:** HES pulls from `IP:4059`; push must originate from that same IP (future: bind outbound socket to the meter's IPv6).
- **One meter = one authoritative mutable state**, shared by pull AND push. Template is a *seed*: build once, then the live model is the truth — never rebuilt on reconnect. All per-meter state goes through `MeterSessionManager` keyed by IP.
- **Scale:** in-RAM now (test scale) → SQLite persistence/paging behind the same seam later (§10.4/§10.8).

## Checklist

### Foundation
- [x] **#1** Restructure `Meter-Simulator` → `MeterSimulator.Core` class library (dropped `Program.cs`, `DLMSTCPGateway`, `MeterManager`; builds clean)
- [x] **#2** Unify one solution + bump host/HESTestClient to net10.0, wire references

### Core merge
- [x] **#3** Remove hardcoded XML path → template path as a parameter
- [x] **#4** Per-meter DLMS identity from IPv6 index
- [x] **#5** Override serial OBIS `0.0.96.1.0.255` per-meter on load
- [x] **#6** `IMeterSimBridge` seam carries the full WPDU frame
- [x] **#7** `MeterSessionManager` (authoritative per-meter state) + thin `BrainMeterSimBridge`

### Templates & provisioning
- [x] **#8** `Templates/` folder + `TemplateRegistry` (list + upload)
- [x] **#9** Bind a template to each batch in `MeterRegistry`
- [x] **#10** Template dropdown + upload in `Setup.razor`
- [x] **#11** Reject connections for meters with no batch/template

### Cleanup, push-readiness, verify
- [x] **#12** Config cleanup; document in-RAM-now/SQLite-later; keep push unwired
- [x] **#13** ~~Update `HESTestClient` for full-frame + per-meter keys~~ — **DESCOPED** (user: HESTestClient was only for initial NIC-framing testing; left as-is, works vs `Brain:Mode=Simulated`)
- [x] **#15** Reserve push-readiness seams (source-IP bind, `MaterializeBatch`) — documented, not built
- [x] **#14** End-to-end verification + tests + docs (no hand-rolled DLMS client; real HES is the true end-to-end)

**ALL TASKS COMPLETE.** Solution builds; 24/24 tests pass; app runtime-smoke verified.

## Notes / log

- Templates present in `ManyMeterSimulator/ManyMeterSimulator/Templates/`: `SA1231166HP_values.xml`,
  `SA1231166HP_values_bill.xml`, `SZ0000014HP_Only_Push.xml`, `Values_SZ0000014HP.xml`.
  Serial = `GXDLMSData` at `0.0.96.1.0.255`, `<Value Type="10">` (string).
- #1: renamed folder + csproj via `git mv`; removed `Program.cs`, `DLMS/DLMSTCPGateway.cs`,
  `Simulation/MeterManager.cs`; csproj is now a library (Gurux refs kept). `dotnet build` → 0 errors.
- #2: bumped `ManyMeterSimulator` + `HESTestClient` to net10.0; added `MeterSimulator.Core`
  ProjectReference to the host; rewrote root `Meter-Simulator.slnx` as the unified solution
  (Gurux/Brain/NIC folders, 6 projects). Full solution build → 0 errors. NOTE: the old inner
  `ManyMeterSimulator/ManyMeterSimulator/ManyMeterSimulator.sln` still exists but is superseded
  by the root slnx (left in place, harmless).
- #3: `DLMSServerSession` ctor now takes `string templatePath` (2nd arg), passed to
  `MeterObjectLoader`; deleted the hardcoded `C:\Users\AkshitaGupta\...` path. No absolute
  paths remain in `MeterSimulator.Core`. Builds clean.
- #4: new `Models/MeterIdentity.cs` = single source of truth deriving per-meter system title
  + GUEK/GAK/HLS/LLS keys from the IPv6 index (HESTestClient will reuse it, task 13).
  `DLMSMeter` ctor now takes `long index` and derives identity. **Refinement to the "distinct
  address/keys" choice:** system title + keys are per-meter distinct (the meaningful crypto
  identity); the DLMS server (lower) address is kept FIXED (IP is the distinguisher) and
  `IsTarget` now returns true (accepts whatever the HES dials). This is more technically
  correct than varying the logical device address — flag for review if you wanted the numeric
  address itself to vary.
- #5: `ApplySerialOverride` in `DLMSServerSession` rewrites the `0.0.96.1.0.255` GXDLMSData
  string to `_meter.MeterNo` after load (before values seed the meter store). Builds clean.
- #6: added `WpduFrame.Raw` (full header+payload); framer captures it; `IMeterSimBridge` now
  exchanges the FULL frame (in and out); listener passes `frame.Raw` and writes the reply
  verbatim (dropped the response `BuildFrame`, guards empty replies); `SimulatedMeterSimBridge`
  echoes the full frame. Solution builds. **Reorder:** do #8 → #9 → #7 (the session factory
  needs template resolution from #8/#9).
- #8: `Provisioning/TemplateOptions.cs` + `TemplateRegistry.cs` (list/resolve/upload, path-traversal
  guarded); `Templates` config section; DI singleton; csproj copies `Templates/**/*.xml` to output.
- #9: `MeterBatch.TemplateName` (required); `AddBatch(name, templateName, count)`;
  `GetBatchForAddress` + `GetTemplateNameForAddress`; `GetBatchStatusForAddress` delegates.
  Updated tests (+2 new). 18/18 pass.
- #10: `Setup.razor` gets a template dropdown (from TemplateRegistry) + `<InputFile>` upload
  (32MB cap, auto-selects uploaded), Add Batch disabled until a template is chosen, Template
  column in the batch table. Done together with #9 since the AddBatch signature forced the change.
- #7: new `Brain/` folder — `BrainOptions` (ClientAddress/ServerAddress/LogicalName/Mode),
  `MeterSessionManager` (authoritative per-meter sessions, Lazy-built once, keyed by IP; throws
  for no-batch; `MaterializeBatch` stubbed for push #15), `BrainMeterSimBridge` (thin adapter,
  offloads Gurux `HandleRequest` via Task.Run + per-session lock). Program.cs registers the
  session manager and selects Brain (default) vs Simulated via `Brain:Mode`. `Brain` config
  section added. Solution builds.
- #11: listener injects `TemplateRegistry`; gate is now batch-exists → running → template-resolvable,
  else reject. New `rejectedNoTemplate` metric (counter + snapshot + log line). Replaces the old
  permissive path. Builds.
- #12: deleted dead `MeterConfig.cs` + Core `appsettings.json` (batches replace them; brain is a
  library). Push confirmed unwired (sessions built with null PushConfig, no StartPush call in host).
  PushConfig doc-comment updated to note push is deferred. Scale note documented in walkthrough §10.
- Added **walkthrough.md** (full architecture + request flow + config + deferred seams) per user request.
- #15: `MeterSessionManager.MaterializeBatch` stubbed (NotImplemented + doc); `StartPush/StopPush`
  kept unused; push egress source-IP-bind requirement documented at `DLMSServerSession.SendFrames`;
  one-state-mutation documented. Checkpoint: solution builds, 18/18 tests pass.
- #13: **DESCOPED** by user — HESTestClient was only for initial NIC-framing testing; left as-is
  (compiles, works vs `Brain:Mode=Simulated`). Real DLMS end-to-end is the actual HES's job.
- #14: added `MeterBrainTests` (session builds from real templates; serial override applied) +
  `MeterIdentityTests` (deterministic, distinct per index) — 24/24 pass. Runtime smoke: app boots,
  TCP listener bound `[::]:4059` (netstat LISTENING), Kestrel on :5000, brain mode default, no
  exceptions. Updated implementation.md §10.6 to "Done".
