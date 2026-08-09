# Network Registry — Task List

Status legend: `[ ]` not started · `[~]` in progress · `[x]` done

See [network_registry.md](network_registry.md) for the design rationale behind each item.
Phases are ordered by dependency: 1 → 2 → 3 is the critical path; 4 and 5 can proceed in parallel
once 2 lands.

---

## Phase 0 — Decisions — CLOSED
- [x] **Password at rest**: encrypted in `data/network.json` via ASP.NET Core Data Protection, keys
      persisted to `data/keys/` — design §8
- [x] **`Nics:<transport>:Enabled`**: removed, replaced by a per-endpoint `Enabled` toggle in the
      registry — design §5.6
- [x] **Push target address family**: IPv6 only, validated at entry — design §6

## Phase 1 — Model & store — DONE
- [x] `Networking/Registry/BrokerEndpoint.cs` — Key, Host, Port, Username, Password, UseTls,
      Enabled, CreatedAtUtc, LastVerifiedUtc, Verified
- [x] `Networking/Registry/PushTargetEndpoint.cs` — Key, Address, Port, Enabled, CreatedAtUtc,
      LastVerifiedUtc, Verified; `Destination` renders the bracketed `[v6]:port` form
      `PushCoordinator` already parses
- [x] IPv6-only validation on `PushTargetEndpoint.Address` (`AddressFamily.InterNetworkV6`),
      rejecting IPv4 with that as the stated reason; bracketed input accepted
- [x] `INetworkRegistryStore` + `NetworkRegistrySnapshot` + `NullNetworkRegistryStore`
- [x] `JsonNetworkRegistryStore` → `data/network.json`; atomic temp+rename write, **fail-fast on a
      corrupt file** (batch-store policy, not runtime-config policy — design §3.4)
- [x] `NetworkRegistry` singleton: add / update / delete / enable / lookup, case-insensitive keys
      unique **across both kinds**, keys immutable after create, `Changed` event for reconcile
- [x] Seed a `default` broker entry from `Nics:Shared:Broker` on first load; never overwrites an
      operator edit on a later start
- [x] `EndpointProber.TestBrokerAsync` — real MQTT connect with a **disposable probe client id**,
      configurable timeout, returns `(ok, elapsed, error)` with the real failure text
- [x] `EndpointProber.TestPushTargetAsync` — TCP connect + close, no bytes sent
- [x] Password encryption via ASP.NET Core Data Protection — `AddDataProtection()` with
      `PersistKeysToFileSystem(data/keys)`; protect/unprotect at the store boundary, so the
      in-memory registry only ever holds plaintext and the file only ever holds ciphertext
- [x] An undecryptable password degrades to empty **on that row only** rather than failing the load
- [x] `IEndpointUsageSource` seam — delete refuses while a batch is bound, and names the batches,
      without `NetworkRegistry` depending on `MeterRegistry` (no cycle)
- [x] Registered in `Program.cs`; key ring created at `data/keys/` on startup
- [x] Tests: `NetworkRegistryTests` (14) + `JsonNetworkRegistryStoreTests` (6) — **20 passing**,
      full suite 234/234

> **Deviation from the original plan** (design §3): `MeterRegistry` will **not** depend on
> `NetworkRegistry` to validate binding keys. It stores them as opaque strings, exactly as it
> already stores a template name without depending on `TemplateRegistry`, which is what keeps the
> two registries acyclic. Existence/kind validation moves to the UI/service layer in Phase 2.

## Phase 2 — Batch binding — DONE
- [x] `MeterBatch.BrokerKey` / `MeterBatch.PushTargetKey` (both `string?`, settable — rebinding is
      an admin action on a live batch)
- [x] Same two fields on `PersistedBatch`, plus `BatchStoreSnapshot.Version` / `CurrentVersion`
      and the load and `Persist()` paths in `MeterRegistry`
- [x] `MeterRegistry.AddBatch` takes the two keys as opaque strings; **both may be null (= unbound)**;
      blank/whitespace normalizes to null so unbound is one state, not three
- [x] `NicTypes.IsMqtt` — written as "not TCP", so a NIC added later is MQTT by default
- [x] `NetworkBindingValidator` — key must exist and match the NIC kind; also implements
      `IEndpointUsageSource`, so it is the single object that sees both registries
- [x] `MeterRegistry.SetNetworkBinding(batchId, brokerKey, pushTargetKey)` — returns whether
      anything actually changed, so the caller can skip a needless reconcile
- [x] `NetworkRegistry.TryDeleteBroker` / `TryDeletePushTarget` refuse while a batch references the
      key, and name the batches
- [x] **Store migration**: `MigrateLegacyBindings`, called once from `Program.cs` where both
      registries exist. Binds pre-registry MQTT batches to the seeded `default`; bumps the schema
      version **even when there is no default broker**, so a later "default" cannot retroactively
      bind batches an operator deliberately unbound
- [x] `NetworkBindingValidator.IsUnreachable` — the running-but-unbound MQTT predicate the
      `LogTopicPlan` line (Phase 3) and the UI chip (Phase 5) both render
- [x] Tests: `BatchNetworkBindingTests` (11) + `NetworkBindingValidatorTests` (8) — **19 passing**,
      full suite 253/253

## Phase 3 — Multi-broker listener — DONE
- [x] `BrokerBinding(Transport, BrokerKey)` — the type that replaced `NicType` as the client key
- [x] `BrokerBindingPlanner` — the desired-client rule, extracted as a **pure function** so it can
      be tested directly; also reports every Running-but-unreachable batch with its reason
- [x] `MqttNicListenerService`: `_clients` keyed by binding; `BoundBrokerClient` bundles the client,
      its own codec, its options and its cancellation
- [x] `NicWorkItem` carries the originating `BoundBrokerClient`; `ProcessAsync` publishes on
      `item.Source.Client` — never a transport lookup (design §5.2)
- [x] IMG still shares the 4G client **per broker** — one subscription, not two; a 4G and an IMG
      batch on *different* brokers correctly get one client each
- [x] Codec state audited: only `WirepasCodec` holds reassembly state (`(nodeId, frameId)`).
      Isolated by giving each binding its **own codec instance** via `NicCodecFactory`, rather than
      threading a binding key through `INicCodec.Decode` and every implementation
- [x] Cross-broker mismatch: answered on the arriving broker, warned, and counted via
      `SimulatorMetrics.RecordCrossBrokerMessage` / `TotalCrossBrokerMessages`
- [x] Reconcile loop — signalled by `NetworkRegistry.Changed` and the new `MeterRegistry.Changed`
      (raised outside the lock), with a 30s safety-net sweep. Stops before it starts, so a rebind
      does not hold both connections open
- [x] `BoundBrokerClient.Matches` — an EDITED broker (rotated password, moved host) keeps its key,
      so the binding looks unchanged; without this the edit would never take effect
- [x] `ConnectionStatuses` re-keyed by binding; dashboard row now reads "4G MQTT · pune"
- [x] `LogTopicPlan` prints the broker each batch is bound to, and says `NO BROKER` /
      `MISSING from the registry` / `DISABLED` where applicable
- [x] Removed `Nics:<transport>:Enabled`, `EnabledTransports()`, `BrokerFor()` and the per-variant
      `Broker` override; `appsettings.json` updated with a note on what replaced them
- [x] Disabling an endpoint tears its clients down through the normal reconcile pass — no separate
      shutdown path
- [x] Tests: `BrokerBindingPlannerTests` (11) + `NicCodecFactoryTests` (4), plus `NicCodecTests`
      rewritten for `ConnectionFor` — **268/268 passing**

> **Not covered by a test**: that a reply is physically published on the originating connection.
> The routing is structural (the client travels on the work item and `ProcessAsync` has no other
> client to reach for), but proving it end-to-end needs two live brokers — an integration test, not
> a unit one. Worth doing against the EQA broker before this ships.

## Phase 4 — Push targets — DONE
- [x] `PushCoordinator` resolves the destination from `batch.PushTargetKey`; the typed argument
      still wins when supplied, and is now optional rather than required
- [x] Clear error when a TCP batch has no push target and none was typed; also when the bound key
      is missing from the registry, or its endpoint is disabled
- [x] Dashboard's push button no longer demands a typed IP — an empty box uses the binding
- [x] `IPushScheduler` seam — interface only, no scheduling logic
- [x] Tests: `PushDestinationTests` (5) — **273/273 passing**

## Phase 5 — UI — DONE
- [x] **Permissions per design §7.0**: view = any authenticated; add / edit / delete / enable /
      disable an endpoint = **Admin**; change a batch's binding = **Admin**; *Test now* = Utility+.
      Control hidden **and** handler re-checks the role, as `Setup.razor` already does
- [x] `Components/Pages/NetworkRegistryPage.razor` at `/network`, `[Authorize]`, `InteractiveServer`
- [x] Nav entry in `Components/Layout/MainLayout.razor` (`Icons.Material.Filled.Hub`)
- [x] *Add broker* dialog — host, port, username, password, TLS toggle, name; tests before saving,
      shows the real failure text, admin-only "save unverified"
- [x] **Edit broker** dialog (not in the original plan, added after live testing): a bound broker
      cannot be deleted, so without Edit a wrong password on an in-use endpoint was unfixable from
      the UI. Name is locked; a blank password keeps the stored one and is never rendered back
- [x] *Add push target* dialog — IPv6 address, port, name; same test-then-save flow
- [x] Health table — name, endpoint, state chip, last checked, last error, referencing batch count;
      5s re-render of what the monitor already found + per-row *Test now*
- [x] Four-state chip — Disabled / Unverified / Connected / Unreachable — rather than one dot that
      would collapse "switched off", "never reached" and "failing right now"
- [x] Per-row *Enable / Disable* toggle, with the effect stated
- [x] Delete action, blocked and explained when referenced
- [x] `Setup.razor`: broker select (MQTT NICs) and push-target select (`Tcp4G`), always rendered,
      disabled when not applicable, with an explicit **"(none — unbound)"** option
- [x] Batch detail panel shows the binding (and flags a key MISSING from the registry), with an
      admin-only *Change network binding* dialog calling `SetNetworkBinding`
- [x] `unreachable` chip on an MQTT batch row that is Running but unbound
- [x] Reused the existing `batch-table` / `is-running` / `is-stopped` / `is-idle` classes — no new CSS

## Phase 6 — Health monitoring — DONE
- [x] `NetworkHealthOptions` — interval (default 60s, floored at 10s), timeout
- [x] `NetworkHealthMonitor : BackgroundService` — live `MqttNicClient.Status` for in-use brokers,
      `EndpointProber` for idle brokers and all push targets (design §7.1)
- [x] Disabled endpoints are not probed — reporting a healthy broker the operator switched off is
      worse than reporting nothing
- [x] `EndpointHealth.Ok` is **nullable**: "not checked yet" is a third state, and collapsing it
      into false shows a brand-new endpoint as broken
- [x] Snapshot surface the page reads without triggering probes of its own

## Phase 7 — Tests — DONE (275/275)
Most landed with the phase they cover rather than here; the covering file is named for each.
- [x] `JsonNetworkRegistryStore` round-trip; corrupt file throws rather than starting empty
      — `JsonNetworkRegistryStoreTests`
- [x] Duplicate key rejected; key comparison is case-insensitive — `NetworkRegistryTests`
- [x] Delete refused while referenced, allowed once the batch is gone — `NetworkRegistryTests`,
      `NetworkBindingValidatorTests`
- [x] Binding computation from a mixed batch set (4G + IMG + Wirepas across two brokers)
      — `BrokerBindingPlannerTests`
- [x] Legacy batch (no keys) loads and resolves to the `default` broker — `BatchNetworkBindingTests`
- [x] `AddBatch` rejects a key of the wrong kind for the NIC — `NetworkBindingValidatorTests`
- [x] A disabled endpoint contributes no bindings; **re-enabling brings its client back**
      — `BrokerBindingPlannerTests` (`ReEnablingABroker_BringsItsBindingBack`)
- [x] An unbound (null-key) MQTT batch contributes no binding; a null/null batch is legal and
      persists as null/null — `BatchNetworkBindingTests`, `BrokerBindingPlannerTests`
- [x] Pre-feature `batches.json` migrates MQTT batches to `default`, exactly once
      — `BatchNetworkBindingTests`
- [x] `SetNetworkBinding` moves a running batch's binding to the new broker
      — `BrokerBindingPlannerTests` (`RebindingARunningBatch_MovesTheDesiredBinding`)
- [x] Password survives a store round-trip encrypted, and the on-disk JSON does not contain it in
      plaintext — `JsonNetworkRegistryStoreTests`
- [x] IPv4 push target rejected — `NetworkRegistryTests`, and push resolution in `PushDestinationTests`

> **Still integration-only, not unit-tested**: that a reply is physically published on the
> originating connection (design §5.2). The routing is structural — the client rides on the work
> item and `ProcessAsync` reaches for no other — but proving it end-to-end needs two live brokers.
> Run against EQA before shipping.

## Phase 8 — Documentation
- [x] `appsettings.json` sample updated; note that broker details now live in the registry, and
      what replaced the removed `Enabled` flags
- [x] `virtual_nics.md` §14.5 updated — the "one broker serves all four variants" statement is now
      marked as a reading of THIS HES config, not a property of the field. The two-credential note
      is unchanged and still load-bearing (it is why a seeded endpoint keeps config credentials as
      fallbacks)
- [ ] `Components/Pages/Documentation.razor` — how to add a broker / push target and bind a batch
- [ ] Deployment note: `data/network.json` **and `data/keys/`** join `data/batches.json` as files
      that must survive a redeploy — losing the keys folder makes every stored password
      undecryptable
- [ ] Upgrade note: `Nics:<x>:Enabled` no longer exists; the equivalent is the per-endpoint
      `Enabled` toggle on `/network`
