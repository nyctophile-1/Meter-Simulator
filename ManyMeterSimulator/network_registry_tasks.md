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

## Phase 2 — Batch binding
- [ ] `MeterBatch.BrokerKey` / `MeterBatch.PushTargetKey` (both `string?`)
- [ ] Same two fields on `PersistedBatch`, plus the load and `Persist()` paths in `MeterRegistry`
- [ ] `MeterRegistry.AddBatch` takes the two keys as opaque strings; **both may be null (= unbound)**
- [ ] `NetworkBindingValidator` (has both registries) — a supplied key must exist, be of the right
      kind for the NIC (broker → MQTT NICs, push target → `Tcp4G`), and is checked at the UI/service
      layer; see the Phase 1 deviation note
- [ ] `MeterRegistry.SetNetworkBinding(batchId, brokerKey, pushTargetKey)` — rebinding an existing
      batch; same validation, persists, and triggers a reconcile so live traffic follows
- [ ] `NetworkRegistry.Delete` refuses while a batch references the key, and names the batches
- [ ] **Store migration**: a `batches.json` with no schema version has its MQTT batches bound to the
      seeded `default` broker and is rewritten once — after which null means unbound (design §3.2)
- [ ] Unbound MQTT batch is surfaced, not silent: `LogTopicPlan` line, reconcile log, UI chip

## Phase 3 — Multi-broker listener (highest risk)
- [ ] Introduce the `(transport, brokerKey)` binding type; compute desired bindings from running
      MQTT batches whose broker is **enabled** (design §5.1, §5.6)
- [ ] `MqttNicListenerService`: key `_clients` by binding instead of `NicType`
- [ ] `NicWorkItem` carries the originating `MqttNicClient`; `ProcessAsync` publishes on **that**
      client, not a transport lookup (design §5.2)
- [ ] Verify IMG still shares the 4G client per broker — one subscription, not two
- [ ] Audit codec reassembly state for per-binding isolation: `Mqtt4GCodec`, `WirepasCodec`,
      `KmeshCodec`, `Rf2Framing` (design §5.4)
- [ ] Cross-broker mismatch: answer on the arriving broker, log a warning, add a
      `SimulatorMetrics` counter (design §5.3)
- [ ] Reconcile loop — bindings follow batch/registry changes with no restart; log every client
      added and removed (design §5.5)
- [ ] Replace `ConnectionStatuses` with a per-binding status surface; update the dashboard's
      consumer
- [ ] Extend `LogTopicPlan` to print the broker each NIC's batches are bound to — the "nothing is
      happening" diagnostic has to survive the change
- [ ] Remove `Nics:<transport>:Enabled`, `NicsOptions.EnabledTransports()` and the per-variant
      `Broker` override; drop the flags from `appsettings.json`
- [ ] Disabling an endpoint tears its clients down through the normal reconcile pass — no separate
      shutdown path

## Phase 4 — Push targets
- [ ] `PushCoordinator` resolves the destination from `batch.PushTargetKey`; explicit destination
      argument still wins when supplied
- [ ] Clear error when a TCP batch has no push target and none was typed
- [ ] `IPushScheduler` seam — interface + DI registration only, no scheduling logic yet

## Phase 5 — UI
- [ ] **Permissions per design §7.0**: view = any authenticated; add / edit / delete / enable /
      disable an endpoint = **Admin**; change a batch's binding = **Admin**; *Test now* = Utility+.
      Control hidden **and** handler re-checks the role, as `Setup.razor` already does
- [ ] `Components/Pages/NetworkRegistry.razor` at `/network`, `[Authorize]`, `InteractiveServer`
- [ ] Nav entry in `Components/Layout/MainLayout.razor` (icon: `Icons.Material.Filled.Hub`)
- [ ] *Add broker* dialog — host, port, username, password, TLS toggle, label; tests before saving,
      shows the real failure text, admin-only "save unverified"
- [ ] *Add push target* dialog — IPv6 address, port, label; same test-then-save flow
- [ ] Health table — key, kind, endpoint, state chip, last checked, last error, referencing batch
      count; timer refresh + per-row *Test now*
- [ ] Per-row *Enable / Disable* toggle, with the effect stated (clients torn down / brought up)
- [ ] Delete action, blocked and explained when referenced
- [ ] `Setup.razor`: broker select (MQTT NICs) and push-target select (`Tcp4G`), always rendered,
      disabled when not applicable, with an explicit **"(none — unbound)"** option
- [ ] Show the bound broker / push target in the batch detail panel, with an admin-only *Change*
      action calling `SetNetworkBinding`
- [ ] Warning chip on an MQTT batch row that is Running but unbound
- [ ] Styles in `wwwroot/css/site.css` reusing the existing status-accent row classes

## Phase 6 — Health monitoring
- [ ] `NetworkHealthOptions` — probe interval (default 60s), probe timeout
- [ ] `NetworkHealthMonitor : BackgroundService` — live `MqttNicClient.Status` for in-use brokers,
      `EndpointProber` for idle brokers and all push targets (design §7.1)
- [ ] Snapshot surface the page reads without triggering probes of its own

## Phase 7 — Tests
- [ ] `JsonNetworkRegistryStore` round-trip; corrupt file throws rather than starting empty
- [ ] Duplicate key rejected; key comparison is case-insensitive
- [ ] Delete refused while referenced, allowed once the batch is gone
- [ ] Binding computation from a mixed batch set (4G + IMG + Wirepas across two brokers)
- [ ] Reply publishes on the originating client when two brokers serve one transport
- [ ] Legacy batch (no keys) loads and resolves to the `default` broker
- [ ] `AddBatch` rejects a key of the wrong kind for the NIC
- [ ] A disabled endpoint contributes no bindings; re-enabling brings its client back
- [ ] An unbound (null-key) MQTT batch contributes no binding; a null/null batch is legal and
      persists as null/null
- [ ] Pre-feature `batches.json` migrates MQTT batches to `default`, exactly once
- [ ] `SetNetworkBinding` moves a running batch's traffic to the new broker
- [ ] Password survives a store round-trip encrypted, and the on-disk JSON does not contain it in
      plaintext
- [ ] IPv4 push target rejected

## Phase 8 — Documentation
- [ ] `appsettings.json` sample updated; note that broker details now live in the registry
- [ ] `virtual_nics.md` §14.5 updated — the "one broker serves all four variants" statement no
      longer holds
- [ ] `Components/Pages/Documentation.razor` — how to add a broker / push target and bind a batch
- [ ] Deployment note: `data/network.json` **and `data/keys/`** join `data/batches.json` as files
      that must survive a redeploy — losing the keys folder makes every stored password
      undecryptable
- [ ] Upgrade note: `Nics:<x>:Enabled` no longer exists; the equivalent is the per-endpoint
      `Enabled` toggle on `/network`
