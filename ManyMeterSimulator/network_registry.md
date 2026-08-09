# Network Registry — Design

Status: **design, not yet implemented**. Branch `new-merge` (current).

Companion to `implementation.md` (architecture), `virtual_nics.md` (the five NIC variants) and
`task.md` (delivery). Task list for this feature: `network_registry_tasks.md`.

This document covers the move from **one hard-coded broker and a typed-in push IP** to a
**named, validated, operator-managed registry of network endpoints** that batches bind to.

---

## 1. What the field looks like

Every NIC variant learns where to send its traffic from somewhere, and it is never the same place:

| NIC variant | Where the destination lives in the real world |
|-------------|-----------------------------------------------|
| RF Wirepas  | the **gateway** holds the broker details; meters behind it never see them |
| RF Kmesh    | same — gateway-held broker details |
| 4G MQTT     | broker details are written **into the meter**, in OBIS objects (HES's `SetMQTTBrokerDetails`) |
| 4G IMG MQTT | same as 4G MQTT |
| 4G TCP      | the meter's **push object** holds the HES push-listener IP/port |

So a fleet is not served by one broker. Different gateways, different regions and different HES
instances mean several brokers and several push listeners are live at once, and a given meter
belongs to exactly one of each.

## 2. What the simulator does today — and why it can't express that

Three places encode the "there is exactly one destination" assumption:

1. **`NicsOptions`** (`Networking/Mqtt/NicsOptions.cs`) — `Nics:Shared:Broker`, one
   `MqttBrokerOptions`, with a per-variant override that is still one-per-variant. Host, port, TLS
   flag and the credential list all come from config, and credentials are deliberately kept out of
   `appsettings.json` (env vars / user-secrets only).
2. **`MqttNicListenerService`** (`Networking/Mqtt/MqttNicListenerService.cs`) — creates **one
   `MqttNicClient` per transport**, stored as `_clients[transport]`, and the reply path looks the
   client back up by transport alone:
   ```csharp
   if (publishes.Count == 0 || !_clients.TryGetValue(item.Transport, out MqttNicClient? client))
   ```
   With two brokers on one transport, that lookup is ambiguous — which is exactly the bug this
   feature has to prevent.
3. **`PushCoordinator`** (`Brain/PushCoordinator.cs`) — takes the destination as a string argument
   typed into the dashboard box. Nothing about a batch says where its meters push.

Batches themselves (`Provisioning/MeterBatch.cs`) carry NIC type, template and HES template id, but
no network binding at all.

## 3. The model

Two endpoint kinds, one registry, one store:

```
NetworkRegistry (singleton)
  ├─ BrokerEndpoint     { Key, Host, Port, Username, Password, UseTls, Enabled,
  │                       CreatedAtUtc, LastVerifiedUtc, Verified }
  └─ PushTargetEndpoint { Key, Address, Port, Enabled,
                          CreatedAtUtc, LastVerifiedUtc, Verified }

INetworkRegistryStore → JsonNetworkRegistryStore → data/network.json
```

`Password` is stored encrypted; `Address` is IPv6-only. See §8 and §6. `Enabled` is the
operational kill switch — see §5.6.

`MeterBatch` gains two nullable keys:

```csharp
public string? BrokerKey { get; init; }      // MQTT NICs
public string? PushTargetKey { get; init; }  // 4G TCP
```

### 3.1 Why the label is the key

Batch names are already the operator's handle on a batch, and the registry entries are created and
referenced by the same person in the same session. A separate numeric id would have to be surfaced
in the UI anyway, so it would be a second name to keep in sync. The label is therefore the key:
unique, case-insensitive, and **immutable once created** — renaming would silently orphan every
batch pointing at it.

### 3.2 Null means unbound — deliberately

`null` on either key means **this batch is connected to nothing**, and that is a legal, useful
state: a batch provisioned before its broker exists, a batch parked without deleting it, a TCP
batch that only ever answers pulls and never pushes. Both keys may be null at once.

An earlier draft of this document had `null` mean "fall back to the legacy configured broker".
That reading is now gone, because the two cannot coexist — if null silently falls back, there is no
way to express "bound to nothing", and a batch the operator deliberately unbound would quietly keep
serving traffic on the config broker.

The legacy case is handled by **migration instead of fallback**. On first load of a store written
before this feature (no schema version), every MQTT batch is bound to the seeded `default` broker
entry and the store is rewritten once. After that migration, null is unambiguous everywhere: it is
intent, never absence of information.

### 3.3 What unbound does at runtime

| Batch | Broker key null | Push target key null |
|-------|-----------------|----------------------|
| MQTT (RF Wirepas / Kmesh / 4G / IMG) | contributes no binding — no client, no subscription, **the meters are never reached** | n/a (no push target offered) |
| 4G TCP | n/a (no broker offered) | inbound pulls work normally; push has no destination until one is assigned or typed |

The MQTT row is the dangerous one: it is a running batch that answers nothing, which is the exact
symptom `LogTopicPlan` exists to explain. So an unbound MQTT batch is called out explicitly — in
the startup NIC plan, as a warning chip on the batch row, and in the reconcile log. It is never
inferred from silence.

The TCP row is benign, and follows from §5.0: nothing about an inbound TCP session depends on the
registry.

### 3.4 Why a third store file

There are two persistence policies in the codebase already, and they differ on purpose
(`JsonBatchStore` vs `JsonRuntimeConfigStore`):

- **Batch store** — fleet identity. A corrupt file **fails startup**, because starting empty would
  rewind the allocation cursor and reissue addresses the HES already knows.
- **Runtime config store** — behavioural knobs. A corrupt file falls back to configured defaults,
  because losing a delay setting is harmless.

The network registry sits with the **batch store**: losing it silently would make batches bind to
the wrong broker, or to none, with no visible error. So `data/network.json` gets the same atomic
temp-file+rename write and the same fail-fast-on-corrupt read.

## 4. Validation — "accept only if it connects"

One prober, `EndpointProber`, used by both the add dialog and the health monitor, so a row can
never be accepted by a check that differs from the one that later reports it red.

- **Broker**: a real `MqttClient.ConnectAsync` with the supplied credentials and a ~10s timeout,
  then disconnect. Uses a **disposable client id** (`{prefix}-probe-{guid}`), never one a live NIC
  client could be using — a colliding client id would get the live connection evicted by the broker.
- **Push target**: `TcpClient.ConnectAsync(address, port)` with a timeout, then close. A successful
  TCP handshake is all we can assert; nothing is sent, because a stray byte to a real HES listener
  would be parsed as a malformed push.

Failure is reported with the actual exception message. The alternative — a generic "could not
connect" — makes a wrong password and an unroutable host look identical, which is the single most
common support question this page will generate.

**The unverified escape hatch.** A HES TCP listener may legitimately not be running at provisioning
time. Blocking on that would force the operator to fake a listener just to save a row. So an
admin-only *"save unverified"* path exists; the row is stored with `Verified = false` and shows as
such everywhere, so an unverified endpoint is never mistaken for a working one.

## 5. Multi-broker at runtime — the load-bearing part

### 5.0 TCP is out of scope here, and stays that way

An inbound TCP connection is **broker-agnostic and may come from anywhere**: HES dials the meter's
own IPv6 address, the listener derives the identity from `localEndPoint.Address`, and the reply goes
back down the same socket. That is already a one-to-one channel by construction — the socket *is*
the correlation — so `TcpNicListenerService` needs no registry, no binding and no change. The only
TCP-side use of the registry is the **outbound** push destination (§6).

The MQTT NICs have no such channel. Requests arrive on a shared topic on a shared connection, and
nothing in the payload says which broker it came from, so the correlation has to be carried in the
work item explicitly. Everything below exists to give RF and MQTT the property TCP gets for free:
**a request that arrives on broker A is answered on broker A, for every leg of the exchange.**

### 5.1 Bindings replace transports as the client key

```
binding = (transport, brokerKey)
```

Desired bindings are derived from the batches, not from config:

```csharp
batches.Where(b => b.Status == Running && IsMqtt(b.NicType) && b.BrokerKey is not null)
       .Where(b => registry.Broker(b.BrokerKey!) is { Enabled: true })
       .Select(b => (NicTypes.TransportFor(b.NicType), b.BrokerKey!))
       .Distinct()
```

One `MqttNicClient` per binding, subscribed to that transport's codec filters. Note this keeps the
existing IMG-folds-into-4G rule intact (`NicTypes.TransportFor`): two batches, one 4G MQTT and one
4G IMG, pointing at the same broker still share **one** client and one subscription — otherwise
every message would be received twice, which is the reason there is no separate IMG section today.

### 5.2 The reply goes back on the connection it arrived on

`NicWorkItem` gains the originating client, and `ProcessAsync` publishes on it instead of looking
one up by transport. This is the requirement that "a true exchange must account for the broker that
sent the request": a DLMS command is rarely one round trip — AARQ, then get/set, then release, plus
fragmentation on the RF NICs — and every leg has to return to the same broker, or HES sees an
association that answers once and then goes silent.

It is also strictly more robust than resolving the broker from the batch: if a request physically
arrived on broker A, then A is reachable and A is where HES is listening, whatever the registry says.

### 5.3 Cross-broker mismatch policy

A message for node X arriving on broker A while X's batch is bound to B is **answered on A**, with
a warning log and a dedicated metric.

Real hardware answers whoever reached it, so this mirrors the field. The alternative — dropping —
produces the one symptom with no evidence attached ("nothing happens"), which `LogTopicPlan` already
exists to prevent for the config case. The counter makes a persistent misbinding visible instead of
merely survivable.

### 5.4 Fragment state must be per-binding

The codecs reassemble fragments keyed by node id. Node ids are globally unique across batches, so
two brokers cannot legitimately carry the same node — but a misrouted or duplicated gateway can,
and the failure mode (frames from two brokers interleaved into one reassembly buffer) is a
corrupted APDU that looks like a codec bug. The reassembly key becomes `(binding, nodeId)`.

### 5.5 Reconciliation, not startup wiring

Today the client set is decided once in `ExecuteAsync`. With batch-driven bindings the set changes
whenever a batch is started, stopped, added or deleted, and whenever a registry entry appears. A
reconcile pass (desired vs actual, on an interval and on demand) adds and removes clients in place.
Requiring a restart to pick up a new broker would make the registry page a lie — it accepts a broker
that then does nothing.

### 5.6 What happens to `Nics:<transport>:Enabled` — DECIDED

**The flag is removed, and the kill switch it provided moves to the registry as a per-endpoint
`Enabled` toggle.**

Removal alone was the original proposal, but it loses something real: the ability to silence one
transport without deleting anything. The reason to move it rather than keep it is that a
*per-transport* switch does not survive this feature. Once N brokers serve one transport,
"disable 4G MQTT" is no longer a meaningful unit — it silences brokers the operator never intended
to touch, and there is no way to express "stop talking to the Bangalore broker, leave Pune
running". The flag would get less useful with every broker added, which is the definition of a
knob that does not age well.

A per-endpoint `Enabled` scales the other way: it is exactly one row per thing an operator would
ever want to silence, it lives next to the health state that prompts them to silence it, and it
composes — disabling every broker on a transport is the old behaviour, expressed as data instead of
config. A disabled endpoint contributes no bindings, so its clients are torn down by the normal
reconcile pass (§5.5); no separate shutdown path exists.

The gate is therefore two conditions, both visible on one page: a **running batch** references the
endpoint, and the endpoint is **enabled**. `Nics:Shared:Broker` stays as the seed for the `default`
registry entry, and `EnabledTransports()` disappears along with the per-variant flags.

## 6. Push targets

**IPv6 only.** `PushTargetEndpoint.Address` is validated as `AddressFamily.InterNetworkV6` at
entry and an IPv4 address is rejected with that as the stated reason. `PushCoordinator` keeps
parsing `[v6]:port` as it does today; the registry simply never produces anything else. The fleet's
own addressing is a routed IPv6 /64 (`Tcp:AddressPrefix`), so a push originating from a meter in
that prefix to an IPv4 listener has no source address to be correlated on at the far end —
accepting one would store a target that cannot work.


`PushCoordinator.PushBatchAsync` resolves the destination from `batch.PushTargetKey` through the
registry, falling back to the explicit destination argument when one is passed. The dashboard box
stays for now as a deliberate override — it is the bring-up tool, and the button is expected to be
hidden once push is scheduled.

A `PushScheduler` seam (interface + registration, no scheduling logic) lands with this feature so
the eventual periodic push has an obvious home and does not reopen `PushCoordinator`.

The existing `NicType.Tcp4G` guard stays: MQTT meters have no per-meter source IP for a receiver to
correlate on, so a push target on an MQTT batch is meaningless and the UI does not offer one.

## 7. UI

### 7.0 Permissions — admin only for anything that changes a binding

| Action | Role |
|--------|------|
| View the registry and its health | any authenticated user (Viewer+) |
| Add / edit / delete a broker or push target | **Admin only** |
| Enable / disable an endpoint | **Admin only** |
| Test now (probe an existing endpoint) | Utility+ — read-only, changes nothing |
| Set or change a batch's broker / push target | **Admin only** |
| Start / stop a batch | Utility+ (unchanged) |

Rebinding a batch redirects live traffic for every meter in it, so it sits with provisioning (already
`IsAdmin` in `Setup.razor`), not with operation. A Utility operator can still start, stop and test —
they just cannot change where the fleet talks.

Enforced in two places, as `Setup.razor` already does it: the control is hidden for non-admins,
**and** the handler re-checks the role before acting. The comment in the existing code calls this
defense in depth, and it matters more here — the registry mutations are reachable from a page a
Utility user can legitimately open.

New page `/network` ("Network"), following the conventions already set by `Setup.razor`:
`MudPaper` form block, status-accented table rows, admin gating via `IsAdmin` / `CanOperate`.

- **Two buttons** — *Add broker*, *Add push target* — each opening a dialog that tests before it
  saves, with the failure text inline.
- **Health table** — key, kind, endpoint, state chip, last checked, last error, and how many batches
  reference it. Refreshes on a timer (default 60s) plus a per-row *Test now*.
- **Delete** is blocked while any batch references the key, and says which batches.
- **Setup page** gains a broker select (MQTT NICs) and a push-target select (4G TCP). Both are
  always rendered and disabled when not applicable — the same reason the HES-template-id field is:
  conditional rendering reflows the whole row the moment the NIC changes.

### 7.1 Health monitoring

`NetworkHealthMonitor`, a hosted service on a configurable interval:

- For a broker **in use**, it reports the live `MqttNicClient.Status` rather than probing. That
  status is the truth the meters actually experience; a separate probe could pass while the real
  client sits in its reconnect backoff.
- For an **idle** broker or **any** push target, it runs the same `EndpointProber` check used at
  add time.

## 8. Security

Storing broker passwords is new: `appsettings.json` says in as many words that credentials never go
in the file, and this feature has to persist them somewhere the app can read unattended.

**Decided: encrypted in the JSON file**, alongside the batch and runtime-config stores rather than
in a separate secret mechanism — one persistence story for everything the operator sets at runtime.

The password field is encrypted with **ASP.NET Core Data Protection**, keys staying on the sim
host under `data/keys/` (persisted explicitly with `PersistKeysToFileSystem`; the default key
location is per-user and would silently lose every stored password when the app runs as a different
account after a redeploy). Only the password is encrypted — host, port, username and TLS flag stay
plaintext, because a file an operator cannot read is a file they cannot debug. That keeps `data/network.json` readable and diffable for everything an operator wants to see,
while a copied-off file is not a credential leak. The page is admin-gated, and passwords are never
rendered back — an edit replaces, it does not reveal. `MqttNicClient` already logs credential
*names*, never passwords; that rule extends to the registry.

## 9. Compatibility

| Existing state | Behaviour after this feature |
|----------------|------------------------------|
| `data/batches.json` with no keys | **one-time migration**: MQTT batches bound to the seeded `default` broker, store rewritten with a schema version. Null afterwards means unbound (§3.2) |
| Inbound TCP sessions | unchanged — no registry involvement at all (§5.0) |
| `Nics:Shared:Broker` configured | seeds the `default` registry entry on first run |
| `Nics:<x>:Enabled = true` | flag removed; a client starts when a **running batch** references an **enabled** endpoint |
| Dashboard *Send Push* box | still works, as an explicit override of the batch's push target |

## 10. Decisions

1. **Password at rest** — encrypted in `data/network.json` with ASP.NET Core Data Protection, keys
   persisted to `data/keys/`. Same file-based persistence story as batches and runtime config (§8).
2. **`Nics:<x>:Enabled`** — removed; replaced by a per-endpoint `Enabled` toggle in the registry,
   because a per-transport switch stops being expressible once N brokers serve one transport (§5.6).
3. **Push target address family** — IPv6 only, validated at entry (§6).
