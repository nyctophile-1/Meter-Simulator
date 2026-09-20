# FakeRouting gateway and sink contract

Publish an empty message on `FakeRouting/{nodeId}/{transportType}/{gatewayId}/{sinkId}`.
Transport types remain 1 = Kmesh, 2 = Wirepas, 3 = MQTT 4G/IMG, 4 = TCP.
Node IDs are preserved verbatim. IDs cannot contain topic separators, wildcards,
whitespace or controls; node IDs are at most 50 characters and gateway/sink IDs 32.

Routing, GapReading and Background accept both this format and the legacy
`FakeRouting/{nodeId}/{transportType}` during rollout. Existing `FakeRouting/#`
subscriptions cover both. Explicit routes update LatestRouting through its existing
repository and stored-procedure/bulk path, including already registered meters.
There is no new SQL, schema, routine, package dependency or transport subscription.
The update requires an existing registered LatestRouting row; it does not provision meters.
Repository acceptance, including bulk queue admission, is not proof of database persistence.

Routing retains the legacy timestamp-only behavior for old publishers. For explicit
routes it updates LatestRouting without generating a synthetic routing-history packet.
GapReading and Background apply explicit routing before enqueuing the node ID for
their existing time-gated command work. An update exception prevents enqueueing.
Hop count -1 preserves the stored hop count; Wirepas uses endpoint 3 and other
transports -1. Malformed topics never reach protobuf decoding or route writes.

Core's MQTT 4G and TCP push publishers include their existing direct_4g/direct_tcp
gateway and sink. TCP's existing enable-routing gate remains; Kmesh pushes do not
acquire an extra FakeRouting publication.

MAYA shares one RF assignment across FakeRouting, push envelopes and HES
registration: gate_{batchId}_{1 + floor((meterIndex - batchStart)/1000)}.
Wirepas sink is sink{(meterIndex - 1) % 4}; Kmesh uses numeric 0–3 for its protocol.
Node IDs use a fixed offset from meterIndex. Reconstructing the same batch produces
the same assignments; one million meters yield 1000 gateways, 1000 meters each.
The upgrade deliberately replaces previous 500-meter groups and batch-relative sinks.
Existing active meters migrate on their next scheduled routing/push update; no
bulk database rewrite is performed. Stopped batches remain stopped.

Core pull already groups RF commands using the cached LatestRouting gateway.
Changes become visible when normal routing caches refresh. This release supplies
routing identities; it does not change pull scheduling or prove a throughput gain.

Deploy all consumers before the new Core/MAYA publishers. Legacy topics remain
usable throughout. Verify emitted topics, persisted LatestRouting values and
command grouping separately; MQTT success is not HES persistence.

## Validation

Local checks cover all transport types, exact identity/route fields, malformed
segments, legacy topics, consumer callbacks and route update failures.
MAYA additionally checks gateway boundaries, a million-meter distribution,
stable node-derived sinks, push envelopes, and loopback MQTT framing.
Release builds use existing published package references without source overrides.
Database procedure bodies were inspected read-only on the observability replica;
database write fixtures require an isolated test target and were not run there.

Local result (2026-09-20): 820 Release tests passed, 8 isolated database tests skipped; PushProbe Release build passed. Application Release publish/build succeeded.
