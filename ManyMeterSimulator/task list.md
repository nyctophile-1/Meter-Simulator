# Custom pull commands: implementation task list

Date: 2026-09-10. Design: [plan.md](<C:/Users/ayush/OneDrive/Documents/Development/Sinhal Repos/Meter-Simulator/ManyMeterSimulator/plan.md>).

Only the discovery/documentation tasks below are complete. All implementation and runtime validation tasks remain unchecked. Task IDs are stable references; phases and G01-G12 compatibility gates correspond to the plan. A task is complete only when its stated evidence is recorded, not when a class compiles.

## Completed planning work

- [x] D01 — Verify simulator root, branch, worktrees, HEAD, and existing staged changes.
- [x] D02 — Inspect Core custom sender, selector/value conversion, command aliases, endpoints, and response orchestration.
- [x] D03 — Trace Core ordinary DLMS public association, invocation counter, release, secure association, HLS, command, and final release.
- [x] D04 — Inspect Common serializer, generic parser, low-level decoder, template key/offset calculation, and fragment reassembly.
- [x] D05 — Inspect supplied Template-DM and ObisCodeMapping SQL; record hashes, representative templates, distinct custom-pull data types, and mapping limitations.
- [x] D06 — Verify Core's local resolved Common/Database/Gurux versions and matching local Common/Database tags; distinguish these from live deployment proof.
- [x] D07 — Inspect existing Smart NIC scaffolding, missing data exports, bridge/session ownership, dispatcher, and push-specific framing/body code.
- [x] D08 — Record architecture, scope, implementation phases, acceptance matrix, and unresolved interoperability gates in the plan.

## P0 — Freeze protocol contracts and choose the first reference tuple

Dependencies: D01-D08. Output: versioned fixture manifest, command catalogue, metadata-coverage report, and selected XML/HES-template/category tuple.

- [ ] P0.01 — Recheck all source HEADs/dirty state and applicable repository instructions before code changes. Preserve the three existing staged behavior/math documents.
- [ ] P0.02 — Record the intended HES receiver build and resolved packages, generic enablement, custom-pull template/command support lists, manufacturer/date flags, and force-DLMS rules. Use explicit local test configuration before live access is available. Closes G02 scope ambiguity.
- [ ] P0.03 — Reconcile every `SupportedPullCommands` entry against sender selectors, command aliasing, mini-HES operation, endpoint, and response parser. Classify reads, writes/actions, separate endpoint protocols, and HES inconsistencies. Include GetSingleActionSchedule's selector availability and source 72→4 / 90→83 aliases.
- [ ] P0.04 — Produce golden request fixtures from the pinned HES serializer or sanitized captures: old F2/N3, old F2/N4, new F4/N4, selectors 1..6, values of semantic length 0/4/8, and CRC variants. Record raw bytes and independently expected intent.
- [ ] P0.05 — Document the date-policy matrix: ordinary block, Capital branch, internal block alias, generic daily/event ranges, SET dates, and gap-reading bitmap. Include UTC/IST midnight and actual DLMS clock deviation. Addresses G06.
- [ ] P0.06 — Resolve entry-range endpoint semantics, latest-entry meaning, entry numbering, billing/event differences, zero/default selection, and requested count greater than available. Record examples with exact expected rows. Addresses G12.
- [ ] P0.07 — Prepare an authoritative metadata bundle from supported offline SQL import or table export. Record SQL/export hashes and provenance; do not execute seed/update scripts or depend on the missing historic CSV folder. Addresses G01.
- [ ] P0.08 — Produce field coverage for candidate tuples, including absent/null OBIS attributes, capture columns, units, scalars, category, and profile IDs. Select the first fully resolvable block-profile tuple; do not assume templates 34/93 fit the current XML.
- [ ] P0.09 — Pin a valid response magic when multiple mappings exist. Record the exact old/new header predicate and chosen profile-header template for each candidate.
- [ ] P0.10 — Build a parser-only HES test adapter or controlled fixture harness. Confirm it uses the actual target parser boundary and does not write to shared data.
- [ ] P0.11 — Reproduce UInt32/UInt64/Int64 narrowing with values above 2^31 and 2^32. Record correct raw value, parser output, source/package version, and any required HES fix. Do not mark affected tuples compatible. Addresses G03.
- [ ] P0.12 — Resolve Boolean/String/OctetString consumer and width behavior for enabled fields. Record command-specific formats or HES defects. Addresses G04.
- [ ] P0.13 — Establish block/event row-count behavior at 0/1/15/16 rows and daily/billing multi-row behavior; distinguish RF fragments from logical response groups. Verify HES completion for multiple messages before designing segmentation. Addresses G05.
- [ ] P0.14 — Obtain/reference response fixtures for old/new headers, profile identity, length fields, response CRC policy, RF fragmentation, no entries, and failure. Keep every unresolved case explicitly unavailable. Addresses G09/G10.
- [ ] P0.15 — Verify HES frame correlation with IDs 0, 65,535, 65,536, and equal low 16 bits. Document receiver limits while preserving full IDs in the simulator. Addresses G07.
- [ ] P0.16 — Record separate receiver-fix requirements for false success flags, numeric precision, metadata defects, and unsupported result formats. Simulator implementation must not hide them. Addresses G08/G11.

Exit: P1/P2/P3 may proceed with resolved contracts. The first end-to-end tuple must have a complete read plan, response layout, date policy, and parser fixture before P4 is called complete.

## P1 — Custom request codec and Wirepas channel routing

Dependencies: P0.02-P0.06 and applicable width/CRC fixtures.

- [x] P1.01 — Introduce explicit wire command/selector mapping. Preserve raw command, selector, declared lengths, signed/bits representation, frame ID, and node IDs; expand the domain intent without relying on enum ordinals. `CustomPullCommandDecoder` maps explicit source values and aliases while retaining the raw request fields in `CustomPullRequest` and `CommandIntent`.
- [ ] P1.02 — Define typed selections: plain/default, date range, entry range, latest entries, bitmap, typed SET data, SET date. Reject unsupported command/selector combinations. Read-family selector validation is implemented; SET/bitmap/date interpretation remains tied to the unimplemented command catalogue and date policy.
- [x] P1.03 — Replace the permissive request parse with bounded explicit endian reads. Validate width combinations, physical length, trailing words, CRC, fragment fields, semantic DataLength, and unexpected trailing data. Implemented in `CustomPullRequestParser`; batch/template selection is integrated in P2.
- [x] P1.04 — Add endpoint demultiplexing to the existing Wirepas binding. Route endpoint 3 to the current DLMS path and 13 to custom decoding. Keep one `MqttWirepas` meter identity. Endpoint 13 is safely marked unsupported until the typed execution path lands.
- [x] P1.05 — Resolve the meter/batch before selecting its protocol profile. Validate outer address against inner From/To IDs and reject unsupported routing/broadcast forms. `CustomPullIngress` resolves the provisioned Wirepas batch before parsing, requires both sender-populated inner IDs to equal the outer destination, and rejects node IDs which do not fit the template width.
- [x] P1.06 — Introduce a typed decode/work seam for DLMS frames versus custom commands; keep the 32-bit custom frame ID out of existing ushort-only APIs. `ICustomPullRequestCodec` and `CustomPullInbound` bypass `NicDecodeResult` for endpoint 13, preserving the full custom frame ID for the later runner.
- [ ] P1.07 — Carry originating `BoundBrokerClient`, gateway/sink, request ID, endpoint, received time, batch generation, and request fingerprint throughout the operation.
- [x] P1.08 — Define unsupported custom fragment handling. Only add reassembly with verified custom framing, bounded state, expiry, duplicate/conflict checks, and binding/meter/frame isolation. Multi-fragment custom requests are rejected before any brain/session access.
- [x] P1.09 — Add golden decoding tests and malformed-input cases at every field boundary. Assert malformed/custom-unsupported messages do not materialize a brain. Parser tests cover all supported width profiles, CRC, selector length, declared length, and fragments; endpoint-13 codec test proves no DLMS frame is produced.
- [x] P1.10 — Run routing/framing regressions for endpoint 3 and the other NIC codecs; confirm unknown endpoints retain deliberate handling. Focused Wirepas/RF2 tests passed on 2026-09-10.

Exit: HES-produced custom bytes decode to the exact expected intent and routing context with no ordinary-DLMS regression.

## P2 — HES metadata bundle and execution/layout compiler

Dependencies: P0.07-P0.09; type restrictions from P0.11-P0.12.

- [ ] P2.01 — Extend metadata records with Id/MeterTemplateId, profile-header ID, all profile-template IDs including event-nonprofile, TypeId, PayloadType, Details, and all magic mappings.
- [ ] P2.02 — Add ObisCodeMapping input with field name, formatted OBIS, nullable attribute, unit, scalar, and source provenance. Keep any ProfileAttributeMapping export explicitly identified.
- [ ] P2.03 — Implement the chosen offline SQL-to-bundle/export workflow with real quote/NULL handling and deterministic update ordering. Report unavailable base rows and unsupported statements; never run the SQL against HES.
- [ ] P2.04 — Match HES's five-part layout key and D1/D2/D3 category translation. Select the command's profile-template ID separately from the meter-template ID.
- [ ] P2.05 — Calculate field offsets in SerialNumber order using the target consumer's widths. Include reserved fields where defined; detect duplicate ordinals/ambiguous layouts for enabled capabilities.
- [ ] P2.06 — Define exact field-name aliases between template parameters and ObisCodeMapping DTO field names. No fuzzy matching, universal attribute-2 default, or cross-template fallback.
- [ ] P2.07 — Resolve XML object class/version, attribute, data index, capture ordinal, and DLMS scaler/unit context. Report disagreements with external mappings for the enabled tuple.
- [ ] P2.08 — Replace OBIS-only result binding with a key that preserves profile context and duplicate object/attribute/capture references.
- [ ] P2.09 — Compile immutable read/projection/write plans keyed by metadata hash, XML fingerprint, command, category, and protocol profile. Share descriptors across compatible batches only.
- [ ] P2.10 — Enforce explicit magic selection and exact `NewHeader`/node-width rules. Unrelated historical mappings remain loadable.
- [ ] P2.11 — Integrate startup loading and a capability report. Missing metadata keeps custom support unavailable while ordinary DLMS remains usable. Refresh uses bundle replacement and restart.
- [ ] P2.12 — Add compiler/importer fixtures for quoted values, NULL attributes, key collisions, ordering, multiple templates, missing profile mappings, unsupported types, and magic ambiguity.

Exit: Every advertised field has an unambiguous value source and physical byte offset. Unresolved fields are reported before command execution, not zero-filled during packing.

## P3 — Association ownership and mini-HES DLMS runner

Dependencies: P1 typed intent; P2 read plan; P0 security/counter reference.

- [ ] P3.01 — Introduce shared per-meter association ownership across endpoint 3, endpoint 13, TCP, multiple brokers, and reset/stop paths.
- [ ] P3.02 — Implement owner-aware scheduling so a pending custom request cannot block the next frame needed by an existing ordinary-DLMS association. Add deadlines and fair pending-work handling.
- [ ] P3.03 — Separate active-conversation limits from per-bridge-exchange permits. Do not hold a bridge permit while waiting for delays, ownership, or MQTT publish.
- [ ] P3.04 — Expose simulated security material through a narrow provider consistent with `MeterIdentity` and actual supported key changes. Keep readings behind DLMS. Avoid logging secret values.
- [ ] P3.05 — Implement public AARQ/AARE with client 0x10 and server configuration through full WPDU bridge calls.
- [ ] P3.06 — Read invocation-counter object attribute 2 and release the public association. Verify the live brain's counter projection.
- [ ] P3.07 — Implement secure AARQ/AARE with client 0x30, Authentication.High, correct cipher/authentication material, counter progression, and system-title policy.
- [ ] P3.08 — Generate/validate application association HLS request/response before executing meter operations.
- [ ] P3.09 — Implement `ExchangeAndDecodeAsync`: expected reply checks, empty/error replies, continuations, maximum blocks/bytes, cancellation, per-call timeout, and total deadline.
- [ ] P3.10 — Read profile capture descriptors/scaler metadata/entry count as required; execute buffer GET with plain/date/entry selection and preserve historical rows.
- [ ] P3.11 — Carry typed DLMS result/provenance to projection without direct meter-value shortcuts or premature scalar application.
- [ ] P3.12 — Release the secure association in cleanup. Distinguish operation failure from release failure; retain authoritative meter values/counters.
- [ ] P3.13 — Integrate session touch, batch generation, lifecycle cancellation, and active-work tracking so stop/reset cannot publish stale results or return before in-flight work is accounted for.
- [ ] P3.14 — Add real-brain seven-step tests including consecutive commands, HLS failure, stale counter, multi-block transfer, malformed/empty reply, cancellation at every state, and cleanup.
- [ ] P3.15 — Add interleaving/deadlock tests for endpoint-3 association interrupted by custom traffic, cross-broker/TCP contention, reset, and independent meters making progress.

Exit: A real secure DLMS read completes with correct values and cleanup; ownership and concurrency tests pass.

## P4 — Response encoding and first block-load vertical slice

Dependencies: P1-P3; relevant P0 compatibility gates resolved for the selected tuple.

- [ ] P4.01 — Implement profile-header templates with verified identity encoding, clock status, profile byte, reserved bytes, and row-count limits.
- [ ] P4.02 — Implement typed numeric writer: signed/unsigned widths, Float32 bits, inverse scalar, explicit unit conversion, rounding policy, and checked range/length arithmetic.
- [ ] P4.03 — Implement response timestamp inversion using the target HES parser's convention and DLMS clock/deviation semantics; keep it separate from request time policy.
- [ ] P4.04 — Implement the selected block template projection using the real returned rows and capture bindings. Verify every offset and every requested field.
- [ ] P4.05 — Implement custom pull old 10-byte/new 12-byte framing with full frame ID and pinned magic. Share pure push helpers only after removing unsafe size assumptions from the shared path.
- [ ] P4.06 — Apply only a verified response CRC policy. Independently verify request CRC and response framing behavior.
- [ ] P4.07 — Build Wirepas packet_received_event with `/13/13`, original binding/gateway/sink, source node, correct payload_size, QoS, timestamp, and transport metadata.
- [ ] P4.08 — Implement proven no-row behavior and typed failure outcomes; do not fabricate successful zero rows on DLMS/encoding failure.
- [ ] P4.09 — Add a full local fixture: HES-produced request → endpoint routing → seven-step brain execution → response bytes → independent HES decoding.
- [ ] P4.10 — Compare decoded result to ordinary DLMS on the same immutable historical selection: count, row identities/order, times, units, and all representable values.
- [ ] P4.11 — Exercise large-value parser defects and narrow-field overflow (including template 34 and 93 cases). Keep incompatible cases visibly unsupported; do not adjust the brain values to pass.
- [ ] P4.12 — Record the reference tuple, exact request/response bytes, metadata hashes, parser version, DLMS trace states, and test results without credentials.

Exit: One block-load command is proven end to end. This is a milestone; the broader read-command implementation is still incomplete.

## P5 — Read-command coverage and response-size handling

Dependencies: P4; per-command catalogue/selection/response contracts.

- [ ] P5.01 — Add instantaneous profile reads and generic pull response layout.
- [ ] P5.02 — Add daily and billing reads, including their entry selection, current/history behavior, and per-message completion rules.
- [ ] P5.03 — Add block no-selection/date/entry/latest modes and gap bitmap reads with independently expected row sets.
- [ ] P5.04 — Add profile event families and DI alias; distinguish nonprofile event commands, event IDs, capture layouts, and event/nonprofile template IDs.
- [ ] P5.05 — Add nameplate read and its typed/length-prefixed response encoder, preserving meter identity from the brain.
- [ ] P5.06 — Add clock/schedule reads using the actual enabled HES generic or command-specific consumer, including date-prefix details.
- [ ] P5.07 — Add relay, limits, capture periods, demand period, mode, ESWF, and prepaid parameter reads with exact class/attribute/result conversions.
- [ ] P5.08 — Implement proven RF fragmentation/reassembly limits, ordering, duplicates, expiry, and lengths; keep it independent of DLMS block transfer.
- [ ] P5.09 — Implement the verified policy for more than 15 template-3 rows, old-header size limits, and multi-message responses. If HES cannot represent/complete the request correctly, retain an explicit unsupported capability and track the external fix; never truncate.
- [ ] P5.10 — Verify empty/error semantics per command, including no entries and unsupported profile behavior. Do not use PROFILE_NOT_FOUND 255 unless its receiver handling is proven.
- [ ] P5.11 — Add per-family parity tests across supported 1P/3P/CT tuples, reordered capture columns, negative values, full integer ranges, timezone boundaries, and repeat reads.
- [ ] P5.12 — Reconcile implemented capability matrix against the P0 catalogue; label every excluded HES command/selector/template with a concrete reason.

Exit: Every advertised read command and selection passes independent encoding and semantic tests. No command family is implicitly treated as supported by sharing a profile name.

## P6 — Meter SET/ACTION commands carried by custom pull

Dependencies: P3 secure execution; P0 verified sender/result contracts; P4 response infrastructure. Keep independently configurable from read-only support.

- [ ] P6.01 — Catalogue the source-listed meter writes/actions and their exact selectors, types, OBIS/class/attribute or method, result prefix, and supported XML behavior.
- [ ] P6.02 — Add clock, relay connect/disconnect, limits, demand/capture periods, and mode changes with actual authenticated DLMS Write/Method execution.
- [ ] P6.03 — Add remaining supported calendar/schedule, recharge/prepaid, ESWF, reset, and key-change operations only with complete variable-data and brain behavior contracts. Mark sender/helper limitations explicitly.
- [ ] P6.04 — Decode float bit patterns, signed amounts, dates, and actions correctly; do not treat every four-byte value as a numeric integer.
- [ ] P6.05 — Implement command-specific success/failure response encoders matching `ParseProfileData` and the subsequent consumer.
- [ ] P6.06 — Add idempotency/replay and ambiguous-timeout handling. A repeated transport request must not repeat a completed disconnect/reset/recharge/action.
- [ ] P6.07 — Verify ordinary-DLMS readback and relevant later custom reads reflect the mutation after association release. Test key/counter continuity for supported security changes.
- [ ] P6.08 — Exclude separate NIC-config, diagnostics, firmware, and RTC-sync endpoint protocols from this capability set; they need separate contracts and tests.

Exit: Each enabled write changes real brain state once, returns the correct result, and has independent readback and retry evidence.

## P7 — Runtime configuration, operations, and regression

Dependencies: P4 for initial integration; P5/P6 for full capability coverage.

- [ ] P7.01 — Register loader/compiler/runner/processor/options in Program.cs and validate that custom support uses the real brain mode.
- [ ] P7.02 — Persist custom enablement, HES protocol/template/magic selection, metadata hash, limits, and time policy with batch/configuration bundles. Keep HES template distinct from meter XML.
- [ ] P7.03 — Show capability/mapping errors in setup/inspection using the existing UI pattern. Only expose choices the operator needs; no protocol-debug internals in normal user flows.
- [ ] P7.04 — Implement bounded duplicate/replay storage keyed by origin, meter/generation, endpoint, full frame ID, and fingerprint; verify expiration and frame reuse.
- [ ] P7.05 — Add state-duration/outcome metrics, queue/exchange/conversation gauges, and opt-in bounded captures with secret-bearing payload protection.
- [ ] P7.06 — Apply existing admission, bad-communication, delay, and batch state behavior once at the intended layer; avoid accidentally applying external network delay to every internal DLMS step.
- [ ] P7.07 — Exercise powered-off behavior only if the authoritative brain/state policy implements it; otherwise record the dependency without claiming it is available.
- [ ] P7.08 — Run mixed ordinary/custom workload tests with long profiles, bursts, full queues, slow publish, cancellation, shutdown, and batch reset. Verify fairness and bounded added allocations/state.
- [ ] P7.09 — Verify clients, permits, buffers, fragment state, and replay entries are released; distinguish existing persistent brain RAM from added NIC memory. Do not claim million-meter scale from a small smoke test.
- [ ] P7.10 — Run targeted custom tests, the full simulator test project, and build. Fix relevant regressions; record any pre-existing failures precisely.
- [ ] P7.11 — Update operator/developer docs with supported matrix, metadata refresh, evidence fixtures, diagnostics, packet layering, failure meanings, and disabling/rollback steps.

Exit: The feature is configurable and diagnosable, protects ordinary traffic, and has measured bounded resource behavior at the tested scale.

## P8 — Controlled HES acceptance and delivery

Dependencies: P5/P7; P6 for enabled writes; all gates applicable to the advertised matrix resolved.

- [ ] P8.01 — Pin target HES environment, parser DLL/package/build, active metadata and generic flags, simulator commit/build, broker binding, and selected test meters before integration.
- [ ] P8.02 — Run one real HES custom read for the reference tuple; capture sanitized request/response, endpoint/topic/frame correlation, mini-HES steps, decoded rows, and command outcome.
- [ ] P8.03 — Validate actual values/persistence through approved read-only checks or isolated test data. HES success status alone is insufficient.
- [ ] P8.04 — Expand to new/old headers and 1P/3P/CT supported tuples, empty/range/boundary cases, large-value cases, retries, and mixed endpoint-3/13 traffic.
- [ ] P8.05 — Validate enabled SET/ACTION commands with readback and retry proof on explicitly selected simulated meters.
- [ ] P8.06 — Verify custom disablement, drain/cancellation, restart, and ordinary-DLMS continuity using the rollback procedure.
- [ ] P8.07 — Attach final capability matrix, unresolved exclusions, test/scale evidence, known receiver limitations, source/bundle hashes, and deployment provenance to the implementation review.
- [ ] P8.08 — Mark the feature complete only when all advertised capabilities meet the plan's definition of done. Do not close gaps by reducing payload values, hiding errors, or presenting an intermediate block-only slice as full implementation.

## Evidence record to maintain during implementation

For each completed task or blocked compatibility gate, record:

| Field | Required content |
|---|---|
| Task/gate | Stable ID, such as P4.09 or G03. |
| Source | Repository/commit or exact resolved package; runtime version when tested live. |
| Fixture | Template/category/XML fingerprint, metadata hash, command/selector and sanitized bytes or fixture path. |
| Expected | Rows/values/state transition or exact error/unsupported result. |
| Observed | Actual outcome and test command/log reference. |
| Remaining dependency | Specific missing contract or external correction, with owner/scope once established. |

No implementation tests, builds, or live HES checks were run in the planning task. Completion marks above apply only to source investigation and the two documents.
