# Push/pull verification — active work

Latest follow-up: [profile time alignment](d1-time-alignment-20260914.md), release `time-d17d9f77`, deployed and verified on both servers with 598 tests. Future-dated profiles now align to UTC now while retaining row spacing. Four fresh packet RTCs pass the local Common parser; the Common fixes are not deployed. Live matrix gaps below remain.

The goal is **not complete**. The [86-entry matrix](matrix.csv) retains the requested four paths, seven profile names and three category families, plus GRBlockLoad and fakerouting. Codes 8/D3 and 10/D3 remain separate variants requiring evidence. RTC push is custom Wirepas only, per the user's clarification; the three DLMS RTC-push entries remain visible as not applicable. Events need event-family subcases, and the two extra scenarios still require applicable per-category coverage.

## Latest release: September 14 India time

Release `profiles-818f418a` is deployed and preservation-verified on DRISHTI and EQA, with 592 simulator tests and nine composer checks passing. The master preserves its 160-object model and uses physical wire values for Instant, Block, Daily and four event families; its original compatible Billing donor remains. The loader preserves precision across shared captured objects, and custom ESW pull is implemented.

Custom ESW command 98932984 completed and persisted row 3908521 with all 128 bits and current RTC verified. During EQA's authorized deployment window, DLMS Instant 98932983 completed its seven-exchange lifecycle without duplicate responses, but HES rejected energy values from the batch's older selected XML and persisted no row. The corrected master is deployed; existing batch template selections are preserved. Ongoing fleet isolation awaits the user's preference, and HES push/routing services remain inactive at the latest check. See [the current release and live results](d1-release-20260914.md) and [deployment manifest](../../deploy/profiles-20260914-manifest.json).

## Wave 1 update: D1, 2026-09-13 17:52 UTC

The user resumed work with D1 as the current wave, D2/D3 deferred, direct database command insertion authorized, and current simulated time required. The D1 master preserves the base model and includes 13 compatible Billing rows and 39 event rows captured from the physical D1 meter SA1038079. The locale fix passes all 589 simulator tests and both database-enqueued GetRTC commands completed successfully. See [the D1 master and command evidence](d1-master.md) and [remaining D1 work](remaining-inputs.md). Older time-stamped sections below retain historical findings; API authentication is no longer a prerequisite.

## Common fractional-second source fix: 2026-09-13, 16:13 UTC

Common now converts the DLMS hundredths byte to milliseconds by multiplying it by ten; the unspecified `0xFF` marker still becomes zero milliseconds. This is independent of the pending deviation convention. The actual compiled Common methods failed 12 of 20 fraction cases before the change and passed all 20 afterwards, covering 0, 1, 50 and 99 hundredths and the unspecified marker across zero, positive, negative and unspecified deviations. A paired comparison confirmed that only the expected fractional part changed in every case.

The recorded full-UTC cases still fail all four explicit expectations because HES continues to apply -330 minutes regardless of the wire deviation. No complete timestamp pass is claimed. The Common project compiled through the probe's project reference; no database connection, package publication, consumer update, live push or deployment occurred. The fix and runnable probe are in the isolated Common checkout. See [evidence, source and assembly hashes](run-20260913-1613.json). The live scenario matrix remains unchanged.

## Daily deviation source fix and HES datetime reproduction: 2026-09-13, 16:10 UTC

The Daily fallback previously emitted unspecified deviation (`0x8000`) even though the loader had normalized its captured timestamp to UTC. It now copies the captured datetime, includes its known offset and preserves the original shared row, clock status and other skip flags. The fix adds no NIC, meter or template identity branch. Explicit template PushSetup definitions keep their existing behavior.

The new assertion failed both plaintext/ciphered cases before the fix. Afterwards, all 24 focused Daily tests passed and the full Release suite passed **581 tests, zero failures or skips**. A fresh generated Daily packet carries deviation zero; identity, profile channel and all four energy values exactly match the previous packet. It was not published. See [packet comparison](daily-deviation-correlation.json) and [receipt manifest](run-20260913-1610.json).

An offline probe invoking the actual compiled Common methods reproduced the 330-minute skew from the recorded Instant, Block and ESW RTC bytes. A synthetic fractional timestamp also decoded 50 hundredths as 50 milliseconds instead of 500. All four explicit UTC expectations fail. Nonzero and unspecified deviations were observed without assigning an expected UTC instant pending policy clarification; they are not counted as passes. Common's static initializer attempted an RTC-trend lookup but stopped before connection because runtime database configuration was absent. No live database or service was invoked.

The reusable probe is under `.codex/worktrees/vayu-common-push-frame-id/tools/DateTimeProbe`. No HES datetime production change is made yet. [Gurux documents opposite signs](https://www.gurux.fi/Gurux.DLMS.Objects.GXDLMSClock#deviation) for standard and Indian DLMS, so the convention and unspecified-deviation fallback have been requested. The [Gurux parser](https://github.com/Gurux/Gurux.DLMS.Net/blob/master/Development/Internal/GXCommon.cs) also confirms hundredths-to-milliseconds conversion. The earlier live timestamp skew and Daily energy rejection remain open. No deployment occurred and matrix live statuses are unchanged.

## Common fragment source fix: 2026-09-13, 16:00 UTC

The earlier HES `Int32` overflow has been reproduced in a source-isolated regression harness. Valid UInt32 frame IDs above `0x7fffffff` failed the push reassembler's `int.Parse` conversion. An isolated Common checkout at `0337feb506a1c9963ffd42d50c3aa592327c10dc` now preserves the wire bits with explicit unchecked signed casts for fragment storage, lookup and deletion, matching the existing pull behavior. No meter/template identity rule was added. Read-only catalog inspection confirmed signed integer storage with no nonnegative constraint; no database changes were made.

Before the fix, 18 cases passed and 6 high-ID push cases failed. After the fix, all **24 cases passed**, including duplicates, reversed arrival order, merged bytes, cleanup and pull correlation; checked arithmetic also passed all 24. The complete Common project built with 0 errors and 2,074 warnings. Tests extract the exact two production methods with in-memory dependency stand-ins; they do not verify the real repository/tracker, PostgreSQL persistence or live HES reassembly.

The fix is in `.codex/worktrees/vayu-common-push-frame-id`, with its runnable harness and explanation under `tools/FrameIdRegression`. No package, consumer reference or runtime was changed. Matrix live statuses are unchanged; release and a bounded fragmented replay remain required. See [source-fix evidence and hashes](run-20260913-1600.json).

## Fakerouting and pull access: 2026-09-13, 15:47–15:49 UTC

Two bounded fakerouting keepalives generated by the production topic mapper passed on the **normal MQTT route**: D1 Wirepas `FakeRouting/1000100001/2` and direct 4G `FakeRouting/1000400001/3`. Each received PUBACK and a matching observer receipt. HES changed only the target route's `lastcommunicatedon`, at 15:47:22.516551 and 15:47:43.330267 UTC respectively (about 45 ms and 28 ms after PUBACK). Existing route IDs, gateways, sinks and every other route field were preserved. The other meter's route remained unchanged between the two sends. See [routing correlation](routing-correlation.json).

Both selected meters are first meters of running DRISHTI MAYA batches with scheduled routing enabled. Their prior refreshes were at 15:30, and the sequential probe ran outside the next 16:00 window. No batch was stopped or modified. The local probe generator built successfully; no production application source changed in this pass. Both publishers and observers exited.

`vayu-routing` was PID 139850, started 15:07:15 UTC, with zero restarts and DLL SHA-256 `222bbf2708dfa97a7503e17d88e3f2dd9c2cbcb71376016d6a2351fdc677e020`. No new routing warning or error accompanied these probes. A separate 15:30 warning for RF node 1001500001 reported no existing route; RF initialization still requires real gateway/sink routing. These two refresh passes do not establish all categories/NIC variants or missing-route behavior.

The HES API's existing `RequestOnDemandData` endpoint is available under `https://10.254.3.185/vayu-api/`, but an unauthenticated request returned **HTTP 401**. At 15:49:11 UTC, API PID 66008 and pull PID 134152 were active; API DLL SHA-256 was `66597bd3dd9f5a6b6fbcae88770b195b5f3271ded8cf90da58924577b62a9188`. No usable signed-in browser session was connected and no command was created. An existing authorized test session or credential location has been requested. Direct SQL command insertion and authentication changes were not used as substitutes.

The selected meters also have running responders on DRISHTI MAYA (the earlier `daily-8ca673e0` snapshot). A workstation pull responder must use an isolated, registered test identity to avoid duplicate replies; testing the running server cannot prove the newer local custom-pull changes. This earlier API plan was superseded by the user's direct-database instruction; two bounded GetRTC commands subsequently completed through the existing responders. See [the latest receipt manifest](run-20260913-1547.json).

## Latest source checks: 2026-09-13, 15:40 UTC

Custom pull now requires configured per-template event IDs for generated event/DI responses and validates explicit response-header metadata for profiles and RTC. The RTC meter-template-number cutoff is removed. Focused checks passed 42 tests; the full Release suite passed **581 tests, zero failures or skips**. No deployment or live HES pull occurred in this pass. See [custom-pull metadata and ESW contract findings](../custom-pull-metadata.md). The ESW pull status remains unresolved in the matrix; the HES command name and the XML's distinct status/filter objects must not be conflated.

## Latest live evidence: 2026-09-13, 15:12–15:28 UTC

The metadata-driven custom encoder now supports Instant, Block, Daily, Billing, seven configured event families, ESW and custom Wirepas RTC. The production template-93 encoder was moved to test fixtures; only the old saved Daily selector remains as a compatibility alias. Payload fields and magic resolve from the selected HES template and category. Explicit DLMS selections retain DLMS encoding on every NIC. Configuration prerequisites and the current new-header limitation are described in [Daily push](../daily-push.md) and [PushProbe](../../tools/PushProbe/README.md).

The final full Release rerun passed **569 tests, zero failures or skips**. The first final run passed 568 and timed out in `BatchTrafficTests.EachStreamSendsOnePassSpreadAcrossWindowAndRepeats(BlockLoad)`; all 20 scheduling tests subsequently passed in isolation, then the full suite passed. The timing-sensitive result is retained in the evidence, not hidden by the rerun. `git diff --check` passed. Arbitrary template IDs across 1P/3P/CT fixture layouts test metadata resolution, but do not prove D2/D3 live compatibility.

HES was updated externally during this investigation. At 15:25:41 UTC, `vayu-core-push-rf-drop` was active with PID **129983**, start **14:55:43 UTC**, zero automatic restarts, application SHA-256 `6c604a951dd75c067bec5a4bf61af6b8722aae04aa9ca405fd0b10b688a47145` and Common SHA-256 `bcce384debce0f3f1cca458e81551e0aa28f023afafeb4f3d06d5012417c898f`. The earlier process had reported dictionary cache count 0; the new process reported 6488. Improvements cannot be attributed solely to the simulator encoder. This verification run performed no deployment or configuration changes.

### Custom D1 diagnostic ingestion

Fourteen bounded custom packets were sent directly to the existing `drop/gw-event/.../10/10` subscription. Thirteen persisted successfully; the initial voltage event ID 1 was not allowed by D1 HES settings. The final encoder requires configured event IDs rather than assuming one. Using allowed IDs 7, 51, 101, 151, 201, 251 and 301 produced all seven event-family records.

Every successful packet was matched byte-for-byte to its raw HES receipt and persisted record. **93 field checks passed** against the actual encoded values: every configured numeric/date field, the RTC profile's clock, and all 128 ESW bits. HES intentionally truncated the main Block, Daily and Billing date fields to the minute; this was accounted for explicitly. No correlated errors were found in the latest custom probe window; unrelated service warnings are not counted as probe failures.

| Custom profile | Persisted ID | Result |
| --- | --- | --- |
| Instant | 40051043 | All 22 fields match |
| Block | 39563268 | All 8 fields match |
| Daily | 2117590 | All 5 fields match |
| Billing | 378981 | All 23 fields match |
| Voltage / current / power events | 4285884 / 4285882 / 4285881 | Configured fields and IDs match |
| Transaction / other events | 4285883 / 4285886 | Configured fields and IDs match |
| Non-rollover / control events | 4285887 / 4285885 | Configured fields and IDs match |
| ESW | 3639314 | RTC and all 128 bits match |
| RTC | 809187 | Device clock matches |

These are passes for the **diagnostic drop path**. Normal-topic forwarding remains unverified, and the metadata encoder has not been deployed to MAYA on DRISHTI or EQA. See [custom packet correlation](custom-metadata-correlation.json).

### DLMS D1 recheck on the new HES process

Four fresh packets sent at 15:27:23 UTC received broker acknowledgements, observer matches and exact raw HES receipts. Instant and Block now persist; the earlier nullable and database date failures did not recur. Current outcomes are:

| DLMS profile | Current result |
| --- | --- |
| Instant | Row 40115507; encoded RTC 15:26:40 with deviation 0, stored 09:56:40 |
| Block | Row 39593468; encoded RTC 15:30:00 with deviation 0, stored 10:00:00 |
| Daily | Raw receipt 955574f8-2e4e-4ad3-b9ea-89b801641a86; no profile row. Current warning rejects import kWh 4684814.453 and import kVAh 4883597.167. Encoded values preserve the template values; scaling/fixture compatibility remains unresolved. |
| ESW | Row 3658978; all 128 bits match; encoded RTC 15:26:40 with deviation 0, stored 09:56:40 |

The three persisted RTCs are exactly **330 minutes early**. Local Vayu Common `Functions.GetTimeOffsetInMinutesFromByteArray` still returns -330 regardless of the packet deviation, consistent with the live result. No HES source or runtime fix is claimed here. [DLMS correlation](dlms-current-correlation.json) records raw IDs, payload hashes, encoded deviations and persisted IDs.

The [latest manifest](run-20260913-1512.json) and durable receipt `C:\Users\ayush\Documents\MAYA-release-receipts\scenario-verification-20260913-1512` retain inputs, generated bytes, metadata exports, PUBACKs, read-only SQL results, source hashes, tests and HES logs. Credentials are not stored. All bounded publishers and observers exited.

## Historical evidence: 2026-09-13, 14:43–14:57 UTC

The current `Custom-Push-Implementation` worktree passes **511 tests, zero failures or skips**. This is a different source snapshot from the earlier 527-test deployed snapshot; neither count proves live matrix coverage. No application deployment or HES configuration change was performed in this run. Existing unrelated worktree changes were preserved.

A new `tools/PushProbe` generates bounded payload artifacts from the production session/encoders/codecs, taking meter and template inputs from a JSON configuration. It does not publish automatically or contain broker credentials. The probe is not a replacement for coordinator tests. Local public DLMS read exchanges are also available and report empty data separately from protocol errors.

DRISHTI's verified HES host is `10.254.3.185`. Its `vayu-core-push-rf-drop` service was active with PID 116854, start time 14:24:31 UTC, zero automatic restarts and two MQTT connections to the DRISHTI broker. `vayu-core-pull` was active. Normal RF/TCP/combined push units were inactive. Application and Common hashes are in [the run manifest](run-20260913-1447.json). This is newer HES code than the earlier Daily deployment investigation.

### Local machine to broker and HES

The selected registered D1 meters were MY00400001/node 1000400001 (HES template 88, direct DLMS) and MY00100001/node 1000100001 (HES template 93, custom Wirepas). These are explicit test inputs, not new production identity rules.

Four plaintext DLMS packets (Instant, Block, Daily, ESW) and two custom packets (Daily, ESW) were published once from this workstation. Broker PUBACK and byte-identical observer receipt were recorded for all six normal-topic packets. None had a corresponding `drop/` observation or raw HES receipt at the bounded pre-replay check. The active service subscribes to `drop/` topics. Normal-route delivery remains unverified/failed; inspect the intended consumer and forwarding topology rather than assuming a broker acknowledgement means HES receipt.

Each captured packet was then replayed **once** onto the existing corresponding `drop/` subscription. All six produced raw HES receipts. Exact payload comparison matched each receipt to its generated artifact. This proves the diagnostic replay path, not the original normal route.

| Case | Diagnostic replay outcome |
| --- | --- |
| DLMS Instant | HES error at 14:49:40.1938 UTC: `Nullable object must have a value.` Stack: `System.Nullable<T>.get_Value` → `GenericParser.ParseAndSaveInstantProfile` → `ParseAndSavePushDataToDb` → `ParseDLMS` → `MQTTDataReceiverDirectDLMSClient.cs:104`. Raw ID `5ae78c5a-cfaf-4e00-9a63-c5d4e93a31a2`. No new Instant row observed. Exact nullable field is not yet established. |
| DLMS Block | Raw ID `c2dd0a66-d8c7-447f-a773-574af479a7a8`; no Block row observed. Do not infer successful parsing from the absence of a correlated warning. |
| DLMS Daily | Raw ID `58c8324a-a7fa-4e02-922e-56971ddc8f0b`; no Daily row observed. The older release's energy-validation error is historical context and was not reproduced in this run's current warning log. |
| DLMS ESW | Persisted row `3626316`; all 128 bits exactly match. Encoded RTC 14:47:16 UTC, stored RTC 09:17:16: 330 minutes early. |
| Custom Daily | Raw ID `9a24380d-b01c-4b09-9b95-67ce32c4acde`; no new Daily row observed. The earlier 12:31 row still exists but cannot be claimed as this run's success. |
| Custom ESW | Persisted row `3626317`; exact 128-bit match and RTC matches the original encoded 14:47:16 UTC. Compare with generation time, not the later replay time. |

At this historical push-verification stage, database checks used read-only transactions on KimbalHES replica `10.254.3.137`; recovery and read-only status were verified. The later D1 wave performed two explicitly authorized command inserts on the primary. Normal HES ingestion performed the test inserts. No observers or continuous test loops remain running.

### Local DLMS pull

Fresh public-association reads against `SA1231166HP_values.xml` returned nonempty responses for Instant, Block, Daily, ESW and GetRTC. The original XML contains zero Billing rows and zero rows for each of the seven event families; all those reads returned empty arrays. Stale XML `EntriesInUse` values do not establish actual row presence.

The alternate `SA1231166HP_values_bill.xml` initially returned DLMS error 3. Wave 1 traced this to host-culture parsing of US-formatted dates, fixed it and verified a successful bounded public Billing read from D1_Master.xml. These local reads do not prove a HES command lifecycle, transport response correlation or database persistence.

## Hardcoding audit — requirement not satisfied

| Location | Finding and required direction |
| --- | --- |
| `Brain/MqttPushProfiles.cs` | Resolved in the latest source: generic custom keys; the old Daily key remains only as a saved-selector compatibility alias. |
| `Brain/PushCoordinator.Mqtt.cs` | Resolved in the latest source: `CustomPushEncoder` selects capabilities and packing from supplied metadata. Explicit DLMS remains independent of custom selection. |
| Former production `Networking/CustomPush/Template93.cs` | Moved to historical golden test fixtures. Production uses generic metadata and shared synthetic value generation. Legacy headers and D2/D3 live layouts remain unverified. |
| Core `DLMSServerSession.DailyPush.cs` | Fallback assumes five captured Daily columns. It preserves numeric values and supports explicit PushSetup precedence, but is not proof that every vendor/category's required Daily fields are covered. |
| `Networking/SmartNic/CustomRtcCommand.cs` | Resolved in the latest source: support now validates exported response-header metadata, independent of meter template numbering. Legacy 24-bit response node limits and the HES receiver's own template allow-list remain. |
| Vayu Common `Helpers/GenericHelpers.cs` | `HardCodedEnabledGenericTemplateIds` uses `>26` with exclusions 47 and 48 across all four paths. The no-template-hardcoding requirement also requires auditing this HES behavior. |
| Vayu Common `Helpers/Functions.cs` | `GetTimeOffsetInMinutesFromByteArray` returns -330 regardless of DLMS deviation. The observed ESW RTC skew matches this conversion. |

Protocol discriminators, standard OBIS identifiers, endpoint numbers and scalar/type definitions are not automatically invalid hardcoding. Meter/template identity branches and unverified category/layout assumptions are the problem. Existing configurable custom-pull metadata is useful groundwork, but its tests alone do not establish complete runtime support.

The initial HES log also contained `Int32` overflow in `IsCompletePacketNewHeader`. Source inspection places the risky `int.Parse(UInt32)` inside multi-fragment handling. The live custom packets were single-fragment and did not reproduce it; do not attribute that pre-existing error to those probes. The later 16:00 source regression reproduces and fixes the high-ID conversion, but the live fix is still unverified.

## Remaining work

1. Resolve the current DLMS RTC conversion and Daily energy/template compatibility issues. The earlier Instant nullable and Block persistence failures did not recur on the newer HES process.
2. Establish normal-topic consumer/forwarding behavior across the actual service hosts; server details are still pending from the user.
3. Validate legacy custom header contracts and the new metadata configuration on the intended MAYA runtime. New-header custom D1 diagnostic ingestion now passes for all seven requested profile types and all seven event families.
4. Verify DLMS and custom pulls through the real HES command lifecycle, including ESW/ESWF contract clarification, GRBlockLoad and fakerouting. Current custom decoder has no ESW command mapping.
5. D2/D3 XMLs, mappings and per-variant execution are deferred to future waves by the user.
6. Re-run affected tests and live scenarios after fixes. No row becomes a complete pass until emitted bytes, receiver parsing, expected values/timestamps and persistence are correlated.

Durable evidence: `C:\Users\ayush\Documents\MAYA-release-receipts\scenario-verification-20260913-1447`. It contains the test TRX, generated payloads and hashes, normal/replay broker results, SQL outputs, exact HES error text and payload correlation records. Credentials are not stored in these artifacts.





