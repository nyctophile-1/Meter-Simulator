# D1 live pull after deployment

MAYA release `d1-cd070faf` was deployed to DRISHTI and EQA with full data recovery copies, exact application/core/master hashes, HTTP 200, IPv6 listener/route checks, stable processes and preserved saved logical state. Existing batch XML selections were retained. D1_Master.xml is available but is not substituted into every batch.

## Instant pull

| Path | Command | Outcome |
| --- | --- | --- |
| Custom, MY00100001 | 98932914, frame 10001 | Status 4, successful, one try. MAYA logged custom GetInstantaneousProfile response; HES logged final pull success. Persisted instantaneous row 40991843 links this command, has RTC 2026-09-13 18:26:16 UTC, creation 18:26:17.160 and voltage 231.000. Full field parity is not yet claimed. |
| DLMS, MY00400001 | 98932913, frame 10001 | Status 5 after one try, completed 18:27:58.935963 UTC. HES received the malformed release response and logged Invalid data type. No Instant profile row was found for this command. |

Both were bounded application-contract inserts directly into the verified KimbalHES primary. No API, schema, HES configuration, HES service restart or second local responder was used. The exact command helpers, inserts, state queries and HES/MAYA log excerpts are in the release receipt.

## Release response defect

The captured wrapper payload is:

```text
00 01 00 01 00 10 00 17 63 11 80 01 00 BE 0F 04 0E 08 00 06 5F 1F 04 00 62 1E 5D FF FF 00 07
```

The nested BER lengths do not cover their contents. The vendored server writes `tmp.Length + 3` for the release content and `tmp.Length + 1` for the user-information content, omitting enclosing tag/length bytes. A new public association -> invocation-counter read -> release regression feeds the result into the .NET ASN.1 BER reader, which rejects the original response.

The fix builds each inner value first and derives the enclosing length from its actual encoded size. The same test then validates all nested boundaries and parses the response as Gurux ReleaseResponse. No meter/template/NIC branch or XML model change was added. The full local suite passes 590 tests. Release ber-d2d245b5 is deployed on both servers; app/core hashes and saved state remain unchanged. EQA has a complete hash-verified offhost app/data archive, rather than a metadata-only backup. See the [deployment receipt](../../deploy/ber-20260914-manifest.json).

Post-fix command 98932915 (frame 10002) was created at 18:57:48.540632 UTC and failed after one attempt at 18:59:49.848625. The final expected response was GetResponse (196). The earlier one-hour routing guard rejected an insert before any command was created; the successful insert used the unchanged route observed at 17:30 after checking the running MAYA responder and HES pull broker. No routing row was fabricated. The HES log stops at public-client read. Its intermediate command state alone does not prove that a release exchange occurred. Command 98932916 is a separate bounded retry with a passive observer on this node's two Poll topics.

At 18:56 UTC, the DRISHTI HES pull process was running (PID 215274, started 18:48:02), while all push variants and routing services were inactive. The database push broker setting differed from the previously verified DRISHTI broker, so the guarded routing publisher stopped before connecting. No HES service/configuration was changed. Fresh push persistence and fakerouting checks need a running consumer on the intended broker.

The passive capture for 98932916 recorded duplicate AARE, counter and corrected release responses. Both MAYA hosts logged answering this node/frame at 19:04:30.469 UTC: DRISHTI through LHES EQMS and EQA through LHES Optimization. HES then logged parser/state errors and the command failed at 19:06:14.446149, expecting release (99). This is confirmed overlapping responders, not proof that the corrected release packet alone fails. The observer disconnected after its MQTT keepalive expired; the twelve messages before that are retained, and DB/server logs independently establish failure and duplicate origin. Isolate one simulator before further lifecycle tests. No batches were paused while waiting for the user's fleet-ownership preference.

## Release test timing

The first isolated release run passed 588/589 tests. BatchTrafficTests advanced its fake clock when a sender had recorded delivery, before all subsequent delay timers were registered. The test now waits for the window deadline, maintenance timer and next-slot timer before advancing virtual time; failed assertions also dispose the service. All 20 focused batch-traffic tests and the complete 589-test release suite pass. This changes test synchronization only.

## Next actions

1. Both BER deployments are verified; preserve their full recovery receipts. EQA has approximately 311 MiB root space after the patch.
2. Re-run DLMS Instant through the complete secure association and correlate its profile row. The local BER pass alone does not prove the live command is fixed.
3. Continue bounded D1 custom profile commands, event-family checks and GRBlockLoad, and audit all decoded fields.
4. The physical Daily comparison confirms the scaler multiplication: wire float32 847.8488 becomes client XML double 847848.8159179688. The capture tool now saves a separate profile-wire export, and a regression verifies its values through XML, simulator pull and Daily push. The local master uses three compatible physical Daily rows without changing the model. Other historical profile buffers still need a wire-value audit; fresh HES Daily persistence remains unproven.
5. D2/D3 remain future waves. The original matrix remains incomplete.
