# D1 master: wave 1

The user selected D1 for the current wave, deferred D2/D3, authorized direct database command insertion instead of the API, and requested current simulated time. DLMS remains independent of NIC type; RTC push is custom Wirepas only.

## Composition

`ManyMeterSimulator/Templates/D1_Master.xml` retains all 160 objects from `SA1231166HP_values.xml` and imports the 13 Billing rows from `SA1231166HP_values_bill.xml`, plus 39 event rows from a fresh physical D1 capture. Both sources explicitly identify meter type 6/category D1 and have identical ordered Billing capture definitions and compatible scaler/unit definitions. The source files are unchanged by this composition.

The composer checks the complete base model before and after writing, excluding only profile Buffer and EntriesInUse. Logical names, object classes and versions, access rights, capture columns, scalers, units, security objects, capacities and existing push definitions are preserved. EntriesInUse is corrected to the actual row count. Formatting and comments are not part of the semantic model.

The D2, D3 and SZ/CT-family XMLs were inventoried but excluded from this merge. Similar OBIS identifiers alone do not establish compatible profile layouts. No event rows or Billing/event push definitions were invented. Secure capture of SA1038079 supplied 13 voltage, 13 power, 1 transaction and 12 other-event rows with matching capture layouts and scalers. Current, non-rollover and control-event buffers remain empty on both the source meter and master; it advertises Instant, Block and ESW push definitions, with Daily supplied by the existing simulator fallback.

See [initial composition](d1-master-composition.json), [Daily replacement](d1-daily-wire-composition.json), [Instant/event replacement](d1-profiles-wire-composition.json) and [100-row Block replacement](d1-block-wire-composition.json). The current local and deployed master SHA-256 is `9328f37b2c6b0b9a2beceb22f1db326fbd19b3b07aea5b5ddf855cdb2b7fdb38`.

The master uses three Daily, 100 Block, one Instant and 39 event rows captured from SA1038079 on September 14 (India time). Raw wire values are restored before using the donors: Gurux's ordinary client XML applies register scalers. The composer verifies all 160 object definitions unchanged. The original compatible 13 Billing rows remain because the physical Billing donor has a class mismatch for a captured object, as detailed in the [release receipt](d1-release-20260914.md). The master and loader fixes are deployed on both servers; existing batch template selections remain unchanged.

## Current time and Billing correction

Historical XML timestamps remain intact. At runtime the simulator supplies its current UTC clock and shifts profile recency while preserving the intervals between rows. Push generation uses the current runtime time. Historical profile rows are not all collapsed onto a single timestamp.

The Billing donor uses US-formatted datetime strings. Host-dependent parsing left these as strings on en-IN/fr-FR systems and subsequently produced a DLMS error 3 when Gurux attempted to encode them. This was a date-parsing defect, not evidence of an association access-rights defect. The loader now parses those strings using invariant culture and UTC semantics, without changing their source values or capture definitions.

The focused regression failed on en-IN and fr-FR before the fix and passed all four cases afterwards. The complete simulator Release suite passed 589 tests, zero failures/skips. Seven Python composer checks passed after allowing incompatible unselected donor profiles to remain excluded; all imported profiles still require full compatibility. A fresh local probe successfully read Instant, Block, Daily, Billing, RTC and ESW, and generated all four advertised push families; the four imported event profiles also read successfully, while the remaining three event profiles were empty. This is local source validation, not deployment or HES ingestion proof for the new master.

## Direct database command verification

Two GetRTC commands were inserted into the verified KimbalHES primary using the application command contract: generated identity, pending status 1, OnDemand 2, medium priority 2, one allowed attempt, current UTC CreatedDate, resolved existing route and no competing pending command. No API or schema changes were needed. Existing DRISHTI responders handled them; no duplicate local responder was started.

| Path | Meter | Command ID | Created UTC | Completed UTC | Result |
| --- | --- | --- | --- | --- | --- |
| DLMS | MY00400001 | 98932773 | 17:41:01.246525 | 17:41:14.290780 | status 4, success, one try; `2026-09-13T17:41:13.255Z` |
| Custom | MY00100001 | 98932775 | 17:41:30.868190 | 17:41:36.987755 | status 4, success, one try; `2026-09-13T17:41:36Z` |

All times are 2026-09-13. Both results match current time at whole-second resolution. The DLMS fractional `.255` has not been packet-correlated and is not claimed as fractional-second correctness. These commands prove the existing runtime command lifecycle, not deployment of the current local master or pending Common fixes.

Evidence workspace: `C:\Users\ayush\AppData\Local\Temp\maya-d1-wave-20260913`. The command helpers are local, bounded and idempotent; do not rerun successful inserts. Full push/pull coverage remains incomplete, including the recorded HES push timestamp conversion and Daily energy validation issues.

## Physical D1 source

The first supplied template-31 endpoint authenticated successfully and reported SA1038079, meter type 6/category D1. Capture ran from 18:00:24 to 18:04:26 UTC on 2026-09-13: 155 objects, 396 exchanges, 33,606 received bytes, no denied/failed requested attributes. The physical source SHA-256 is `a27f97501b7ab010879b5f5b24bbc36fe48aaf9484ae9e8c46208b3eb2a3908b`.

The raw capture is retained separately as `C:\Users\ayush\Documents\MAYA-release-receipts\d1-wave-20260913-1804\captures\D1_SA1038079_20260913.xml`, with its capture report. Its EntriesInUse describes the physical meter's complete buffers; only bounded rows were downloaded. The master corrects its own counts to the rows actually imported.

An existing Billing profile in the master is not replaced by a donor with an incomplete association view. Compatibility checks apply to each imported profile, and unrelated donor objects cannot alter the base model. Four event profiles passed all checks; their rows are copied without changing values or types. See [physical capture details](physical-meter-capture.md).


## Deployment and next live pull: 2026-09-13, 18:23-18:31 UTC

MAYA snapshot d1-cd070faf is deployed on DRISHTI and EQA. Both application/core DLL hashes and the master XML hash match the package. All original batch selections/statuses, network bindings and persistent state were preserved; D1_Master.xml is available as an additional template. The installer preserved existing configuration values and added the metadata settings needed by the generic custom encoder. The isolated release suite passed 589 tests after correcting a fake-clock scheduling race in BatchTrafficTests; production scheduling did not change.

Custom Instant command 98932914 completed and persisted row 40991843 with its command ID and current RTC. DLMS Instant command 98932913 failed while HES decoded the association-release reply. Release `ber-d2d245b5` corrects the nested BER lengths and is deployed on both servers, with 590 tests and full recovery receipts. The next live Instant command 98932915 timed out waiting for GetResponse, so end-to-end DLMS Instant remains unproven. See [the live-pull investigation](d1-live-pull.md), [D1 deployment](../../deploy/d1-20260913-manifest.json) and [BER deployment](../../deploy/ber-20260914-manifest.json).
