# Custom GRBlockLoad

GRBlockLoad (command 21, selector 5) generates synthetic block rows from the selected HES data model. It uses the existing custom MQTT endpoint 13 dispatch and response publishing path. It does not open a DLMS meter association, including when other profile commands use `ProfileDataSource: Meter`.

## Flow

1. Parse and validate the template-selected custom request header, including its CRC where required.
2. Read `ValueFrom` as FromDate and `ValueTo` as an unsigned 32-bit bitmap, not an end date.
3. Resolve the batch's HES template, its `BlockTemplateId`, and `BLOCK_CUSTOM_PULL_<configured category>` field list.
4. Generate each logical period's engineering values. Encode selected rows in metadata `SerialNumber` order using each field's `DataType` and `Scalar`. Row size comes from the encoded fields; there is no Template 93 or category-specific row-size branch.
5. Return only selected periods in complete block profile responses (profile type 19), retaining the request frame ID. Each new-header response contains at most 15 rows. Rows within each response are reversed on the wire because the generic HES block parser reads them from last to first.

Known electrical fields receive repeatable simulated values. Unknown numeric fields receive stable small values that respect their declared scalar. Unsupported field types, missing layouts, ambiguous field order, and numeric overflow fail before any response is published.

## Request and periods

The HES sender's `GetGapReadingBits` requires exactly **32 characters**. To select the first two slots, use:

```text
11000000000000000000000000000000
```

Character zero becomes bit zero (the least-significant bit), so this bitmap is uint32 `3`, serialized `03 00 00 00`. The existing HES helper converts a 16-character input to zero; this simulator change does not alter that HES helper.

The simulator's slot contract is `timestamp = FromDate + bitIndex * period`. Bit zero corresponds to FromDate itself. FromDate must be aligned to the configured period. This anchor should be confirmed in a live HES command before treating the timestamps as verified end to end.

The metadata field exports do not specify capture period. The current implementation uses a configured default of 15, 30 or 60 minutes, with optional per-template overrides; it does not yet derive PCP from the meter XML:

```json
{
  "CustomPull": {
    "BlockPeriodMinutes": 15,
    "BlockPeriodMinutesByTemplate": { "93": 30 },
    "MeterCategories": { "93": "1P" }
  }
}
```

The example override makes Template 93 use 30 minutes; omit it for the default 15 minutes. Category selects the exported layout rather than a hard-coded encoder. Other templates can be configured in the same dictionaries. Existing framing/magic-number configuration and data-model exports remain necessary.

The HES sender adds 330 minutes to FromDate before serializing. `BlockRequestOffsetMinutes` reverses that shift; `ResponseTimestampOffsetMinutes` defaults to 330 to match HES's timestamp decoder.

## Limits and verification

One command covers at most eight hours. Only the first `480 / PCP` bitmap characters are considered: 32 for PCP 15, 16 for PCP 30, and 8 for PCP 60. Later bits are ignored even when set; they never fail the command or generate future records. Masking happens before row-limit validation and generation. If only ignored bits were set, the effective selection is empty and returns the existing no-data profile (100). Zero bits within the valid window preserve their slot positions.

The new profile header has a four-bit row count. With an all-ones bitmap, PCP 15 produces three complete responses containing **15 + 15 + 2 rows**, PCP 30 produces **15 + 1**, and PCP 60 produces **8**. Each response has its own profile header and retains the command frame ID; these are separate complete responses, not transport fragments of a single oversized profile. HES would concatenate transport fragments and still read only one four-bit row count. Row, aggregate byte (including every header), cancellation, and timeout limits apply before publishing any packet.

Template 93's exported 1P layout 49 encodes 18 bytes per row. Two selected rows produce 59 bytes: 12 transport + 11 profile header + 36 row data. At PCP 15, all 32 rows produce 645 bytes across the three responses. Tests check HES-style reverse row traversal, timestamps, scalars, 15/30/60-minute energy values, bit 31 at PCP 15, 15/16/31/32 selected rows, sparse selections, ignored trailing bits, empty effective selections, limits, and alternate 3P/CT metadata with reordered fields and different widths.

Custom block pushes use the same configured capture period as GR. Their timestamp is floored to the configured period, and generated block energy uses that period. The previous custom push sender supplied its current send time to the block fields, causing off-boundary records. GR timestamps remain anchored to the requested FromDate and selected bit positions; they are never replaced by the current clock.

## Investigation on 2026-09-17

DRISHTI MAYA was running source `3cac283a9251ac7147874ebaf71c1b5161bdb8d3`. Its `RF` batch (ID 4) contained 200,000 meters starting at index 100001, using `PKG9.xml` and HES template 93. Sampled HES nameplates report a 15-minute capture period. Command `99755777`, meter `MY00140267`, frame 6917, requests `FromDate=2026-09-15T18:45:00Z` and 32 ones. The live MAYA log confirms the old 15-row exception. The expected stored UTC timestamps are 18:45 on September 15 through 02:30 on September 16, inclusive, at 15-minute intervals. The regression test checks this exact time anchor and mask.

Read-only database inspection also found RF block rows at off-boundary times (for example, `MY00140267` at `2026-09-17 11:06:00` and `MY00200000` at `11:14:00`) with null HES command IDs. These rows are not evidence of successful GR responses. No successful command-21 rows were found in the queried September 17 command window. The custom push source independently confirms the current-clock timestamp defect; a new live GR response/persistence comparison remains necessary.

The inspected HES custom receiver retrieves commands with `onlyPending=false`, allowing subsequent complete responses for the same frame to be parsed after the first. It can mark the command successful after the first response, so command success alone cannot prove all selected rows arrived. Live acceptance must compare the complete set of expected timestamps and HES command IDs, including the final two rows of a full bitmap.

The three reported masks with `FromDate=2026-09-16T10:45:00Z` are covered by explicit expected-time regressions **for PCP 15**. Their UTC window is 10:45 through 18:30 on September 16, inclusive:

| Bits | Rows | Omitted UTC timestamps |
| --- | ---: | --- |
| `11111111111111111111111111111111` | 32 | None |
| `11111110001111111111111111111111` | 29 | 12:30, 12:45, 13:00 |
| `00111111111111001111111111011111` | 27 | 10:45, 11:00, 14:15, 14:30, 17:15 |

Each zero consumes its original slot. Later one bits keep their original timestamps. Encoded payload clocks have the configured 330-minute shift: the last UTC slot, September 16 at 18:30, is encoded as September 17 at 00:00 before HES subtracts that shift.

A subsequent read of the deployed RF `PKG9.xml` found block profile `1.0.99.1.0.255` configured with CapturePeriod 1800 seconds (30 minutes), while the sampled HES nameplates and MAYA fallback report 15. This mismatch remains unresolved. The PCP-15 expected-time examples must not be treated as proof of the RF meter's actual capture period. Meter-derived PCP resolution and capture-clock boundary handling remain necessary before live acceptance.

Local tests validate the packet layout against the inspected generic HES parser. They do not establish that a live EQA HES command has completed or that every vendor-specific HES parser accepts these packets.

Source references used for the wire contract: `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCustomCommandClient.cs` (GR sender), `vayu-common/CrystalHES.Common/Helpers/CustomPullCommandPayload.cs` (bitmap), `CustomGenericParser.cs` (block parser), and `GenericHelpers.cs` (row offsets).
