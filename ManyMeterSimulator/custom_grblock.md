# Custom GRBlockLoad

GRBlockLoad (command 21, selector 5) generates synthetic block rows from the selected HES data model. It uses the existing custom MQTT endpoint 13 dispatch and response publishing path. It does not open a DLMS meter association, including when other profile commands use `ProfileDataSource: Meter`.

## Flow

1. Parse and validate the template-selected custom request header, including its CRC where required.
2. Read `ValueFrom` as FromDate and `ValueTo` as an unsigned 32-bit bitmap, not an end date.
3. Resolve the batch's HES template, its `BlockTemplateId`, and `BLOCK_CUSTOM_PULL_<configured category>` field list.
4. Generate each logical period's engineering values. Encode selected rows in metadata `SerialNumber` order using each field's `DataType` and `Scalar`. Row size comes from the encoded fields; there is no Template 93 or category-specific row-size branch.
5. Return only selected periods in one assembled block profile response (profile type 19), retaining the request frame ID. Rows are reversed on the wire because the generic HES block parser reads them from last to first.

Known electrical fields receive repeatable simulated values. Unknown numeric fields receive stable small values that respect their declared scalar. Unsupported field types, missing layouts, ambiguous field order, and numeric overflow fail before any response is published.

## Request and periods

The HES sender's `GetGapReadingBits` requires exactly **32 characters**. To select the first two slots, use:

```text
11000000000000000000000000000000
```

Character zero becomes bit zero (the least-significant bit), so this bitmap is uint32 `3`, serialized `03 00 00 00`. The existing HES helper converts a 16-character input to zero; this simulator change does not alter that HES helper.

The simulator's slot contract is `timestamp = FromDate + bitIndex * period`. Bit zero corresponds to FromDate itself. FromDate must be aligned to the configured period. This anchor should be confirmed in a live HES command before treating the timestamps as verified end to end.

The metadata field exports do not specify capture period. Configure a default of 15 or 30 minutes, with optional per-template overrides:

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

The new profile header has a four-bit row count: at most **15 set bits per request**. Larger selections fail with an instruction to split the request. Transport fragmentation cannot expand that profile row count. A zero bitmap returns the existing no-data profile (100). Row, byte, cancellation, and timeout limits also apply.

Template 93's exported 1P layout 49 encodes 18 bytes per row. Two selected rows produce 59 bytes: 12 transport + 11 profile header + 36 row data. Tests check HES-style reverse row traversal, timestamps, scalars, 15/30-minute energy values, bit 31, empty and oversized selections, limits, and alternate 3P/CT metadata with reordered fields and different widths.

Local tests validate the packet layout against the inspected generic HES parser. They do not establish that a live EQA HES command has completed or that every vendor-specific HES parser accepts these packets.

Source references used for the wire contract: `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCustomCommandClient.cs` (GR sender), `vayu-common/CrystalHES.Common/Helpers/CustomPullCommandPayload.cs` (bitmap), `CustomGenericParser.cs` (block parser), and `GenericHelpers.cs` (row offsets).
