# ESW push

Select **ESW (Event Status Word)** in Testing, MQTT stress, TCP stress, or a saved stress task. The selector is `0.4.25.9.0.255` for both custom and DLMS batches. The coordinator chooses the encoding from the batch configuration.

Both encoders use the current meter value at `0.0.94.91.18.255`, with exactly 128 binary digits. This is ESW, not the filter mask at `0.0.94.91.26.255`. Template defaults are used until that meter's state changes. Sending a push does not raise, clear, or cycle event bits. Live runs read the value each pass; prepared runs retain the value captured during preparation.

## DLMS

The alert setup emits a flat DataNotification structure:

1. Per-meter device ID.
2. Push setup logical name: `0.4.25.9.0.255`.
3. COSEM clock value (12 bytes).
4. ESW as a DLMS BitString (128 bits).

The existing TCP and MQTT DLMS encoders retain their framing and ciphering behavior. ESW uses a temporary data object during encoding so sending one meter's status cannot alter the template default inherited by future sessions. Empty alert setup object lists were populated in `SA1231166HP_values.xml`, `SA1231166HP_values_bill.xml`, `Template-31-D2.xml`, and `SZ0000014HP_Only_Push.xml`. The last template also needed a typed, cleared ESW default. Existing populated alert setups remain intact. Uploaded templates still need their own valid alert setup and ESW object.

**All** now includes ESW alongside other non-empty DLMS push setups. Repeated ciphered pushes generate fresh frames through the existing invocation-counter path. Prepared ciphered mode remains unavailable.

## Template 93 custom Wirepas

Supported on Wirepas batches with HES template 93 and the new custom header. ESW is packed in the consolidated `Template93` encoder and sent on `gw-event/received_data/{gateway}/{sink}/{node}/10/10` using the existing configurable gateway, sink, and endpoint settings.

| Body offset | Size | Content |
| --- | --- | --- |
| 0 | 1 | Profile 5: ESW |
| 1 | 1 | One frame, clock status zero |
| 2 | 9 | Existing zero meter/reserved header fields; identity comes from the Wirepas node |
| 11 | 4 | Little-endian wall-clock epoch, UTC plus 330 minutes |
| 15 | 2 | `04 80` bit-string tag/bit count |
| 17 | 16 | ESW bytes, most significant bit first |

The 33-byte body is enclosed in the existing 12-byte new header (45 bytes total) and Wirepas protobuf envelope. The checked HES generic ESW reader consumes two bytes after RTC without validating their values, then reads 128 bits. The encoder supplies `04 80`; exact device metadata-byte semantics have not been validated against a live capture. The HES custom date reader subtracts 330 minutes, so the ESW epoch offset preserves the intended UTC instant on that parser.

The checked HES enum routes **5 to ESW and 7 to Daily**. The old simulator Daily encoder used 5; it now uses 7 to prevent Daily being routed into the ESW parser. Its existing energy layout and timestamp encoding are otherwise unchanged.

**All** sends Daily and ESW as separate messages. Explicit Daily retains its session-free generation path. ESW resolves the live meter session, so selecting ESW or All can materialize sessions for meters not already loaded. A missing or malformed ESW fails validation rather than fabricating a value.

## Contract evidence and validation

Receiver source inspected locally on 2026-09-13:

- `vayu-common`, `master-pg`, HEAD `79f6a15`: `CustomGenericParser.ParseHeader`, `ParseESW`, `Helpers/Functions.PushType.NonDLMSProfileType`, `NonDLMSDataParser.GetDateTime/GetBinaryString`, and `DLMSGenericParser.ParseAndSaveESW`.
- `vayu-core`, `master-pg`, HEAD `74ff0565`: `MQTTDataReceiverClient` custom dispatch and Wirepas endpoint subscription.

Regression coverage includes plaintext and encrypted DLMS decoding, per-meter ESW isolation, all four updated templates, profile discovery, custom bit order/RTC conversion, new-header/protobuf framing, live/prepared ESW and All selection, existing Daily, and TCP/MQTT push runs.

Result: **71 passed, 0 failed, 0 skipped** on 2026-09-13. The application and test projects compiled; existing dependency, nullable, obsolete-API, and UI analyzer warnings remain. `git diff --check` passed.

Validation command (from the Meter-Simulator repository):

```powershell
dotnet test ManyMeterSimulator/ManyMeterSimulator.Tests/ManyMeterSimulator.Tests.csproj --no-restore --filter 'FullyQualifiedName~EswPushTests|FullyQualifiedName~MqttPushRunTests|FullyQualifiedName~PushBlockLoadProfileTests|FullyQualifiedName~PushInstantaneousProfileTests|FullyQualifiedName~CustomPushFramerTests|FullyQualifiedName~TcpPush|FullyQualifiedName~TcpStress' --logger 'trx;LogFileName=esw-push.trx'
```

No live broker/HES database ingestion, deployment, or full repository test suite is claimed. Local receiver-source compatibility does not establish the version deployed on EQA or DRISHTI. Running instances need a restart/reload to pick up changed bundled templates.
