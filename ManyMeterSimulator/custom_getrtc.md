# Custom GetRTC

GetRTC (command 48, selector 1) is implemented for Wirepas custom requests on endpoint 13.
It reads DLMS clock `0.0.1.0.0.255`, attribute 2, using the simulator's supported public
read association. The association is separate from an ordinary HES association and shares
the meter's value store without reinitializing it. This is not an HLS/ciphered command runner.
The existing brain currently returns UTC-now for this clock attribute; custom GetRTC follows
that same behavior and does not add a separate clock or implement SetRTC.

The response echoes the full request frame ID and uses the originating broker, gateway and sink,
with Wirepas source/destination endpoint 13. Stopped batches, unsupported commands/layouts,
malformed packets and failed DLMS reads do not produce a fabricated successful reply.

## Supported layouts

- New 12-byte headers with exactly one response magic mapping.
- Legacy 10-byte headers with HES template ID above 26 and node ID fitting 24 bits.
- Earlier vendor-specific legacy layouts are explicitly unsupported.

The payload follows `MQTTSendCustomCommandClient.ParseProfileData` followed by its GetRTC
result field. HES `NonDLMSDataParser.GetDateTime` subtracts 330 minutes and GetRTC adds
330 minutes to the JSON result. The encoder therefore preserves the DLMS clock's wall time
as a uint32 epoch, independent of the simulator host timezone.

Reference source in the sibling repositories:

- `vayu-common/CrystalHES.Common/Helpers/CustomPullCommandPayload.cs`: request selector.
- `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCustomCommandClient.cs`: GetRTC result and prefix.
- `vayu-common/CrystalHES.Common/Helpers/NonDLMSDataParser.cs`: timestamp and nibble decoding.

## Configuration and acceptance

Load the approved CSV exports using `CustomPull:DataModelDirectory` (or environment variable
`CustomPull__DataModelDirectory`). The default directory is `KimbalSpecifics/DataModel` relative
to the application content root. The CSV export directory is not automatically deployed.

A running Wirepas batch must have a matching `HesTemplateId`, an enabled broker/environment,
and the correct meter XML containing the clock. The HES meter/node and template selection must
match. Configure a selected test batch; do not convert an existing MQTT4G fleet just for a test.

EQA node 210005 (MY00210005) was verified in SizeChangeEqa.dbo.NamePlate as HES template 93.
The EQA configuration loads CSVs from persistent `../data/custom-pull` and explicitly selects
`CustomPull:ResponseMagicNumbers:93 = 1050946`. This value is registered for template 93 in the
export; the resolver rejects overrides not present in the model. Other ambiguous templates
remain unsupported until an explicit registered value is selected.

The captured 28-byte new-header GetRTC request (frame 5415, node 210005, CRC B294) is covered by
an integration test through decoding, the actual clock read, and the Wirepas response envelope.

Tests cover a HES-format request through ingress, a real DLMS clock read, response framing and
Wirepas protobuf encoding; full-width frame correlation; HES timestamp parsing; stopped-batch
rejection; and preservation of an existing association and meter values. A live HES acceptance
test is still needed for the chosen environment/template. Other custom commands remain decoding-only.
