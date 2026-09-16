# Daily profile push

Select **Daily (DLMS)** (`0.6.25.9.0.255`) for TCP, MQTT 4G, IMG, Wirepas or Kmesh. DLMS encoding lives in `DLMSServerSession` and has no NIC dependency. Selecting it on a Wirepas batch with HES template 93 now reaches the DLMS encoder instead of being rejected by custom-push selection.

The fallback uses the latest complete timestamped row from `1.0.99.2.0.255`, resolving capture columns by OBIS and value attribute. It emits a flat DataNotification: meter device ID, daily push self LN, captured RTC, import kWh, import kVAh, export kWh, export kVAh. Captured numeric types and values are preserved; no second scaling is applied. It supports plaintext and ciphering and does not modify shared profile rows. A non-empty daily PushSetup supplied by a template takes precedence. Additional vendor-specific daily fields require that explicit template definition.

Profile discovery and DLMS **All** include the fallback when its required captures and a usable row exist. Empty or incomplete daily profiles do not advertise the fallback. Each ciphered send encodes fresh bytes with the existing invocation-counter handling; prepared ciphered sends remain disabled.

The fallback copies the captured `GXDateTime` and includes its known offset in the outgoing datetime. The loader normalizes concrete captured timestamps to UTC, so these packets explicitly carry deviation zero. A stale XML `Skip.Deviation` flag previously emitted `0x8000` despite that normalization. The copy preserves the captured value, status and other skip flags, and leaves the shared row untouched. Explicit template PushSetup definitions keep their existing behavior.

## Transport

| NIC | MQTT topic / transport | Envelope |
| --- | --- | --- |
| TCP | Configured TCP push destination | DLMS wrapper bytes |
| MQTT 4G / IMG | `Normal_Push/{nodeId}` | DLMS wrapper bytes |
| Wirepas DLMS | `gw-event/received_data/{gateway}/{sink}/{nodeId}/1/1` | Wirepas protobuf, legacy 5-byte fragment header, DLMS wrapper |
| Kmesh DLMS | `gateway/push/meter/{gateway}/{nodeId}` | `PushDataMessage`, `KapDlmsWraperPushData`, meter serial, fragment 1/1, wrapper payload |
| Wirepas custom | `gw-event/received_data/{gateway}/{sink}/{nodeId}/10/10` by default | Wirepas protobuf, registered 12-byte transport header, custom body |

Wirepas uses the existing `CustomPush:WirepasGatewayId` and `WirepasSinkId` settings for both envelope formats. Its DLMS endpoint is fixed at 1. Kmesh uses `Push:KmeshGatewayId` (default `sim-gw`) and `Push:KmeshSinkId` (default 1). The local HES receivers confirm these subscriptions and protobuf formats. HES must map the meter to a compatible DLMS payload schema and, for Wirepas DLMS, a 5-byte push header; selecting DLMS in MAYA does not change HES template metadata. Template 93's custom metadata cannot decode a DLMS notification merely because the NIC is the same.

## Metadata-driven custom Daily

Select **Daily (custom)** (`custom:daily`). The old saved selector `custom:93:daily` is accepted as an alias. `CustomPushEncoder` resolves the template's Daily profile ID, category-specific field order, types, scalars and registered magic from HES metadata. There is no template-ID branch. The verified framing is a 12-byte transport header followed by an 11-byte profile header. RTC includes a configurable offset (default 330 minutes) matching the custom HES date reader.

Custom Daily uses the shared custom-profile value generator in engineering units with send-time RTC, so it does not require a DLMS session or XML profile. Custom **All** selects the supported Instant, Block, Daily, Billing, configured event families, ESW and RTC from metadata. ESW uses the meter's DLMS session status word. Scheduled Instant/Block/Daily traffic uses the custom encoder when the Wirepas batch's HES metadata declares a custom payload. Explicit DLMS selection always retains DLMS encoding, including on a custom-configured Wirepas batch.

Configuration must supply HES CSV exports through `CustomPull:DataModelDirectory` (the shared loader), `CustomPush:MeterCategories` keyed by HES template ID, and `CustomPush:ResponseMagicNumbers` when mappings are ambiguous. Event profiles additionally require `CustomPush:EventsWithPowerProfile` and `CustomPush:EventIds`, a dictionary of template IDs to dictionaries of custom event keys and allowed IDs. Missing metadata or unverified legacy headers are rejected. See [the bounded probe configuration](../tools/PushProbe/README.md). These configuration prerequisites have not been installed on DRISHTI or EQA in this verification run.

## Validation

Tests decode plaintext and encrypted Daily on all four MQTT NIC variants, including explicit DLMS selection on template-93 Wirepas. They check captured RTC/energy values, daily channel identity, profile discovery, incomplete-profile rejection, fresh encrypted bytes, prepared plaintext mode, custom scalar/clock/header decoding, and scheduled TCP loopback delivery. These are source and local transport checks; no live broker-to-HES ingestion or deployment is claimed for this change.

The original Daily implementation passed 33 focused checks and a 511-test Release suite. The subsequent metadata encoder and live D1 packet/value checks are recorded in [the active verification report](scenario-verification/README.md). Existing compiler/analyzer warnings remain. Source tests, live diagnostic ingestion and deployed MAYA versions are tracked separately.

## Deployed verification

Release `daily-8ca673e0` was built from the verified deployed batch-traffic snapshot plus these Daily changes, with **527 Release tests passing**, and deployed to DRISHTI and EQA on 2026-09-13. [Deployment and ingestion evidence](../deploy/daily-20260913-verification.md) records custom Daily/ESW database success and the remaining direct-DLMS routing, Daily energy validation and RTC conversion issues. Diagnostic replay confirms parsing separately from the original MQTT route; deployment health does not establish end-to-end ingestion success.
