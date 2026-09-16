# Daily and ESW deployment and ingestion verification — 2026-09-13

Release `daily-8ca673e0` is deployed on DRISHTI and EQA. Full Release suite: **527 passed, 0 failed, 0 skipped**. The source is the hash-verified previously deployed batch-traffic snapshot plus Daily changes, preserving its profile simulation, TCP and UI features. It is not a clean Git commit. No commit or push was made.

## Deployment

Both application and core DLL hashes match the manifest. Both services are active with zero automatic restarts, HTTP 200, authenticated Testing UI, IPv6 port 4059 and the target-specific local route. DRISHTI restored 300,001 meters; EQA restored 500,000. Configuration, templates, persistent logical batch states and disabled environments were preserved. Network encryption/verification timestamp refreshes were checked separately from logical settings.

DRISHTI rollback: `/opt/maya-sim/backups/20260913T122748Z-daily-8ca673e0` (full app and data).

EQA rollback: `/opt/maya-sim/backups/20260913T122945Z-daily-8ca673e0` (previous app and service). Its full data archive is retained and hash-verified in this workstation's `Documents/MAYA-release-receipts/daily-8ca673e0` folder; see the manifest for exact path and SHA-256. EQA had only **393 MiB free** after deployment. No historical backups were deleted.

## Ingestion evidence

Tests were bounded single-meter, single-pass sends on existing enabled environments. Database evidence came from read-only transactions on KimbalHES replica 10.254.3.137. SQL did not insert or modify rows; the normal HES ingestion pipeline handled test packets.

| Path | Observed result |
| --- | --- |
| DRISHTI custom Daily | Persisted for MY00100001 at 12:31:55 UTC: import kWh 100101.000, import kVAh 100111.000, export kWh 0.001, export kVAh 0.101. These exactly match the custom payload after scalar -3. HES rounds the RTC to the minute. Raw ID 115adf41-d2fa-42dc-b336-e9d2c76f1baf. |
| DRISHTI custom ESW | Persisted row 3608341 at 12:33:00 UTC; exact 128-bit comparison against the raw payload passed. RTC matches send time. Raw ID 73208f1b-c6a7-4160-a175-e182601e4635. |
| DRISHTI DLMS Daily, ciphered | Broker received 117 bytes on Normal_Push/1000400001. No corresponding drop-prefixed packet or HES receipt. A single diagnostic replay onto the existing drop/Normal_Push/1000400001 subscription decrypted and parsed, then failed energy validation. Raw ID 420c0980-21b6-4c46-b90f-f39efcc750ef, 12:43:57 UTC. |
| EQA DLMS Daily, plaintext | Same routing gap. A single diagnostic replay parsed, then failed the same energy validation. Raw ID d5c2826d-b5cb-48bb-9e2f-71959636d6a4, 12:50:43 UTC. |
| EQA DLMS ESW, plaintext | Same routing gap. Diagnostic replay persisted row 3612042 at 12:50:52 UTC; exact comparison of all 128 bits passed. Raw ID 1977ae43-fc8d-4ca0-8b8d-cc02680dfe9f. RTC was 07:20:26 versus encoded 12:50:26: 330 minutes early. |

## Remaining integration issues

1. **Normal topic delivery:** both MAYA targets publish direct DLMS to `Normal_Push/{nodeId}`. The active HES service `vayu-core-push-rf-drop` subscribes to `drop/Normal_Push/#`. Temporary observers subscribed successfully to both exact test topics and received only the normal-topic packets. The broker forwarding rule or intended normal consumer needs inspection. No broker rules, HES configuration or HES services were changed. The EMQX dashboard/admin URL was requested but not supplied during this verification.
2. **Daily energy/template contract:** the latest complete captured row in `SA1231166HP_values.xml` contains 4684814.453125 and 4883597.16796875. The fallback faithfully preserves those numeric values. HES daily template 7 has scalar 0 and rejects the resulting import energies above 200000. Exact error: `Energy values are invalid - CumulativeEnergyKvahImport 4883597.167 CumulativeEnergyKwhImport 4684814.453`. The deployed stack reaches `GenericParser.ParseAndSaveDailyProfile` from `MQTTDataReceiverDirectDLMSClient.cs:104`. The matching source guard is `vayu-sql-database/CrystalHES.Database/Repositories/ProfileRepositories.Postgres.cs:626`. No scaling, clamping, template data or HES limit was altered merely to make the test pass.
3. **DLMS RTC contract:** HES `Functions.GetTimeOffsetInMinutesFromByteArray` unconditionally returns -330, ignoring encoded deviation. EQA ESW encoded UTC and therefore persisted 5.5 hours early. Source pointer: `vayu-common/CrystalHES.Common/Helpers/Functions.cs:405`. Custom RTC is already encoded to match this HES convention. Daily's preserved captured RTC is subject to the same HES conversion; its insertion failed before a persisted RTC could be verified.

DLMS encoding remains independent of NIC type. Source tests cover all four MQTT NIC variants and TCP; live tests used the compatible registered direct-DLMS and custom Wirepas mappings. EQA custom Wirepas/Kmesh environments remained disabled, so those paths were not activated for verification. Live Kmesh, Wirepas DLMS and TCP-to-HES ingestion were not proven. Diagnostic replay is parser/persistence evidence, not proof of the original normal-topic route.

See `manifest.json`, source manifest/archive, test log, bounded MQTT observation logs and database query outputs in the durable receipt folder for evidence. No background test loops or observers remain running.
