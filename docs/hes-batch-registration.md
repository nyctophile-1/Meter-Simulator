# HES batch registration

In **Batch Setup → HES batch provisioning**, an administrator selects a saved PostgreSQL
connection and a stopped batch, previews the target and exact node range, edits the registration
values, then reviews a frozen summary in a final **Confirm and submit** dialog. Returning to
the editor performs no writes. A batch with a HES template ID uses that ID; otherwise the operator
must supply it. `NamePlate.MeterTemplateId` references `MeterTemplate.Id`.

The implementation writes only `kimbaldb_dbo.nameplate`, `metersecurity`, and `latestrouting`.
It does not reset historical readings, events, commands, or logs. It creates no HES schema
objects. Nameplate identity follows `MeterNodeIds` and `MeterIdentity`; category, type,
manufacturer, firmware, rating and capture period come from the batch's existing DLMS
model, with registration defaults and edits described below. This feature does not implement the separately planned immutable HES model compiler
or change payload generation. The preview records the current model file's SHA-256.

Security uses the simulator's current fixed demo profile. Global/authentication keys match;
the required master-key and firmware-secret columns use the same demo global/HLS values.
This does not add support for master-key rotation or firmware associations. Secrets and
connection strings are excluded from previews, receipts and diagnostic messages.

Direct TCP routes use `direct_tcp`; direct MQTT uses `direct_4g`. Wirepas and KMesh assign
gateway `gate_{batchId}_{n}`, where `n = floor((meterIndex - batchStartIndex) / 500) + 1`.
Each gateway handles at most 500 meters; its meters alternate across four sinks using the
batch-relative ordinal modulo 4. Wirepas stores `sink0`–`sink3` (source endpoint 3);
KMesh stores the equivalent numeric `0`–`3` (source endpoint -1). Batch and stress push
envelopes use this same allocation so received traffic preserves the planned routes.
Nameplates retain their deterministic reserved IPv6 address and configured listener port.
Routes start with `iscommunicating=false`. Required route timestamps record provisioning time,
not measured communication. HES caches may need their normal refresh before seeing new rows.
Database provisioning is not evidence of HES parsing or persistence.

## Editable registration values

- Category: D1, D2 or D3; meter type, current rating and manufacture year are also editable.
- Manufacturer defaults to `Kimbal`; firmware defaults to `MY01.1`. Both are editable.
- CT and PT ratios use positive model values when present, otherwise 1; the operator can
  set either to a positive integer.
- Block capture period is stored in **minutes**, restricted to 15, 30 or 60. Supported model
  values in seconds are converted; other or absent model values default to 15 minutes.
- Device ID is `{nodeId}MAYA`. `installedon` and `originalinstalledon` are both the same UTC
  submission timestamp, written as PostgreSQL UTC wall-clock timestamps.
- Communication module follows the batch NIC: `TCP`, `RF` (Wirepas), `KMesh`, or `MQTT4G`
  (including IMG). Identity, module, routes and security are generated and read-only.

Edits affect HES registration metadata. Select the matching batch meter model for D2/D3
payload generation; changing category here does not convert the underlying model. Server-side
validation and a separate source-model fingerprint preserve edited values while still rejecting
changes to the batch, model or database after preview.

## Replacement rules

- Registration created here carries a deterministic MAYA UUID in `nameplate.guid`.
  The UUID, exact node and serial mapping jointly establish ownership.
- A legacy nameplate can be adopted only with a matching generated node, serial and
  old `CRY` device identity or new `{nodeId}MAYA` identity, plus explicit operator acknowledgment of MAYA ownership.
  Prefix/range alone cannot authorize deletion.
- Conflicting node/serial mappings, duplicate nameplates, out-of-range serial collisions,
  or orphan security/routing block the entire operation. Duplicate security/routing for
  an owned nameplate are replaced with one row each.
- A preview expires after five minutes and can be used once. Row IDs and PostgreSQL row
  versions are fingerprinted without fetching security material. Replacement rechecks the
  target, ownership and row versions after acquiring database locks.
- A selected batch must be stopped/not started, have no active connections, and have no
  open push/stress runs (including prepared runs). A registry lease prevents start,
  delete, rebind, fleet reset/import, traffic changes and new push runs until completion.
- Replacement uses one transaction with bounded 1,000-meter binary COPY chunks. It briefly
  takes `SHARE ROW EXCLUSIVE` locks on all three registration tables because HES has no
  unique constraint on node IDs. These locks also block unrelated HES writes to those
  tables: use a test maintenance window. Lock acquisition times out after five seconds;
  statements have 60-second timeouts and the overall request is bounded to 15 minutes.
  There are no partial commits or automatic write retries.
- The target must be writable and primary. Targets with registration foreign keys or
  user triggers are rejected pending a reviewed replacement strategy. No cascade is used.
- New identity IDs are generated by PostgreSQL; database IDs are not preserved. Verify
  downstream application/cache behavior for the target HES before load testing.
- Cancellation or errors before commit roll back the transaction. If the commit acknowledgment
  is lost, the outcome is reported as unknown: verify the desired registration before retrying.
  Never interpret an unknown outcome as a successful rollback.

Nonsecret operation receipts are stored in `Persistence:Folder/hes-registration-receipts`.
A `Started` receipt left by a process interruption requires target verification before retry.
The receipt includes target, range, counts, template/model/config fingerprints and timestamp.

## Isolated PostgreSQL tests

Create a disposable PostgreSQL cluster listening only on `127.0.0.1`, with user `maya_test`
and database `maya_registration_test`. Set `MAYA_REGISTRATION_LOCAL_TEST_CONNECTION` to
that local connection string and run the application test project. The integration tests
reject any other host, database or user. They drop/recreate **only this disposable fixture's**
`kimbaldb_dbo` schema. Never point them at shared HES. Without the variable these tests are
reported skipped; registry and authorization tests still run.

Tests cover chunk boundaries, repeat replacement, outside-range/history preservation,
legacy adoption, ownership collisions, orphan refusal, rollback after deletion, competing
replacements, cancellation, read-only targets and missing template IDs.
