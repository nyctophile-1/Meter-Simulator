# Standard DLMS meter FOTA

Open **Meter FOTA** (`/fota`) and select a batch. Administrators can enable simulation, set a target version and block size, and override settings for an individual meter index. Other signed-in users can inspect progress. Blank override index means batch defaults; **Use batch defaults** removes a meter override. Find accepts an index or `MY` serial; results are paged in groups of 50.

FOTA is disabled until explicitly enabled. Templates must contain image transfer `0.0.44.0.0.255` and firmware version `1.0.0.2.0.255`. Templates are not modified. The simulator supports the existing HLS association, including ciphered requests, through the common DLMS session used by transparent TCP/MQTT transports. Proprietary RF FOTA is not implemented.

## Lifecycle

1. Read enabled (attribute 5) and block size (2).
2. Initiate (method 1) with an opaque image identifier and image size. This resets the pending transfer, retaining the active firmware version. Effective settings are frozen for this transfer.
3. Transfer zero-based blocks (method 2). Blocks may arrive out of order; identical retries succeed without adding progress, while conflicting duplicates fail. The final block must have the exact remaining length. Read the received bitmap (3) or first missing block (4) to resume without reinitiating.
4. Verify (method 3). Every block must be present. Read status (6) and activation information (7).
5. Activate (method 4). Successful verification is required. The configured target becomes this meter's reported firmware version; communications continue normally. Retrying a successful activation is idempotent.

The simulator stores SHA-256 block fingerprints, not firmware bytes. Validated image size, block size and index determine each block's required length. Verification establishes completeness and structural validity only: no vendor signature, whole-image checksum, executable image or version parsing is claimed. Activation information carries the original identifier and declared size, with an empty signature.

Scheduled activation (`0.0.15.0.2.255`) and image-transfer attribute writes are rejected. Settings are changed through the authenticated UI. Unauthenticated firmware methods are rejected. No reboot or transport outage is simulated.

## Repeatable failures and recovery

Configure a zero-based block number and rejection count to exercise retry handling. The counter survives restart. Verification and activation failure switches persist for the transfer; change settings and initiate a new transfer to try a different scenario. Transport losses/delays remain controlled by existing BadComm settings.

**Reset pending transfer** requires confirmation and clears only the pending image, fingerprints and failure counters. It preserves the activated firmware version. A new batch reusing the same addresses cannot inherit a previous batch's FOTA state.

## Durability and limits

State lives in `Persistence:Folder/fota`, outside the application overlay. Batch identity, creation time, template hash and meter index determine ownership. Settings saves and state acknowledgements require successful persistence. I/O failure returns temporary failure; retry/resume can reconcile an uncertain response.

Each participating meter has a checksummed append-only journal. Writes are flushed before acknowledgement. Every 256 state changes, an atomically replaced snapshot precedes journal truncation. Sequence numbers prevent duplicate replay after a crash; an incomplete trailing record is discarded. A complete corrupt record fails closed. Preserve the original data for diagnosis rather than deleting it to bypass an error. Settings corruption fails service construction rather than silently enabling or changing simulations.

The `Fota` application configuration section accepts:

| Setting | Default | Accepted range |
| --- | ---: | --- |
| MaxImageBytes | 16777216 | 1–268435456 |
| MaxBlocks | 131072 | 1–1048576 |
| CachedMeters | 128 | 1–4096 |
| CachedBlocks | 262144 | MaxBlocks–4194304 |

UI block size is 32–4096 bytes; rejection count is 0–1000. Cache eviction retains durable state. Restoring a transfer larger than newly lowered limits fails closed until the previous limits are restored. Disk usage grows with participating meters; no firmware blobs or per-block payloads are retained. The store serializes state operations and durable writes: this feature makes no high-throughput firmware-fleet claim.

## Validation boundaries

Tests exercise encoded plain/ciphered HLS exchanges, activation-information decoding, version readback, persistent resume, failure injection, malformed blocks, meter isolation, batch reuse, bounded cache, storage failure and interrupted journal recovery. Local protocol and deployed simulator results must be reported separately from an actual HES command's completion in its database.

`tools/FotaProbe` is a bounded release-verification client using MAYA's demo HLS keys. Its `begin HOST PORT VERSION` mode sends two of three blocks out of order; `complete` reconnects, requires the persisted missing-block position, sends the remaining block, verifies and activates; `verify` checks the active version after another restart. Run it only against explicitly designated simulator meters.

For controlled deployment verification, `prepare DATA_ROOT TEMPLATE_ROOT PROBE_NAME` creates a dedicated two-meter, unbound TCP batch and enables FOTA on its first meter only. Its target version is `PROBE_NAME`. `stop` with the same arguments leaves that batch stopped. Both provisioning modes require the MAYA service to be stopped, a full data backup, and the deployment lock held; they must never run concurrently with the live registry. Record the returned meter index and preserve all other batches.
