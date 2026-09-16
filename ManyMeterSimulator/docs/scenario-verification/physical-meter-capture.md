# Physical meter XML capture: D1 wave

The user supplied three IPv6/4059 endpoints, shared test credentials, and confirmed that the final column is the HES parsing template ID. No credentials are stored in this document or the capture configurations.

| Endpoint | HES template | Observed result |
| --- | --- | --- |
| `2405:203:5b0c:8dd1::10` | 31, HP Apraava TCP | Secure association successful; SA1038079, type 6/category D1; full bounded capture completed. |
| `2401:4900:9847:b38e::2` | 31, HP Apraava TCP | TCP connectivity successful. No association/category capture attempted in this D1 run. |
| `2405:203:5b0c:8061::10` | 21, HP SecureTCP | Public association successful, serial SZ0000001, 18 objects. Secure attempt ended with connection closure; category and secure-key contract remain unverified. |

The current Windows route for the endpoints selects an existing `2000::/4` loopback route. Binding the capture socket to the verified Wi-Fi interface 7 reached all three meters. No routing table, network configuration, HES service or meter settings were changed. The checked HES host 10.254.3.185 has no IPv6 route to these endpoints.

The D1 secure capture used the existing HES user-association contract. It retrieved 155 objects, scaler/unit values, ordered capture definitions, readable attributes and up to 13 entries per profile. All requested attribute reads succeeded. The capture completed in approximately four minutes, with 396 exchanges and 33,606 received bytes. HLS authentication and the normal invocation-counter sequence are part of association establishment; no data SET, clock adjustment, profile reset/capture action or firmware operation was issued.

Four event families had compatible data for the master: voltage 13, power 13, transaction 1 and other 12. Three event families were empty on the meter. The physical association exposes Instant and ESW push setups; the existing master also retains its Block setup and runtime Daily fallback. No Billing/event push setup was fabricated.

The raw capture and report are retained under `C:\Users\ayush\Documents\MAYA-release-receipts\d1-wave-20260913-1804\captures`. Raw XML hash: `a27f97501b7ab010879b5f5b24bbc36fe48aaf9484ae9e8c46208b3eb2a3908b`. The [composition report](d1-master-composition.json) links this source to the final master. Capture values stay separate from the simulator's runtime clock/profile recency adjustment.

The reusable [MeterCapture tool](../../tools/MeterCapture/README.md) writes an immutable XML and a report per run. The [composer](../../tools/TemplateComposer/README.md) checks imported profile compatibility while retaining the base model. D2/D3 generation and any unresolved vendor security variants belong to later waves.

## Profile wire-value audit, September 14 India time

A second Daily capture retained raw decoded cells before Gurux applied scalers. Import energy was float32 `847.8488` on the wire and double `847848.8159179688` in the ordinary client export. The capture tool now saves both representations separately, with hashes. Three Daily rows, one Instant row and the four populated event buffers have been imported from the profile-wire exports into the local master after the same compatibility checks. Their dates remain source dates until the simulator applies its current-time policy.

The subsequent seven-profile capture completed with 155 association objects, 204 exchanges and 23,819 received bytes. Instant, Block and the four event definitions match the master. Billing's association omits the captured object `1.0.84.6.0.255`, so that donor fails validation and was not substituted. The existing 13 Billing rows and 100 Block rows remain intact. See the [compatibility audit](d1-physical-profile-compatibility.json). Captures are retained under `C:\Users\ayush\Documents\MAYA-release-receipts\ber-d2d245b5`.

Mixed float32 event and double Billing rows exposed a loader defect: the last profile could narrow a shared captured object's type and round Billing values. The loader now accumulates the widest type across all profiles before setting it. The existing Billing roundtrip regression failed in three cultures before the fix and all nine focused master/capture tests pass afterwards. Neither the loader fix nor this final local XML revision is deployed yet.
