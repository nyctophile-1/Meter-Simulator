# Profile time alignment

Fresh offline packets from master `9328f37b2c6b0b9a2beceb22f1db326fbd19b3b07aea5b5ddf855cdb2b7fdb38` exposed a future-dated Block RTC. The loader previously shifted only past timestamps, leaving future snapshots unchanged. The running-session freshness check also treated every future timestamp as fresh.

The correction aligns the newest concrete profile timestamp to UTC now on load, with the same delta applied to all concrete timestamps in that profile. During push, future timestamps are corrected as well as buffers older than the existing freshness tolerance. Numeric values, row spacing, capture order, scalers and the XML model remain unchanged. Block push retains its existing nearest-half-hour rounding; this can put its transmitted timestamp up to 15 minutes ahead of generation time.

Six regression cases cover past/future Block and Daily loads, preserved numeric values and row spacing, and a running Block buffer drifting in either direction. Three future cases failed before the correction; all six pass afterward. The full Release suite passes 598 tests, with no failures or skips.

Four fresh unencrypted DLMS packets generated at 2026-09-13 19:55:38 UTC decode completely and have zero wire deviation. Instant, Daily and ESW carry 19:55:38 UTC; Block carries the rounded 20:00 UTC. Daily import energy fields are 847.8488159179688 and 880.4393310546875, matching the captured wire values. The local compiled Common datetime probe preserves all four packet RTCs exactly. These are offline encoding/decoding results, not HES delivery or persistence proof; the Common changes remain undeployed.

Release `time-d17d9f77` is deployed and preservation-verified on both targets. It replaces only the tested Core DLL and its matching symbols over `profiles-818f418a`. DRISHTI PID 21039 started at 19:58:46 UTC and EQA PID 5330 at 20:02:21 UTC; both have zero restarts. All saved batch states recovered, HTTP checks returned 200, and IPv6 listener/route checks passed. Configuration, templates and persistent files are preserved; network verification metadata changed while logical settings remained equal.

The [deployment manifest](../../deploy/time-20260914-manifest.json) records exact source and binary hashes and full backup locations. EQA's complete backup was downloaded and checked before replacement; its remaining root space is approximately 288 MiB. No previous backup was removed.

The master XML is unchanged. Full D1 HES verification still requires an active push consumer and isolation of the overlapping meter fleet; later D2/D3 waves remain deferred.
