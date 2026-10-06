# Dashboard command metrics

Exchanges/sec counts requests handled by the brain, including associations and response-block requests. RF endpoint-13 custom requests now participate in the same per-NIC and fleet counters. A custom request producing many packets contributes one exchange.

Successful commands/sec counts successful meter operations completed by MAYA's brain. DLMS GET, SET and ACTION responses count once when the final result is generated; association/HLS exchanges, intermediate blocks and error results do not count. A list request counts as one operation when every result succeeds. Plain and ciphered responses are observed before encryption, with completion deferred through block transfer. RF custom reads count once after all response packets have been generated successfully.

This is not an HES command-status metric: one HES workflow can perform several meter operations. It does not assert broker receipt, network delivery, validation or persistence in HES. A later send failure does not undo completed brain work.

Command and exchange rates use counter differences over the trailing 60-second history (available elapsed time during startup). Lifetime totals do not become a startup burst. Push rates retain their latest-sample interval. Counters reset on process restart.
