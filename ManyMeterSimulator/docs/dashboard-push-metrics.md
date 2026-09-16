# Dashboard push metrics

The dashboard shows separate MQTT and TCP successful payload sends per second. NIC statistics sits beside Live pull activity, includes push rate, and retains exchange rates. Batches appears beneath that row. The top cards omit live meters, running batches and meters pushed; active connections is labelled Active DLMS sessions.

Rates use the difference between the latest two background samples divided by their actual elapsed time (normally two seconds). They start at zero until two samples exist, return to zero when sending stops, and do not spike when a new browser opens against lifetime counters.

MQTT accounting belongs to `MqttPushRun`, which all regular, prepared, stress-loop and saved-plan pushes share. TCP stress accounting belongs to `TcpPushRun`; regular TCP pushes retain their coordinator accounting. Successful sends, failures, skips and meter latency are recorded as meters finish, rather than waiting for an entire loop or plan. The regular MQTT caller no longer duplicates these counters. Prepared messages retain the meter's NIC identity, including IMG meters that share a 4G broker binding.

An interrupted multi-payload send retains completed payloads and counts remaining delivery as unconfirmed. Canceled work that never acquired a sender is not a successful push. Failed sends do not contribute to pushes per second. Preparing data alone does not count as sending.

MQTT counts successful publish operations, including transport fragments; TCP counts completed payload writes. MQTT QoS 0 and TCP writes do not prove broker/HES ingestion. Meter totals count repeated attempts, not distinct meter identities, and reset when the process restarts.

Validation: the isolated deployment source passed the 462-test full suite and 53 focused tests, including prepared/live accounting, concurrent loops, NIC attribution, rejected sends, partial cancellation and elapsed-time rates. Visual QA used a locally published build. No production fleet stress test is used as a deployment health check.

The deployment source is an isolated worktree based on the servers' `f133aa1` Profile-Simulation merge, with `c1fe203`, existing local TCP stress work, and this change applied. This preserves functionality absent from the user's current branch. The exact source file manifest, build hashes, test logs, backups and verification receipts are in `C:\Users\ayush\AppData\Local\Temp\maya-ui-20260913`. No commit or push was made.

EQA uses a complete compressed data backup, verified against the stopped data tree before replacement. Its rollback script verifies that archive, preserves and verifies a compressed copy of displaced data, then restores the original data. DRISHTI uses the usual full directory backup. Existing configuration, templates, keys and logical batch/network state must match after restart; only broker verification timestamps and password ciphertext may change during reconnection.
