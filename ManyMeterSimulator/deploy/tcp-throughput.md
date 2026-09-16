# TCP push throughput tests

Start and bind TCP batches, then open **Testing → TCP stress**. The default is 256
concurrent meter connections; the supported range is 1–1024. Select profiles, an optional
per-batch meter limit, and optional waves and pauses. Wave size 0 sends continuously.
Ordinary scheduled push concurrency and pacing defaults remain unchanged.

## Running a test

- **Send live** generates fresh DLMS payloads and sends the selected fleet once.
- **Continuous TCP stress loop** repeats the fleet with fresh payloads each pass. Duration
  0 runs until Stop. Positive durations are in minutes, up to seven days. Optional pauses
  occur after a complete pass; passes do not overlap.
- **Prepare** builds payloads in memory without opening TCP connections. **Fire prepared
  burst** sends those bytes once, without wave pauses. Prepared data expires five minutes
  after generation starts and requires `Push:UseCiphering=false`. Use live mode for ciphering.
- **Stop / Discard** cancels active work and releases prepared data. Changing a selected
  batch or its TCP destination invalidates the run.

Custom plans also support a saved **TCP Stress Loop** job, with the same concurrency,
profile, subset, wave and cycle-pause settings. Reports retain completed passes and
cumulative meter/payload totals, including completed work in an interrupted pass.
Repeated sends count repeatedly. A pass with no successful writes stops the loop.
Closing the browser does not stop a server-side loop; application restarts do.

Payload and meter counts also feed the dashboard. Successful writes mean the local
socket accepted the bytes; they do not prove HES decoding or database persistence.
Check receiver-side throughput and failures when measuring an actual HES environment.

## Transport and resource behavior

Each meter opens a connection bound to its own assigned source IP and sends all its
selected payloads over that connection. Connections are not shared between meters:
the HES uses the source IP as TCP meter identity. Existing source-IP requirements and
connect/write deadlines apply. Cancellation retains completed payload counts.

The normal TCP sender and stress workflow use bounded asynchronous workers. Normal
push no longer creates a waiting task for every meter in a wave or an extra `Task.Run`
for every payload build. The stress workflow enumerates batches lazily, rotating between
selected batches. It does not materialize a session for the entire fleet before sending.

Prepared memory is an estimate covering retained payloads and dataset objects. Sessions,
template caches and transient encoding allocations are additional. Reduce the selected
meter count if preparation exceeds the budget. Preparation failure sends no payloads.

## Local validation

Tests cover bounded workers, single-use prepared bursts, ciphering and memory rejection,
configuration invalidation, loop cancellation and totals, source-bound IPv6 TCP delivery,
ordered payload bytes, and saved-plan reload/run/stop reporting. An integration test
generates a real template payload and receives it on a local TCP listener.

A local IPv6 loopback transport benchmark used 1,000 fresh connections per trial, a
256-byte payload per meter, and three alternating trials at each concurrency. The receiver
verified all 1,000 connections and 256,000 bytes in every trial. Mean throughput was
approximately 456 connections/second at 64 workers and 585 at 256 workers, about 28%
higher. This measures local transport only, excluding DLMS generation, remote latency
and HES processing; it is not a production throughput claim.

A separate 10,000-item scheduling probe measured roughly 18–21% fewer allocated bytes
with bounded workers than the prior queued-task implementation. Timing varied, so this
probe establishes an allocation improvement, not a scheduling speedup.

This change has been validated locally. Server deployment and receiver-side capacity
measurement are separate steps.
