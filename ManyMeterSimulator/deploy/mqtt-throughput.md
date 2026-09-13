# MQTT push throughput tests

The app remains a single .NET process. EMQX Dashboard supplies incoming message rates, drops,
queue depth and broker resource usage. No EMQX API polling, distributed workers or new chart
pipeline is added.

## Testing page

Start and bind the desired MQTT batches on Setup/Network, then open **Testing → MQTT stress**.
Select batches, profile, QoS, publishers per broker/transport, concurrent meters and an optional
per-batch meter limit. Use the same workload settings when comparing runs.

Publisher pools support 1–256 connections per broker/transport. The stress dropdown includes
128 and 256; saved MQTT Stress Loop tasks accept any count in that range. Increasing publishers
raises the form's concurrent-meter value when needed. Defaults remain 8 publishers and 64
concurrent meters; the concurrency ceiling remains 1024. These connections only publish and
do not add pull subscriptions.

**Continuous MQTT stress loop** is available in the Run mode dropdown. Set duration to `0`
to run until Stop, or set a minute duration (up to seven days). Each cycle generates fresh
payloads for the selected fleet and reuses the same publisher pools. Set wave size and pause
after each pass to `0` for uninterrupted maximum-speed sending. Pauses apply after completing
the preceding wave/pass; cycles never overlap. Stop and duration deadlines interrupt active
publishes and pauses. A cycle with zero successful publishes stops the loop with an error.

For a saved test, edit your custom **Push Burst Loop** plan and change its job type to
**MQTT Stress Loop**, or add a new job of that type to any custom plan. Select an environment,
MQTT batches, profile, QoS, publishers, concurrency and optional subset/pacing settings.
Custom plans can now change their job list/type and timing; supplied base plans keep their
existing rules. Start the batches before running the plan. Duration `0` means until stopped;
scheduled offsets still apply. Closing a browser tab does not stop a server-side loop.
Loops are not automatically resumed after an application restart.

**All supported profiles** sends every non-empty PushSetup configured in each selected DLMS
template, as separate payloads. The dropdown discovers all such setups, including uploaded
templates, rather than listing only Instantaneous and Block Load. It does not create missing
daily, billing or event layouts. Template 93 custom push supports only the verified daily
layout. Selecting a specific profile requires it to exist on every selected batch; unsupported
selections fail before publishers open instead of silently sending a different profile.

Stopped plans retain cumulative client publish/meter-send totals and full-pass count, including
completed work in the interrupted pass. These counts include repeats, not unique meters.
The MQTT task result is separate from the standard best-minute benchmark scores. It retains
constant-size totals, not per-cycle/per-message histories. EMQX remains the source for TPS.

- **Send live** opens publish-only connections, then generates and sends one push per selected
  meter with bounded concurrency. Wave size `0` means continuous sending until that finite fleet
  is exhausted. A positive wave size and pause reproduce paced sends.
- **Prepare** builds final payload bytes and topics in RAM, and connects the publishers. It sends
  no PUBLISH packets. Wait for Ready, arrange the EMQX dashboard, then choose **Fire prepared burst**.
  Fire sends that dataset once, with no inter-wave pauses. Prepare a fresh dataset for another burst.
- **Stop / Discard** cancels work and frees the prepared dataset and publishing connections.
  The run is shared across Testing-page sessions and survives tab navigation. App shutdown stops it.

Prepared data must be fired within five minutes of generation starting. Its timestamps describe preparation time.
Changing a selected batch's status/binding/template or its broker configuration invalidates the run.
Disconnected publishers require a new run; ambiguous publishes are not replayed automatically.
Prepared mode requires `Push:UseCiphering=false` because an intervening pull can advance DLMS
invocation counters. Live ciphered push retains the existing session serialization behavior.
The verified template-93 custom path always produces its daily profile and avoids DLMS-session
materialization. Unsupported push codecs/layouts fail before publishing.

The memory setting bounds an estimate of retained payloads, topics and dataset objects. DLMS
sessions/template caches and the bounded workers' transient encoding allocations are additional.
Reduce the meter limit if preparation exceeds the budget. Generation failure sends no payloads.
Completed client publish counts are not a broker-receipt or HES-persistence guarantee: QoS 0 has
no acknowledgement; a stop/timeout can leave in-flight delivery unconfirmed. QoS 1/2 describe
the MQTT hop, not database persistence. EMQX and HES remain the source for those measurements.

## Ordinary push defaults

Existing on-demand and test-plan MQTT pushes also use publish-only pools, without changing
topics or payload encoding. Each batch push opens a pool and reuses it until that push completes.
Pull subscriptions and replies remain on their existing listener connection.

`ManyMeterSimulator/appsettings.json`, `Push` section (environment variables can override):

| Setting | Default | Meaning |
|---|---:|---|
| PublisherCount | 8 | MQTT publishers per batch push / broker binding |
| PublishQos | 2 | Compare 0, 1 and 2 as separate workloads |
| PublishTimeoutSeconds | 10 | Bounds an individual publish wait |
| MaxConcurrency | 64 | Concurrent meters |
| ChunkSize | 10000 | Meters per live wave |
| ChunkIntervalSeconds | 5 | Pause between ordinary live waves |

The dedicated stress controls override pacing, QoS, publisher count and concurrency for that run.
They do not rewrite the normal defaults. Stress uses one pool per selected broker/transport,
shared across its batches, and round-robin meter selection to supply all selected bindings.
Each meter's payloads/fragments remain ordered on a single leased publishing connection.

## Independent emqtt-bench baseline

Install an official Linux release of [emqtt-bench](https://github.com/emqx/emqtt-bench/releases)
on a load-generator host, or build it following the [official instructions](https://github.com/emqx/emqtt-bench).
Do not run the generator on the broker host when comparing infrastructure limits. The wrappers
below require an existing binary; they do not install packages or change broker configuration.

Both wrappers default to a dry run. Credentials can be supplied through `EMQTT_BENCH_USERNAME`
and `EMQTT_BENCH_PASSWORD`; otherwise a username triggers a password prompt when actually running.
Run the examples from the `ManyMeterSimulator` folder containing `ManyMeterSimulator.Tests`.
Do not commit credentials. The native tool receives passwords as process arguments, so use an
appropriate test credential on a trusted generator host. The wrappers do not print passwords.

Linux / bash, with `emqtt_bench` on PATH (or set `BENCH_BIN`):

```bash
BROKER_HOST=your-emqx-host CLIENTS=8 QOS=2 PAYLOAD_BYTES=256 bash deploy/emqtt-bench.sh
BROKER_HOST=your-emqx-host CLIENTS=8 QOS=2 PAYLOAD_BYTES=256 bash deploy/emqtt-bench.sh --run
# Optional subscriber in a second terminal; one subscriber receives the entire test prefix.
BROKER_HOST=your-emqx-host MODE=sub CLIENTS=1 DURATION_SECONDS=120 bash deploy/emqtt-bench.sh --run
```

PowerShell 7 on a host with a native emqtt_bench executable:

```powershell
./deploy/emqtt-bench.ps1 -BrokerHost your-emqx-host -Clients 8 -Qos 2 -PayloadBytes 256
./deploy/emqtt-bench.ps1 -BrokerHost your-emqx-host -Clients 8 -Qos 2 -PayloadBytes 256 -Run
./deploy/emqtt-bench.ps1 -BrokerHost your-emqx-host -Mode sub -Clients 1 -DurationSeconds 120 -Run
```

The default run is 60 seconds, QoS 2, eight clients, MQTT 5, one in-flight publish per client,
and interval `0` (maximum-speed request). `-Inflight` / `INFLIGHT` can increase the benchmark's
acknowledgement window; first use `1` to match the simulator's per-connection model. Use
`-IntervalMs` / `INTERVAL_MS` for pacing. Start subscribers before the publisher if comparing
delivery. Run publishers with 1/4/8/16/32 clients and QoS 0/1/2; record each scenario separately.
Set TLS and its port explicitly (`-Tls -Port 8883` or `TLS=true PORT=8883`); optional CA file is
`-CaCertFile` / `CA_CERT_FILE`. Match MQTT version, payload size, client count, TLS, topic count,
subscriptions and fan-out. These are synthetic `maya-bench` payloads, not HES meter data.

Use the EMQX incoming-message chart, or the delta of `messages.received` over the measurement
window, while excluding unrelated traffic and connection warm-up. Also inspect dropped/rejected
messages and queue growth. Total MQTT packet rate includes acknowledgement traffic and is a
different measurement. A no-subscriber test measures ingress only; `no_subscribers` drops in that
scenario do not mean the broker failed to receive messages. Subscriber fan-out and HES processing
must be compared separately. See [EMQX metric definitions](https://docs.emqx.com/en/emqx/latest/observability/metrics-and-stats.html).
