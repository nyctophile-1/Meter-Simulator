# Per-batch automatic routing and pushes

Open **Batch Setup**, expand a batch, and use **Automatic routing and push**. Routing,
Instantaneous, Block Load and Daily each have their own Start/Stop button. These switches
are independent of the batch's Start/Stop control and of manually initiated Testing runs.
Stopping the batch pauses every automatic stream; restarting it resumes the saved switches.
Settings persist in `batches.json`, including exports/imports. Existing fleets keep routing
enabled; new automatic push streams default to stopped.

## Timing and distribution

Routing, Instantaneous and Block Load use half-hour windows aligned to :00 and :30. Daily
uses 00:00–00:30 in `BatchTraffic:TimeZoneId`, default `Asia/Kolkata` (India time), independent
of the server's operating-system timezone. Midnight is inclusive; 00:30 is exclusive.
Daily sends are canceled at the end of the window, including blocked network operations.

Each batch's contiguous meter range is divided evenly among 1,800 one-second slots. The
number of meters in any two slots differs by at most one. A healthy continuously enabled
stream sends each meter once per window. It does not dump the whole fleet at a timer tick.
Starting or recovering partway through a window uses the remaining slots; elapsed slots
are skipped, with no catch-up burst. If a receiver cannot sustain the requested rate,
elapsed slots are also skipped rather than queued indefinitely. Stop cancels pending work;
bytes already accepted by a socket or broker cannot be recalled.

The page shows the current state, completed meter sends, failures, elapsed slots skipped,
and the last connection/profile error. `BatchTraffic:MaxConcurrency` defaults to 32 per
batch/stream, bounded to 1–1024. Publisher pools live for the current window and are disposed
on completion, Stop or failure. Failures retry after 30 seconds in the current window,
without replaying already enumerated meters. Unsupported profiles remain visible as errors.

## Topics and data

Routing sends an empty payload to `FakeRouting/{nodeId}/{transport}/{gatewayId}/{sinkId}` using the enabled MQTT
broker in the batch's environment, including for TCP batches. Transport is 4 for TCP,
3 for either 4G MQTT variant, 2 for Wirepas and 1 for Kmesh. Stopped/disabled/unbound batches
cannot send. This scheduler replaces the previous automatic `MqttRoutingService` registration;
there is only one automatic routing scheduler. RF routes use stable groups of 1,000 meters and four node-derived sinks; direct transports use direct_4g/direct_tcp for both gateway and sink. See [the contract](../../fake-routing-gateway-sink.md).

Push data uses its existing NIC transport and encoding, including source-bound TCP and
publish-only MQTT pools. Instantaneous uses `0.0.25.9.0.255`, Block Load `0.5.25.9.0.255`, and
Daily `0.6.25.9.0.255`; template 93 retains its custom Wirepas Daily path.

For templates without a declared Daily PushSetup, a compatible captured Daily Load Profile
can supply the fallback: device identity, daily-channel OBIS, captured RTC, import kWh,
import kVAh, export kWh, export kVAh. Values come from the newest complete timestamped
captured daily row; the scheduler does not synthesize new energy readings. The field order
matches `vayu-core/CrystalHES.MQTTService/Helpers/TCPDLMSParser.cs` Daily handlers. Existing
declared Daily PushSetups take precedence. The fallback does not alter shared template
objects, other push profiles, or the generic All supported profiles selection.

## Verification

Virtual-clock tests cover slot coverage at up to one million meters, :00/:30 repetition,
India-midnight boundaries, the Daily cutoff, cancellation for all four switches, batch Stop,
mid-window recovery and persisted settings. Transport tests decode actual generated TCP and
4G MQTT payloads for all three profiles, and check the custom Wirepas Daily path. TCP checks
also verify the meter's source IP. Local encoding/socket completion is not proof of HES
database ingestion.
