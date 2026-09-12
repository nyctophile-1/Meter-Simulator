# Routing refresh for all running batches

`MqttRoutingService` runs automatically every 30 minutes while MAYA is running.
The first cycle is 30 minutes after service startup. Each cycle reads the current
batch registry and publishes one zero-byte message per node in every Running
batch regardless of NIC type, using that batch's enabled environment broker.
This includes TCP 4G, MQTT 4G, MQTT 4G IMG, Wirepas, and Kmesh.
Node IDs use `MeterNodeIds.Format`, including the reserved MAYA offset.

The topic is `FakeRouting/{nodeId}/{transportType}`, with an empty payload.

| Batch NIC | Transport suffix |
| --- | --- |
| TCP 4G | `4` |
| MQTT 4G and MQTT 4G IMG | `3` |
| Wirepas | `2` |
| Kmesh | `1` |

For example, a TCP batch publishes `FakeRouting/1000000001/4`. Routing uses
suffix 4 to initialize `direct_tcp` and suffix 3 to initialize `direct_4g`
when no route exists, without requiring a meter-template lookup.
The 2026-09-13 receiver changes add `$share/Routing/FakeRouting/#` to Routing
and `FakeRouting/#` to GapReading and Background Service. Deploy those receivers
before enabling this publisher. Routing preserves existing route metadata;
unknown RF nodes still require a real gateway/sink route before FakeRouting can
refresh them. See the sibling repositories' `fake-routing.md` for rollout and
validation details.

Publishing uses one dedicated connection per batch, QoS 0, no retain flag, and a
five-second publish timeout. The connection opens directly from the environment
broker settings, without requiring an MQTT NIC listener or an active 4G MQTT
batch on that broker. It does not instantiate meter sessions, generate
DLMS data, or depend on the manual/stress push controls. Cycles run serially and
do not overlap. Batch stop, removal, rebind, or broker configuration changes stop
the remaining messages for that batch when checked before the next publish;
an already in-flight message may finish.

Unbound batches and environments without an enabled MQTT broker are skipped.
A connection/publish
failure stops that batch's cycle, logs its sent count, and allows other batches
to proceed. There is no immediate replay; the next cycle tries the current fleet
again. QoS 0 provides one application publish attempt per node, not guaranteed
broker receipt or HES persistence. Schedules restart with the process.

Validation covers active batch selection, every NIC type, exact node topics,
empty payloads, broker selection, repeat cycles, stop/rebind, failure isolation,
and cancellation. Loopback MQTTnet tests run the routing service with each NIC
type and no listener, checking the exact topic, zero-byte wire payload,
QoS 0 and retain=false. Deployed Vayu-routing persistence is not exercised by
these local tests.

All 16 focused routing and MQTT socket tests passed locally on 2026-09-13,
including the exact transport suffix for all five NIC variants.
Build output is redirected because the existing local simulator locks its Debug
DLL; that running process is left in place.

```powershell
dotnet test ManyMeterSimulator.Tests/ManyMeterSimulator.Tests.csproj --no-restore --filter 'FullyQualifiedName~MqttRoutingServiceTests|FullyQualifiedName~MqttPushSocketTests' --verbosity quiet -m:1 -p:BaseOutputPath=C:/Users/ayush/AppData/Local/Temp/maya-routing-validation-20260912/
```
