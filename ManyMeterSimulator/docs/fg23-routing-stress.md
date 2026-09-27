# FG23 Routing

In Testing → MQTT stress, select Wirepas batches and choose **FG23 Routing**.
One message is published per selected meter per pass. Live, continuous loop,
scheduled MQTT stress, and Prepare → Fire use the existing publisher pools,
QoS, rate limit, concurrency, cancellation and delivery accounting.
Preparation is available even when meter DLMS ciphering is enabled: these
packets contain no DLMS invocation counters. Stop the current run to change profiles.

The option is Wirepas-only, does not need a HES custom-push template or a meter
session, and is excluded from **All supported profiles**. Existing automatic
FakeRouting traffic remains unchanged.

## Receiver contract

Verified against `vayu-routing` origin/master-pg commit
`6ed820094a99e0a2301d69d47a81bb03f83d61f0`:

- `CrystalHES.NodeManagementService/Helpers/RoutingSubscriptions.cs` subscribes
  to `$share/Routing/gw-event/received_data/+/+/+/247/+`.
- `Client/ManagementDataReceiverClient.cs` deserializes the MQTT bytes using
  protobuf-net as `GenericMessage.wirepas.packet_received_event`.
- The Wirepas branch reads `source_address`, `header.gw_id`, `header.sink_id`,
  `source_endpoint`, and `hop_count`. It sets LinkScore to 1 and uses receipt
  time for CreatedDate/LastCommunicatedOn, then calls AddRouting and UpdateLatestRouting.

MAYA publishes to `gw-event/received_data/{gateway}/{sink}/{node}/247/247`,
using the same per-meter gateway/sink assignment as HES registration and custom
push. Both envelope endpoints are 247, hop count is 1, destination is 0,
and receive time/event ID are generated for each envelope. The envelope's
Wirepas QoS is 1; the MQTT QoS is the stress control's selected QoS.

The inner payload is empty and payload_size is zero because this receiver does
not parse it. This reproduces the routing-service input contract, not a captured
FG23 firmware diagnostic body. MQTT bytes contain the full protobuf envelope;
this is not an empty MQTT message or a FakeRouting topic.

Tests verify routing fields, gateway boundaries, live/prepared sends, loop
regeneration, mixed-transport rejection, random selection, invalidation and
exclusion from All. A generated envelope was also deserialized successfully
using the actual `CrystalHES.Common 3.9.67-rc.60` assembly referenced by the
routing service, independently of MAYA's generated protobuf classes.
Broker completion and application health do not establish
downstream database persistence; that requires a separately observed HES run.
