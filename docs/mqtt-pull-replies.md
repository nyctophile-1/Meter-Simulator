# MQTT pull replies

MAYA publishes command replies with QoS 0 by default on Mqtt4G, MqttWirepas,
and MqttKmesh. This includes custom endpoint-13 GR, daily, billing, RTC and
prepaid replies, and ordinary DLMS replies. Push and request subscription
settings are independent.

`Nics:Shared:MaxConcurrentReplyPublishes` defaults to 32 per connection and
must be positive. Replies from different meters can enter the publisher
concurrently. The existing dispatcher still serializes requests for each
meter, and each response's packets are awaited in order. The dispatcher also
limits concurrent meter work through `MaxConcurrentBrainCalls`.

MQTTnet serializes socket writes internally. MAYA no longer holds a separate
single-slot lock across each complete publish operation. QoS 0 also removes
the QoS 2 acknowledgement round trips. A successful send is not proof of
broker receipt or HES persistence; logs now say "sent" and include QoS.
Failed publishes stop that reply and do not record a completed session exchange.

For existing installations, preserving server appsettings also preserves old
QoS overrides. Set `Nics:Mqtt4G:PublishQos`, `Nics:MqttWirepas:PublishQos` and
`Nics:MqttKmesh:PublishQos` to 0 in the effective server configuration during
deployment. Preserve other settings and verify each client startup log reports
reply QoS 0 and the intended concurrency. Keep the prior settings in the normal
application backup for rollback.

Validation uses a local TCP peer with the real MQTTnet client: concurrent QoS 0
packets without acknowledgements, bounded acknowledged publishes, out-of-order
acknowledgements, rejection, and cancellation slot recovery. Dispatcher tests
cover per-meter order and concurrency across meters. These checks do not
establish sustained DRISHTI throughput or HES command completion under load.
