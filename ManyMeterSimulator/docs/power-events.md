# Power-event push

Select **Power events (101 / 102)** in Testing's normal push profile selector, MQTT stress,
TCP stress, or a saved stress task. The selected batch must support both events. Wirepas
uses custom discriminator 11; other NICs use DLMS PushSetup `0.10.25.9.0.255`.
`All supported profiles` includes one power event per meter per pass.

Each meter starts at power failure 101, then alternates restoration 102 and failure 101.
Normal pushes retain their sequence until the application restarts or the batch is deleted
or replaced. Stress runs each start at 101 and maintain their own sequence across loop passes.
Stress never changes a normal push's next event.

Only successful delivery of the event advances its sequence. Preparing or discarding packets,
skipped meters, failed sends, and cancellation before event delivery do not advance it.
If an event succeeds while another profile fails, the event still advances. MQTT success
uses the selected QoS publish result; TCP success means the complete payload was written.
Neither is proof that HES decoded or stored it.

Custom layouts come from the loaded HES model and configured event profile membership;
both IDs require valid RTC and UInt16 event fields. DLMS uses the template's power-event
captures, a fresh timestamp and explicit UInt16 code. A template's optional generic event
sequence field retains its current model value; this release does not simulate an event log.
Unsupported layouts are unavailable rather than borrowing another template's layout.

This first wave does not turn meters off. Readings and command responses continue after 101.
Automatic outage/restoration scheduling and suppression of normal or historical data belong
to a later release; stress traffic will remain independent of that behavior.
