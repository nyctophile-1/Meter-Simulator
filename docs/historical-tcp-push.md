# Comparing TCP and MQTT historical push

Open **Testing > Historical push**, select **TCP** in Transport, and select a running TCP batch. Configure its HES push destination and meter source-IP routing as usual.

Select the days, instantaneous interval and concurrent records. Block load uses the batch template capture interval. Enable **Use a fixed history end time** and choose a past date/time in IST. Leave the optional rate limit off for an unthrottled run, or set a matching rate for both transports. Start historical push.

For the MQTT comparison, select a running MQTT batch with matching meter count, template, communication classes and capture interval. Use the same fixed end time, days, instantaneous interval, concurrency and rate. MQTT publisher count must not exceed concurrency. Compare matching payload/profile mixes; custom Wirepas and DLMS use different encodings.

The existing historical engine replays instantaneous and load-survey records chronologically. TCP binds each meter source IP and connects, sends and disconnects for each historical record. TCP-only replay ignores MQTT publisher/QoS settings. The transport filter selects existing batches; it does not convert a batch to another NIC type.

Stop/Continue retains the original window and saved progress. Failed/skipped records remain accounted for; cancellation or a crash can replay unconfirmed records. Sender completion measures transport delivery, not durable HES persistence. Measure receiver ingress, queue drain and database writes separately.
