# Comparing TCP and MQTT historical push

Open **Testing > Historical push**, select **TCP** in Transport, and select a running TCP batch. Configure its HES push destination and meter source-IP routing as usual.

Select the days and instantaneous interval. Concurrent records defaults to 0 (no application concurrency cap); a positive value applies the limit you choose. TCP defaults in the UI to waiting up to 15 seconds for HES to close after sending. Set the wait to 0 for immediate close. Block load uses the batch template capture interval. Enable **Use a fixed history end time** and choose a past date/time in IST. Leave the optional rate limit off for an unthrottled run, or set a matching rate for both transports. Start historical push.

For the MQTT comparison, select a running MQTT batch with matching meter count, template, communication classes and capture interval. Use the same fixed end time, days, instantaneous interval, concurrency and rate. With a positive record-concurrency limit, MQTT publisher count must not exceed it. Compare matching payload/profile mixes; custom Wirepas and DLMS use different encodings.

The existing historical engine replays instantaneous and load-survey records chronologically. TCP binds each meter source IP and connects and sends for each historical record, then waits for HES EOF or the configured deadline before disposing its socket. TCP-only replay ignores MQTT publisher/QoS settings. The transport filter selects existing batches; it does not convert a batch to another NIC type.

Historical replay dispatches a whole due timestamp when concurrency is unlimited, then finishes that timestamp before advancing. Checkpoints are saved between dispatch groups; an interrupted timestamp can replay unconfirmed work. Stop/Continue retains the original window, saved progress and saved concurrency/close settings. Failed/skipped records remain accounted for; cancellation or a crash can replay unconfirmed records. Sender completion measures transport delivery, not durable HES persistence. Measure receiver ingress, queue drain and database writes separately.

Historical applies configured BadComm failure percentages and NonComm classification to create missing records. It bypasses simulated network and BadComm delays. TCP stress bypasses both communication losses and simulated delays.
