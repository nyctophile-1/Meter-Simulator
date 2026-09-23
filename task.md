# Maya: Submit Prepaid Parameters — Implementation Tasks

## Definition of done

The five DLMS submit members return typed, non-null values through RF-1, TCP and MQTT/4G, and custom command `70` performs one complete seven-step DLMS exchange and returns one HES-compatible response containing all prepaid values. Tests prove values and field order, not only service startup.

## Implementation status

- Completed locally: dual `.91`/`.96` prepaid DLMS objects, mirrored writes, command-70 decoding, metadata-resolved OBIS reads, isolated custom DLMS runner, one-packet HES encoder, listener dispatch and focused tests.
- Verified locally: full suite `865 passed, 8 environment-dependent PostgreSQL tests skipped, 0 failed`.
- Remaining: capture a routed HES request/response on each named transport. No deployment or live activation has been performed.

## Tasks

### 1. Freeze the Maya contract

- Identify the Maya HES template ID, meter category and active custom-header generation.
- Export/inspect the five prepaid command mappings and any template-specific OBIS/type overrides.
- Capture or obtain one real HES custom command-70 request and expected response layout.
- Record the node width, frame-ID width, CRC rule, response magic and response header template.
- Stop for review if any of these are unavailable; do not invent framing values.

**Output:** a checked-in contract note or test fixture containing the verified Maya inputs.

### 2. Add the canonical prepaid fixture/provider

- Add named per-meter prepaid values to the simulator's existing model/configuration boundary.
- Support deterministic amount and date-time values for tests.
- Validate required values and types at load time or immediately before a response.
- Reject missing or incompatible values without publishing a partial response.

**Acceptance:** a unit test can retrieve all five submit values plus RTC for one meter.

### 3. Complete transparent DLMS object support

- Ensure the meter object loader creates the five required `GXDLMSData` objects.
- Resolve the correct HDLC/non-HDLC OBIS variant and honor template overrides.
- Set attribute 2 and the correct scalar/date-time data type.
- Verify the existing bridge returns each object value for RF-1, TCP and MQTT/4G.

**Acceptance:** five focused DLMS read tests pass and assert OBIS, type and value.

### 4. Add custom command-70 decoding

- Add `GetAllPrepaidParameters = 70` to the custom command model/catalogue.
- Allow only `GetWithoutData` for this command.
- Preserve raw command, frame ID, node ID and template-selected protocol facts.
- Return a clear unsupported/malformed result for wrong selectors or unavailable template metadata.

**Acceptance:** valid command-70 requests decode; wrong selector, node and framing cases fail without opening a meter session.

### 5. Implement the isolated seven-step DLMS runner

- Add `CustomPrepaidCommand` beside the existing custom RTC/profile commands.
- Use the existing isolated `MeterSessionManager` association.
- Execute association setup, RTC read, five prepaid reads, and release/cleanup.
- Enforce cancellation/read timeout and ensure association reset in all failure paths.
- Validate returned values before encoding.

**Acceptance:** a test records the seven-step exchange, including cleanup, and fails on any missing/invalid field.

### 6. Implement the single packed custom response

- Encode fields in Vayu's required order: RTC, last recharge amount, last recharge time, total amount at last recharge, current balance amount, current balance time.
- Apply the verified Maya template's data types, timestamp convention, header, response magic, node identity and frame correlation.
- Reuse common framing/CRC helpers where applicable.
- Publish exactly one response only after complete encoding succeeds.

**Acceptance:** a golden-byte or parser round-trip test recovers all six fields exactly.

### 7. Wire the dispatcher and observability

- Route command 70 to `CustomPrepaidCommand` in `MqttNicListenerService`.
- Keep existing RTC/profile dispatch unchanged.
- Record command, meter, NIC, template, frame ID, read count, packet count and response size.
- Do not log prepaid values, secrets or full payloads.

**Acceptance:** one inbound command-70 request produces one outbound response and one completion record.

### 8. Run bounded transport validation

- Run focused unit and integration tests first.
- Exercise one known-good Maya fixture through RF-1, TCP and MQTT/4G for the five DLMS commands.
- Exercise one custom Wirepas/Maya fixture for command 70.
- Verify request-to-response values, response count, frame correlation, timeout behavior and no partial publish.
- Keep live deployment/restart out of scope unless separately approved.

**Acceptance:** attach request/response evidence and list any route or template not verified.

## Suggested implementation order

1. Freeze Maya contract.
2. Add provider and transparent DLMS objects.
3. Add command-70 decoder and tests.
4. Add seven-step runner and packed encoder.
5. Wire dispatcher.
6. Run focused tests, then bounded transport validation.

## Explicit non-goals

- Do not implement this as five custom endpoint commands.
- Do not return zero/default values for missing OBIS data.
- Do not infer Maya framing from another HES template.
- Do not treat build success, listener startup or a published packet as end-to-end proof.
