# Maya: Submit Prepaid Parameters

## Objective

Implement the Maya meter/NIC behavior required by HES `Submit Prepaid Parameters`.

The implementation has two deliberately different paths:

1. **DLMS path** — RF-1, TCP, MQTT/4G and the other transparent-DLMS NICs continue to receive the five setter requests. The simulated meter must return a non-null, correctly typed value for every required prepaid OBIS object.
2. **Custom protocol path** — endpoint-13 sends one custom command, `GetAllPrepaidParameters` (`70`). The NIC performs the seven-step DLMS exchange against the simulated meter, reads the complete prepaid set, and publishes one HES-compatible response containing all values in the order expected by `MQTTSendCustomCommandClient`.

The custom path must not send five independent custom responses. Its externally visible result is one correlated response for the original frame.

## Verified source contract

The implementation is based on the following existing Vayu source:

- `vayu-sql-database/CrystalHES.Database/Enums/CommandTypeEnum.cs`
  - `SetPrepaidBalance = 56`
  - `SetLastRechargeAmount = 58`
  - `SetLastRechargeTime = 59`
  - `SetTotalAmountAtLastRecharge = 60`
  - `SetCurrentBalanceTime = 61`
  - `GetAllPrepaidParameters = 70`
- `vayu-common/CrystalHES.Common/Helpers/Functions.cs`
  - DLMS/HDLC OBIS mapping:
    - prepaid balance: `0.0.94.91.24.255` for HDLC, `0.0.94.96.24.255` otherwise
    - last recharge amount: suffix `.21`
    - last recharge time: suffix `.22`
    - total amount at last recharge: suffix `.23`
    - current balance time: suffix `.25`
- `vayu-core/CrystalHES.MQTTService/Client/MQTTSendCustomCommandClient.cs`
  - custom command `70` parses the response as:
    1. profile/RTC value
    2. last recharge amount (`Int32`)
    3. last recharge time (`DateTime`)
    4. total amount at last recharge (`Int32`)
    5. current balance amount (`Int32`)
    6. current balance time (`DateTime`)
- `vayu-core/CrystalHES.MQTTService/Helpers/PrepaidResponseProcessor.cs`
  - the five aggregate members are command IDs `56, 58, 59, 60, 61`.

The exact response header, template layout, response magic, node-width and frame-width must continue to come from the selected Maya/HES data model. They must not be guessed or hard-coded from a different template.

## Design

### 1. Canonical prepaid value source

Add a small prepaid value provider owned by the simulated meter/model layer. It should expose named values, not positional bytes:

- `LastRechargeAmount` — signed 32-bit integer
- `LastRechargeTime` — DLMS date/time
- `TotalAmountAtLastRecharge` — signed 32-bit integer
- `CurrentBalanceAmount` — signed 32-bit integer
- `CurrentBalanceTime` — DLMS date/time
- `Rtc` — the clock value used by the custom response's first field

The provider should resolve values per meter and preserve the existing XML/data-model behavior. It must reject missing values before any response is published. It must not silently substitute zero, the host clock, or a default date for a missing configured value.

### 2. Transparent DLMS path

Keep the existing transparent-DLMS request flow and object lookup. Ensure the five setter-target objects are loaded into each applicable simulated meter with the expected object type, attribute index, data type and value:

- `GXDLMSData` attribute 2 for the four scalar/time data objects.
- The exact value type must follow the selected HES template where one is provided; otherwise use the Vayu fallback types (`Int32` for amounts and DLMS octet/date-time representation for times).

This path should work through the existing bridge for RF-1, TCP and MQTT/4G. No custom endpoint framing is involved.

### 3. Custom protocol path

Extend the custom command catalogue and decoder to recognize raw command `70` with selector `GetWithoutData`.

Add a dedicated `CustomPrepaidCommand` (or equivalent) that:

1. Validates running-batch, NIC, selected template and response-header compatibility.
2. Creates the same isolated read association used by the existing custom commands.
3. Performs the standard seven-step DLMS exchange: association setup, the required reads for RTC and the five prepaid objects, then release/association cleanup.
4. Validates every returned value and converts it to the types consumed by the Vayu custom parser.
5. Encodes exactly one custom response using the selected template's header/framing contract.
6. Echoes the request frame ID, node identity and response magic exactly as the existing custom response path does.
7. Publishes only after the entire body has been validated and encoded.

The custom response body must preserve this order:

`RTC, LastRechargeAmount, LastRechargeTime, TotalAmountAtLastRecharge, CurrentBalanceAmount, CurrentBalanceTime`.

The implementation should reuse the existing custom response framing helpers, but must not reuse `CustomProfileCommand`'s profile-row assumptions unless the Maya export proves that command 70 is represented by a profile layout. The Vayu client parses this as a packed non-DLMS response, so the default design is a dedicated packed encoder.

### 4. Configuration and model validation

Use the selected HES template/category to resolve:

- prepaid OBIS overrides, if exported;
- scalar and data-type declarations;
- custom response header generation and response magic;
- legacy versus new-header framing.

Fail closed with an actionable log when any required mapping or value is absent. Do not make the custom endpoint appear successful with a partial response.

### 5. Observability

Log one structured completion record per request containing meter, NIC, command, frame ID, selected template, number of DLMS reads, response byte count and success/failure. Do not log prepaid values or credentials by default. Preserve existing metrics and session accounting.

## Validation strategy

Validation is staged and bounded:

1. Unit tests for command `70` decoding, selector validation, value ordering, integer/date encoding, missing-value rejection, and duplicate/partial-response prevention.
2. DLMS integration tests for each five setter OBIS objects, including typed values and the selected template/category.
3. Custom integration test proving one command causes the seven-step exchange and one response with all six packed fields in the expected order.
4. Transport smoke tests through RF-1, TCP and MQTT/4G using the existing NIC routes; verify request-to-response correlation rather than only process/log success.
5. A Maya-template acceptance run with captured request/response bytes and the Vayu parser or equivalent independently checking every field.

Acceptance requires input-to-output evidence for both paths. A build, listener startup, or successful publish alone is not sufficient.

## Out of scope

- Changing HES, Vayu command IDs, database aggregation, or deployment configuration.
- Implementing prepaid write semantics beyond returning the values required by the submit flow.
- Claiming RF-1, TCP, MQTT/4G or custom success until the corresponding route has a verified request and response.

## Open checks before coding

- Confirm the exact Maya template/category and whether it supplies prepaid field overrides.
- Confirm the custom response header/body layout and response magic from the Maya export or a captured HES request.
- Confirm whether the custom seven-step sequence includes one RTC read plus five prepaid reads in the deployed Vayu build, or whether RTC is obtained through the existing profile helper.
- Confirm the desired deterministic fixture values and time-zone convention for test evidence.
