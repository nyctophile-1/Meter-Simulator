# Custom-pull metadata requirements

Custom profile responses use the selected HES template's profile IDs and the category-specific field layout. Generated event responses now also require an event ID selected for that template and command. The former implicit IDs (including voltage event 1) are removed: D1 HES rejected event 1 during live custom-push verification, so a shared assumption could also invalidate custom-pull results.

Configure `CustomPull:EventIds` as a dictionary of HES template IDs to dictionaries of canonical command numbers and allowed event IDs. Obtain the allowed IDs and `CustomPull:EventsWithPowerProfile` from the intended HES environment. This applies to `ProfileDataSource=DataModel`; `ProfileDataSource=Meter` reads the existing meter profile's event IDs instead of replacing them.

| Command number | Generated profile |
| --- | --- |
| 41 | Voltage events |
| 42 | Current events |
| 43 | Power events |
| 44 | Transaction events |
| 45 | Other events |
| 46 | Non-rollover events |
| 47 | Control events |
| 83 | DI data (wire command 90 is an alias) |

For the verified D1 environment, the seven event-family IDs were 7, 51, 101, 151, 201, 251 and 301. Those are verification inputs, not defaults or a rule for other categories. Missing configuration, non-positive values and IDs exceeding UInt16 fail explicitly. The configured event's power-profile membership determines whether the response includes measurements or the smaller non-profile layout.

RTC and profile responses validate `MeterProfileHeaderTemplateId` from `MeterTemplate.csv`. Header 3 uses the verified 11-byte profile header with new transport framing. Headers 0, 1 and 2 use the 12-byte legacy profile header defined by the HES generic parser. Missing, unknown or incompatible layouts are rejected. The former RTC check on meter template numbers `<=26` is removed; response support is independent of meter template numbering. The HES's own generic-parser template allow-list remains an external limitation to verify.

Legacy response headers still carry a 24-bit RF node address. MAYA's reserved node allocation exceeds that range, so such responses remain explicitly unsupported for those nodes; validating a legacy header does not prove it can represent the current fleet. No truncation or alternate node identity is introduced.

## ESW pull contract audit

The D1 XML explicitly defines current ESW-1 at `0.0.94.91.18.255` and ESWF at `0.0.94.91.26.255`, with different 128-bit values. The `.18` status-word interpretation also matches the [Gurux maintainer's explanation](https://www.gurux.fi/node/14818).

Vayu's command 66 is named `GetESWF`. `Functions.GetOBISCodeByCommandType` defaults it to `.18`, while `GenericHelpers` allows a command-template `GetESWF` row to override that OBIS. Read-only HES metadata inspection found `.26` overrides in several command layouts; the selected template-88 and template-93 Misc IDs are 27 and 28 and have no such override in the queried rows. Therefore a command name alone does not establish the value being read.

The current simulator custom command decoder still has no command-66 implementation. The HES generic custom receiver recognizes profile discriminator 5, parses the 128-bit ESW payload, persists it and returns the bits; `HandleFinalPullResponse` stores the returned string as `JsonResponse.Value` for command 66. This is source contract evidence, not a verified HES pull exchange. The earlier clarification reversed the two OBIS suffixes; it was corrected before implementing either interpretation.

## Validation on 2026-09-13

The focused RTC/profile/resolver run passed 42 tests. The full Release suite passed **581 tests, zero failures or skips**, including event ID packing and missing/out-of-range rejection, arbitrary meter-template numbers for RTC, and incompatible/unknown header rejection. `git diff --check` passed. These tests establish source behavior; no new HES pull command, runtime configuration or application deployment was performed in this pass.

The live DLMS Daily rejection remains separate: the XML profile contains import values around 4.68 million and the selected HES Daily push layout has scalar 0. The fallback preserves those values. Correct units and a compatible template must be established before changing scaling or validation; neither was changed to manufacture a passing ingestion result.
