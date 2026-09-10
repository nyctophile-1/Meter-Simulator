# Custom profile pulls

Custom Wirepas requests on `gw-request/send_data/{gateway}/{sink}` with destination
endpoint **13** now support the following profile commands:

| Request | Command byte | Response profile byte |
|---|---:|---:|
| Instantaneous (IP) | 3 | 22 |
| Block/load survey (LS) | 4, 72 | 19 |
| Daily (DP) | 5 | 20 |
| Billing | 6 | 21 |
| Voltage, current, power, transaction, other, non-rollover, control events | 41–47 | 23–29 |
| Stored instantaneous | 50 | 22 |
| DI event data | 83, 90 | 83 |

IP uses selector 1. The other profiles accept selector 1 (default history), 4
(inclusive one-based entries), 5 (inclusive dates), and 6 (positions from newest).
Gap bitmap command 21, vendor-specific event commands, nameplate, schedules, and writes
are not part of this profile implementation. GetRTC remains its separate live clock read.

## Data generation

EQA explicitly uses `CustomPull:ProfileDataSource = DataModel`. This implements the
requested deterministic simulation: profile rows are generated from the HES layout
without depending on whether the XML contains those profile rows. XML files are preserved.
Values are engineering-unit simulation values, not recordings of actual meters.

`CustomProfileDataGenerator.Value` is deterministic for the same meter index, field,
profile kind, event ID and timestamp. Cumulative energy is monotonic with time; block
energy represents an interval. Voltage, current, power and PF have repeatable plausible
defaults. Fields without a recognized electrical meaning receive a small deterministic
raw default. HES metadata supplies field order, data type and inverse scalar; an unknown
wire type or out-of-range value fails explicitly rather than wrapping.

Date requests generate the requested historical intervals on demand, including dates
outside the default history. Future intervals return no rows. Default/entry history is
7 days of 15-minute LS, 30 daily rows, 12 monthly billing rows, 96 stored IP rows, and
32 hourly event/DI rows. Default maximum is 4096 rows and 4 MiB per command; larger
requests must be split. Empty results use HES profile byte 100.

`ProfileDataSource = Meter` is an optional strict XML-backed mode. It reads through an
isolated public DLMS association, and returns only available XML rows. Missing captures,
access-denied attributes or incompatible numeric ranges are errors in that mode; it does
not silently switch sources. EQA uses DataModel so those XML gaps do not block simulation.

## EQA metadata and wire contract

The four CSV exports live at `/opt/maya-sim/data/custom-pull`. `MeterTemplate.csv` also
needs `MeterProfileHeaderTemplateId` and `EventNonProfileTemplateId` for profile replies.
Template 93 is selected as a **HES decoding layout**, independently of the batch's XML
template; its category is explicitly `1P`, response magic `1050946`, body header ID 3.
`EventsWithPowerProfile` is copied from EQA's HES setting. Other templates need their
category configured and matching exported layout metadata.

Each response body carries one row, because HES's daily, billing and IP parsers consume
one row and event layouts can differ by event ID. Bodies retain the original frame ID;
legacy bodies are fragmented if their packet would exceed its one-byte length. Publishing
uses the request's broker, gateway and sink on
`gw-event/received_data/{gateway}/{sink}/{node}/13/13`.

HES subtracts 330 minutes when decoding profile timestamps, so generated response epochs
include that offset. Block date requests include a 330-minute shift in this EQA sender;
other date requests use UTC. Both offsets are configurable. RTC has its separate timestamp
contract and is unchanged.

Tests use a small EQA metadata fixture to check every response profile, exact body lengths,
determinism, range boundaries, timestamp conversion and legacy fragmentation. A live HES
command is still needed to confirm HES ingestion/completion for each deployment.
