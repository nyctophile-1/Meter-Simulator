# Smart NIC (Wirepas custom channel) — handoff

Continuation of `virtual_nics.md`. Read that first for the four DLMS NICs (Phases A–G, all built);
this file covers the **custom channel** work and is the fast-start for the next session.

Branch `virtual-nics`. Last commit `463f11b`. **171 tests green.**

---

## 1. The correction that shapes everything

There is **no separate "RF2" NIC**. Wirepas is ONE physical NIC with TWO channels, selected per
request by the protobuf's `destination_endpoint`:

| Endpoint | Channel | NIC behaviour |
|---|---|---|
| 3 | DLMS | **Transparent** — carries bytes between HES and the brain, like every other NIC. Built and working. |
| 13 | Custom ("RF2") | **Smart** — HES asks for an OUTCOME ("block load profile T1→T2") and the NIC firmware runs the whole DLMS conversation with the meter itself, returning a manufacturer-specific binary blob. |

A `NicType.MqttWirepasRf2` was added and then **reverted** — do not reintroduce it. A single
Wirepas meter can be polled on either channel in the same session.

The custom channel still reads through the **same brain** via `IMeterSimBridge`. An earlier plan to
bypass it was wrong: bypassing would let a custom profile read invent data that contradicts a plain
DLMS read of the same meter.

**Topic asymmetry (already caught once, worth re-reading):**
- **Inbound**: RF1 and RF2 share `gw-request/send_data/{gw}/{sink}`. Demux on `destination_endpoint`.
- **Outbound**: endpoints are *path segments* — `gw-event/received_data/+/+/+/3/3` vs `…/13/13`.
  The endpoint pair we publish under **selects which HES service picks the message up.**

---

## 2. Wire formats — all four framings now fully specified

Derived from HES source (`MQTTSendCustomCommandClient`, `DLMSHandlingFunctions`,
`CustomPullCommandPayload`). Everything little-endian **except the CRC**.

```
 5  Wirepas DLMS     len | totalFrag | thisFrag | frameId(2)
 6  direct 4G        len(2) | totalFrag | thisFrag | frameId(2)
10  custom, old      len | totalFrag | thisFrag | frameId(2) | 5 bytes HES NEVER READS
12  custom, new      magic(4) | len(2) | totalFrag | thisFrag | frameId(4)
```

**The 10-byte header's extra 5 bytes are opaque to HES.** Every `fragmentBytes[]` index read across
all reassembly functions is 0,1,2,3,4 (5/10-byte), 4–5 (6-byte), 6,7,8–11 (12-byte). Nothing touches
5–9. So we emit zeros. This was a flagged unknown and is now closed.

**CRC** is CCITT-FALSE (poly 0x1021, init 0xFFFF) and goes on the wire **BIG-endian** — the only
multi-byte field in any of these protocols that does. HES computes it, takes LE bytes, then swaps.
Reading the swap as a quirk rather than an endianness choice is how it gets dropped. Verified
against `"123456789"` → `0x29B1` → wire bytes `29 B1`.

**Request** (`CustomPullCommandPayload`, Pack=1, inside the Wirepas `send_packet_req`):
```
PacketLength(1) TotalFragments(1) FragmentId(1)
FrameId(2 or 4)  FromNodeId(3 or 4)  ToNodeId(3 or 4)     ← template-driven widths
CommandType(1) DataSelector(1) DataLength(1)
CommandValueFrom(int32) CommandValueTo(int32)              ← usually unix epochs
```
Widths come from the template (`PullHeaderLength == 12 || IsFG23` → 4 bytes, else 3) and are **not
signalled in the packet**. Read at the wrong width and every later field silently shifts into
plausible garbage. There is a test that deliberately does this and asserts the result is wrong.

Response endpoints seen in HES: 13 (custom pull), 14 (diagnostics), 30 (SyncRTC v2), 31 (FOTA),
120 (image status). **Scope is endpoint 13 only** — user-confirmed.

---

## 3. The data model — resolved and loading

Four CSVs exported from HES (`SizeChangeEQA`) into `KimbalSpecifics/DataModel/` (**gitignored** —
`MeterTemplateDetail.csv` alone is 16.6 MB). Export scripts are in the session scratchpad.

### The lookup chain — two hops, and the trap

```
batch HesTemplateId ──► MeterTemplate row
                          ├─ PullHeaderLength ──► which framing
                          ├─ IsFG23           ──► node id width
                          ├─ MagicNumberMapping (REVERSE) ──► magic to emit, if 12-byte header
                          └─ BlockTemplateId / DailyTemplateId / BillTemplateId /
                             InstantTemplateId / EventTemplateId / MiscTemplateId
                                     │  (which column depends on the command)
                                     ▼
                             MeterTemplateDetail.ProfileTemplateId
                                     └─ ordered fields (SerialNumber = byte order)
                                          └─ ProfileAttributeMapping ──► OBIS + AttributeIndex
```

**`ProfileTemplateId` is NOT `MeterTemplate.Id`.** Meter templates 34, 66 and 80 (`Linkwell_3P`,
`Linkwell_1P`, `Linkwell_TCP`) all point at block profile **35**. Conflating them makes every
lookup miss or, worse, hit an unrelated profile.

**Join key** into `ProfileAttributeMapping` is `(Profile:int, MeterCategory:"1P"/"3P"/"CT",
ParameterName)`. Verified: 15/15 sampled fields resolved.

**`ProfileType` is the real discriminator** — a composite like `BLOCK_CUSTOM_PULL_3P`
(profile × payload type × direction × category). The custom channel is the `%_CUSTOM_PULL_%` rows.

### Real numbers

189 templates, 111 magic numbers, **5,927 profile layouts**, 1,239 attribute mappings.

`PayloadType` enum: `DLMS=1, NonDLMS=2, DirectDLMS=3, TCPDLMS=4`.

| pullHdr | pullType | count | |
|---|---|---|---|
| 5 | 1 | 3 | Wirepas DLMS |
| 10 | 2 | 25 | custom, old header |
| 12 | 2 | 74 | custom, new header + magic |
| 7 | 3 | 15 | Kmesh |
| 0 | 3 / 4 | 71 | no NIC header |

**109 of 111 magic numbers belong to `12/2` templates** — magic and CRC are properties of the *new
custom header*, not of the NIC. Select framing from `PullHeaderLength`, never assume.

### Sample layout (profile 35, `BLOCK_CUSTOM_PULL_3P`, 28 fields)

```
 1  RtcDateTime                DateTime  sc=0   -> 0.0.1.0.0.255
 2  RPhaseCurrent              UInt32    sc=-2  -> 1.0.31.27.0.255
 5  RPhaseVoltage              UInt16    sc=-1  -> 1.0.32.27.0.255
 8  RPhasePowerFactor          Int16     sc=-3  -> 1.0.33.27.0.255
11  CumulativeEnergyKwhImport  UInt64    sc=-6  -> 1.0.1.29.0.255
```

---

## 4. Standing instructions from the user

- **CSV is truth.** No cross-table validation, no fallbacks, no guessing. A wrong template is a
  finding to fix in HES and re-export — not something to defend against in code.
- **Refresh = replace the CSVs and restart the app.** No hot reload needed.
- Stale rows (a magic number pointing at a since-retyped template) are ordinary drift. Load them.
- Make it **generic**: the template id is a user input, so nothing is hardcoded to a template.
- Fragmentation is **deferred** (both directions), except that Wirepas *requests* genuinely arrive
  in 90-byte chunks and will need inbound reassembly eventually.

---

## 5. Built this session

| File | What |
|---|---|
| `Networking/SmartNic/CommandIntent.cs` | Transport-agnostic seam: `CommandIntent`, `MeterReadResult`, `MeterReadRow`. A future custom-Kmesh codec produces the same types from a different envelope. |
| `Networking/SmartNic/HesDataModel.cs` | Loaded model + the two lookups (read plan / byte layout). |
| `Networking/SmartNic/HesDataModelLoader.cs` | CSV loader. Column lookup **by name**, quoted-CSV reader, BOM handling, sorts fields by `SerialNumber`. |
| `Networking/Mqtt/Codecs/Rf2Framing.cs` | Request parse (template-driven widths), 12- and 5-byte response headers, CRC. |
| `Provisioning/MeterBatch.cs` | `HesTemplateId` (int?), persisted, **optional** — the same meter answers DLMS with no data model. |
| `Components/Pages/Setup.razor` | HES template id field (Wirepas only); "template" renamed to **"Meter model (XML)"** to stop the word meaning two things. |
| Tests | `Rf2FramingTests`, `HesDataModelTests` (incl. a real-export smoke test that skips if absent). |

---

## 6. Next steps

1. **Extend `Rf2Framing`** for the 10-byte header (trivial now: 5-byte layout + 5 zero bytes),
   selected from `PullHeaderLength` at runtime.
2. **Endpoint demux** in the Wirepas transport: ep 3 → existing `WirepasCodec`, ep 13 → RF2 codec.
   Currently `WirepasCodec.TryRoute` returns false for anything but ep 3, so RF2 traffic counts as
   `ignored`.
3. **RF2 codec**: envelope ⇄ `CommandIntent`.
4. **SmartNic**: a Gurux **client** loop over `IMeterSimBridge` — `AARQRequest()` →
   `Read(obj, attr)` / `ReadRowsByRange(pg, from, to)` → `GetData()` reply loop (handles block
   transfer) → release. `GXDLMSClient` is already in-solution and confirmed to have all of these.
   Start with `GetBlockLoadProfile`, which exercises association + selective access + block
   transfer in one command.
5. **Packer**: `MeterReadResult` → bytes, ordered by `SerialNumber`, typed by `DataType`, scaled by
   `Scalar`. **Enumerate the full distinct `DataType` set from the CSV first** and fail loudly on
   anything unmapped — a wrong width shifts every subsequent field.
6. **Concurrency**: one RF2 request becomes MANY bridge exchanges. The dispatcher's global
   semaphore currently wraps the whole work item, so a profile read would hold a permit for the
   entire conversation and starve other meters. Move the permit to per-bridge-call, or give the
   custom channel its own budget. Cheap now, painful at scale.

**Test target: template 34 (`Linkwell_3P`)** — `12/2`, points at profile 35 which is already walked
end to end. Templates 36 and 39 are `10/2` if that path needs exercising.

---

## 7. Open items

- **Findings for HES, deliberately not corrected here** (CSV is truth): profile 35 field 7,
  `BPhaseVoltage → 1.0.72.7.0.255`, where R/Y use `…32.27…`/`…52.27…`. Looks like it should be
  `1.0.72.27.0.255`.
- **The 4G blocker is still unresolved** (separate thread, see `virtual_nics.md` §13): HES polls,
  we answer with a valid accepting AARE, HES's `ProcessMessage` never runs. Candidates: response
  topic shape (`PollResponse/{nodeId}` vs `…/{nodeId}/{frameId}`), `direct_tcp` routing on those
  node ids, or another service owning `PollResponse/#`. Captures now record **both directions**,
  so the next run is diagnosable without inference.
- **Uncommitted**: `.gitignore`, `NicType.cs`, `MeterBatch.cs`, `BatchStore.cs`, `MeterRegistry.cs`,
  `Setup.razor`, `Dashboard.razor`, plus new `Networking/SmartNic/`, `Rf2Framing.cs` and two test
  files. Everything before this session is committed (7 commits, `463f11b` at tip).

---

## 8. Traps worth re-reading before writing code

1. `ProfileTemplateId` ≠ `MeterTemplate.Id`.
2. Node id / frame id widths are template-driven and not self-describing.
3. CRC is big-endian; everything else is little-endian.
4. The outbound endpoint pair decides which HES service receives the message.
5. `PullHeaderLength == 7` (Kmesh) is a **discriminator**, not a length — no 7 bytes to strip.
6. Field order (`SerialNumber`) IS the wire layout. Never rely on export row order.
