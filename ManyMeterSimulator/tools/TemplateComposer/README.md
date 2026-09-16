# Template composer

Compose compatible profile data into a new XML while preserving the base object model. By default it fills empty profile buffers; it does not union different meter models or overwrite source XMLs.

From the ManyMeterSimulator directory:

```powershell
python tools/TemplateComposer/compose.py --base ManyMeterSimulator/Templates/SA1231166HP_values.xml --donor ManyMeterSimulator/Templates/SA1231166HP_values_bill.xml --donor "C:/Users/ayush/Documents/MAYA-release-receipts/d1-wave-20260913-1804/captures/D1_SA1038079_20260913.xml" --output ManyMeterSimulator/Templates/D1_Master.xml --report docs/scenario-verification/d1-master-composition.json
python -m unittest discover -s tools/TemplateComposer -v
```

The command rejects category incompatibility and checks class/version, ordered captures, referenced scalers/units and row widths for every imported profile. Populated base buffers retain precedence, so incompatible unselected donor profiles cannot replace them. It validates row capacity, fixes EntriesInUse and records SHA-256 provenance. Source dates are retained; runtime time normalization belongs to the simulator loader. More than one `--donor` is supported, in explicit precedence order.

The current D1 composition and validation limits are recorded in [d1-master.md](../../docs/scenario-verification/d1-master.md).

To replace a known incorrect buffer from an authoritative capture, pass `--replace-profile <logical-name>` for each explicitly selected profile. Each replacement must have exactly one populated compatible donor; missing or ambiguous donors are rejected before writing. All other populated base buffers retain precedence. Use the capture tool's `meter-profile-wire.xml` for freshly captured profile values: ordinary Gurux client exports can contain already-scaled values and must not be assumed to be wire values. The report records explicit replacements separately and still verifies the entire object model unchanged.
