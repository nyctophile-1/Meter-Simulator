# Remaining D1 wave work

The user selected D1 for wave 1; D2/D3 and separate category-code variants are future work. The 86-row historical matrix remains visible with those rows explicitly deferred. RTC push is custom Wirepas only; DLMS support is independent of NIC type.

Direct database command insertion is authorized and working. Both selected D1 GetRTC commands completed successfully using existing DRISHTI responders. An API session is no longer a prerequisite. See [d1-master.md](d1-master.md).

The D1 master merges the compatible local Billing donor while preserving the base model. The locale parsing fix and fresh local Billing exchange pass. Remaining work includes:

The subsequent [time-alignment release](d1-time-alignment-20260914.md), `time-d17d9f77`, is deployed and verified on both hosts with 598 tests. It corrects future profile snapshots while retaining row spacing and all XML content. Four fresh packet RTCs also pass the local Common parser. EQA now has approximately 288 MiB root space; any further deployment needs a fresh capacity check.

- Completed: capture and comparison of the supplied physical D1 meter definitions and bounded profile rows. The user provided three IPv6 endpoints and identified the last column as HES template IDs 31/31/21. Keys are omitted from repository artifacts. Socket binding to Wi-Fi reaches all three endpoints without changing host routes. Secure discovery of the first template 31 endpoint identifies SA1038079, meter type 6/category D1, 155 objects.
- Four compatible event profiles now contain 39 rows from the physical D1 capture. The three remaining event buffers were empty on that meter; Billing/event push setups are absent from the preserved model.
- Local Common fixes preserve explicit UTC timestamps and convert hundredths to milliseconds; 28 compiled compatibility cases pass. These Common changes are not released or deployed. Nonzero/unspecified deviation policy remains unresolved. Repeat Daily energy validation with the corrected master through an active HES consumer; current-time simulation does not justify altering source scalers or numeric values to bypass validation.
- Verify remaining D1 pulls and GRBlockLoad through the HES command lifecycle. GetRTC, Custom Instant and Custom ESW have succeeded; the complete matrix has not. Custom ESW command 98932984 persisted row 3908521 with all 128 bits verified against the deployed source. The command 66 handler follows the [checked HES ESW mapping](esw-pull-contract.md); ESW and the XML ESWF filter remain separate.
- MAYA profiles-818f418a is deployed and verified on both targets, including the profile-wire XML, shared-type precision fix and custom ESW read. EQA has about 298 MiB root headroom; preserve the complete offhost recovery strategy for its next release. Existing batches retain their earlier template selections. Isolated DLMS Instant command 98932983 completed its protocol exchange but failed persistence with invalid energy values from its older selected XML. See [the release evidence](d1-release-20260914.md).
- Both MAYA servers answered the same node/frame during observed DLMS Instant command 98932916. Fleet isolation awaits the user's preference. HES push/routing were inactive at the latest check; fresh persistence tests need the intended consumer running. No HES service or configuration was changed.
- The local master now retains 100 Block rows using fresh wire values, plus fresh Daily, Instant and four populated event buffers. Billing remains the original compatible 13-row donor: its physical capture references class 4 at 1.0.84.6.0.255, while the association declares class 3 and a direct class-4 read returns undefined object. The base has no standalone definition there. Importing it without resolving that mismatch would weaken the model checks.

The latest work made progress; the earlier 16:16 UTC blocked audit is historical. The master deployment is verified; no full-matrix success is claimed.


