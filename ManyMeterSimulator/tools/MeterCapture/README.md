# Bounded DLMS meter capture

This console tool reads a physical meter over IPv6 TCP/DLMS wrapper. It uses the repository's Gurux library and the existing HES contract: public client 16/server 1; user client 48 with High authentication and authenticated encryption; GlobalKey for both cipher and authentication keys; public invocation-counter object `0.0.43.1.3.255` followed by counter + 1 for the secure association.

It issues association/authentication, GET, receiver-ready and disconnect requests. It does not perform data SETs, clock changes, profile capture/reset methods, firmware operations or key updates. HLS authentication itself uses the standard association handshake. Association and security-setup values are excluded from bulk attribute reads; supplied credentials are never written into the XML or report.

Use a non-secret configuration file:

```json
{
  "Host": "<meter IPv6 address>",
  "Port": 4059,
  "HesTemplateId": 31,
  "Output": "<new output directory>",
  "InterfaceIndex": 7,
  "Secure": true,
  "DiscoveryOnly": true,
  "Rows": 13
}
```

Verify the current interface index; do not assume 7 on another machine. Omitting InterfaceIndex uses normal routing. The option applies only to this socket and does not alter host routes. HesTemplateId is evidence metadata, not a parser/layout selector.

Provide `MAYA_CAPTURE_GLOBAL_KEY` and `MAYA_CAPTURE_HLS_SECRET` through the child process environment for secure reads. Do not place keys in configuration, command-line arguments or repository files. Run `dotnet run --project tools/MeterCapture/MeterCapture.csproj -c Release -- <config-path>` from the ManyMeterSimulator directory. An existing output directory is rejected.

Start with discovery to verify the association view, meter type/category and serial. With DiscoveryOnly false, the tool also reads allowed attributes, ordered profile capture definitions, scaler/unit attributes and at most Rows entries per profile (maximum 100). The selection requests the last available entry range; its timestamp order remains the meter's own order. Limits are five minutes, 500 objects, 3,000 exchanges, 256 blocks per read and approximately 8 MiB of received data. Each stream read/write times out after ten seconds.

`capture.json` records read outcomes, identity, counts, timestamps and XML SHA-256. `meter.xml` is saved only when the capture flow finishes; denied attributes are explicitly recorded and default/unread values must not be treated as observed measurements. A transport/authentication failure stops the run and is not retried with guessed credentials. Retain each capture separately and validate compatibility before using its rows as composer input. The tool has been exercised against the supplied test meters; it is not a universal vendor/security-suite reader.

`ProfileLogicalNames`, when supplied, limits profile reads to that list and bulk object reads to their captured objects. For example, `["1.0.99.2.0.255"]` captures Daily only. Identity is still read. Unselected objects in the association remain present but their default values are not physical observations.

Optional `ReadMissingCaptureScalers: true` attempts a GET of scaler/unit metadata for register objects referenced by the selected profiles but missing under that exact class/LN in the association. Results are recorded separately, including that their version was not observed in the association. It does not fabricate object definitions or treat a failed read as scaler 1. Ordinary attribute outcomes also record object class to distinguish conflicting declarations sharing an LN.

Gurux applies register scalers when updating profile buffers. `meter.xml` retains that ordinary client export. Each `raw-profile-<logical-name>.json` records decoded wire cells before this conversion. The additional `meter-profile-wire.xml` restores the captured numeric values and types in profile buffers, while retaining decoded dates and all other object definitions. Use this second XML as a profile donor for simulation, after compatibility checks. This does not infer or reverse scaling in older XMLs, and does not normalize standalone register values. The report hashes both XMLs. The simulator can widen a numeric pull encoding when shared captured objects also occur in other profiles; the regression checks exact numeric equality through pull and float32 equality through Daily push.
