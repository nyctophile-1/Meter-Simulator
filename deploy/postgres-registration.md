# PostgreSQL simulator registration

`register-postgres-meters.ps1` registers a Wirepas meter CSV on any reachable PostgreSQL server with the LHES-compatible `nameplate`, `metersecurity`, `latestrouting`, and `metertemplate` tables. Set `-Schema` for the server. It does not assume the older EHES `public.meter_*` schema is interchangeable, create missing tables, or copy templates between servers.

Requires PowerShell 7 running .NET 10 and Npgsql 10 with Microsoft.Extensions.Logging.Abstractions 10. By default the script checks the user's NuGet cache for Npgsql 10.0.3 and Logging.Abstractions 10.0.0. Pass `-NpgsqlAssembly` and `-LoggingAssembly` to use another installation. Credentials are read from `PG_REGISTRATION_PASSWORD`; they are not written to reports or committed settings.

```powershell
$secure = Read-Host 'PostgreSQL password' -AsSecureString
$env:PG_REGISTRATION_PASSWORD = [Net.NetworkCredential]::new('', $secure).Password
$settings = @{
    Server = 'your-server'
    Port = 5432
    Database = 'KimbalHES'
    Username = 'your-user'
    Schema = 'kimbaldb_dbo'
    CsvPath = 'C:\exports\meters.csv'
    TemplateId = 93
    Category = 'D1'
    CapturePeriod = 15
    GatewayId = 'direct_4g'
    SinkId = 'direct_4g'
    ReportDirectory = 'C:\exports\registration-report'
}
try {
    ./deploy/register-postgres-meters.ps1 @settings       # dry run
    ./deploy/register-postgres-meters.ps1 @settings -Apply
} finally { Remove-Item Env:PG_REGISTRATION_PASSWORD }
```

TLS is required by default. Use `-SslMode VerifyFull` for certificate/hostname verification or explicitly choose `-SslMode Disable` only for a server configured without TLS.

Use `-PreserveExistingRoutes` when the target server already has intentional gateway/sink assignments for these nodes. This reuses those routes without changing their values; new routes still use `-GatewayId` and `-SinkId`. Without this option, a different existing gateway/sink is reported as a conflict. Duplicate routing rows remain conflicts in either mode.

The CSV must have `nodeid`, `serial`, and `nic` columns (`nic=MqttWirepas`); additional exported columns are accepted. Duplicate node IDs or serials fail before database changes. Data goes to temporary staging tables using COPY. Template existence is checked first. Conflicting identities, category/template/period settings, security, or gateway routes are excluded consistently from all three inserts and reported in `conflicts.csv`.

`-Apply` briefly locks the three registration tables against concurrent writers, with a 15-second lock timeout. It inserts missing records, verifies complete registrations, then commits one transaction. Existing matching records are reused; existing conflicts are never overwritten. A failure rolls back inserts. Identity sequences can advance during a rolled-back attempt. Re-running is safe and reports already-present registrations rather than duplicating them.

The security values are the repository's simulator defaults (`AAAAAAAAAAAAAAAA`, LLS `12345678`), not physical-meter keys. Capture period defaults to 15 minutes to match the current simulator. For another period/category, configure the simulator consistently; D2/D3 registration alone does not enable per-meter category selection in the simulator. New routes use the registration timestamp as their initial communication timestamp, following the LHES loader convention; this is not proof of meter communication.

`summary.json` records the target, CSV hash, input/conflict counts, applied/dry-run state, planned inserts, category, template, and period. Registration does not change the simulator's broker connection or start commands.
