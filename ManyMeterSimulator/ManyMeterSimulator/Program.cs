using ManyMeterSimulator.Auth;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Components;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Mqtt.Codecs;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using MudBlazor.Services;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Persistent, deploy-surviving folders live in the PARENT of the deployment folder (the content
// root), so a redeploy that replaces the app folder never touches logs/ or data/. Layout:
//   <sim-root>/
//     <deployment>/   ← app content root, refreshed on every deploy
//     logs/           ← persistent (this)
//     data/           ← persistent (see PersistenceOptions)
// Resolved against the content root (not the CWD) so it's correct however the app is launched;
// created here if missing, so first deployment needs no manual folder setup.
string logDirectory = Path.GetFullPath(Path.Combine(builder.Environment.ContentRootPath, "..", "logs"));
Directory.CreateDirectory(logDirectory);

// A runtime-adjustable minimum level: the live-logs UI's "Include debug" toggle flips this between
// Information (default) and Debug, so Debug events are only ever generated on demand. The bounded
// in-memory broadcaster backs the live-logs page.
var logLevelSwitch = new Serilog.Core.LoggingLevelSwitch(Serilog.Events.LogEventLevel.Information);
var logBroadcaster = new LogBroadcaster(1000);
builder.Services.AddSingleton(logLevelSwitch);
builder.Services.AddSingleton(logBroadcaster);

builder.Services.AddSerilog((_, loggerConfiguration) => loggerConfiguration
    .MinimumLevel.ControlledBy(logLevelSwitch)
    // Keep framework namespaces at Information even when the switch is raised to Debug, so the UI's
    // "Include debug" only reveals OUR debug (ManyMeterSimulator + MeterSimulator.Core) — not Blazor's
    // per-render "Rendering component N" spam or other Microsoft/System internals.
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Information)
    .MinimumLevel.Override("System", Serilog.Events.LogEventLevel.Information)
    .Enrich.FromLogContext()
    // Console stays at Information even when the switch is raised to Debug, so journald isn't flooded.
    .WriteTo.Console(
        restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Information,
        outputTemplate: "[{Timestamp:HH:mm:ss.fff} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    // File keeps ONLY Warning+ to bound disk growth (console/journald and the live-logs UI still
    // carry the full Information stream). Chatty per-frame/per-build lines are Debug now, so at the
    // default Information level they don't reach any sink unless the UI toggle raises the switch.
    .WriteTo.File(
        Path.Combine(logDirectory, "nicsim-.log"),
        restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Warning,
        rollingInterval: RollingInterval.Day,
        outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    // Live-logs UI stream — receives whatever the switch currently allows.
    .WriteTo.Sink(new LogBroadcastSink(logBroadcaster)));

builder.Services.Configure<TcpOptions>(builder.Configuration.GetSection(TcpOptions.SectionName));
builder.Services.Configure<SessionMaintenanceOptions>(builder.Configuration.GetSection(SessionMaintenanceOptions.SectionName));
builder.Services.Configure<NicsOptions>(builder.Configuration.GetSection(NicsOptions.SectionName));
builder.Services.Configure<SimulatedBridgeOptions>(builder.Configuration.GetSection(SimulatedBridgeOptions.SectionName));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
builder.Services.Configure<TemplateOptions>(builder.Configuration.GetSection(TemplateOptions.SectionName));
builder.Services.Configure<BrainOptions>(builder.Configuration.GetSection(BrainOptions.SectionName));
builder.Services.Configure<PushOptions>(builder.Configuration.GetSection(PushOptions.SectionName));
builder.Services.Configure<PersistenceOptions>(builder.Configuration.GetSection(PersistenceOptions.SectionName));
builder.Services.Configure<NetworkDelayOptions>(builder.Configuration.GetSection(NetworkDelayOptions.SectionName));
builder.Services.Configure<NetworkHealthOptions>(builder.Configuration.GetSection(NetworkHealthOptions.SectionName));

// The meter IP prefix is a per-deployment infrastructure value — it must match the IPv6 /64 routed
// to THIS host. Validate it early so a misconfigured/typo'd/missing prefix fails fast with a clear
// message instead of the app silently running on the wrong (or example) prefix. Override per server
// via appsettings.Production.json or the environment variable Tcp__AddressPrefix.
string configuredPrefix = builder.Configuration.GetValue<string>("Tcp:AddressPrefix") ?? string.Empty;
if (!MeterAddressing.TryValidatePrefix(configuredPrefix, out string prefixError))
{
    throw new InvalidOperationException(
        $"Invalid Tcp:AddressPrefix — {prefixError}. Set it (per deployment) in appsettings.json / " +
        "appsettings.Production.json or via the environment variable Tcp__AddressPrefix, to the IPv6 " +
        "/64 routed to this host.");
}

// The host's own shutdown timeout must comfortably exceed Tcp:ShutdownDrainSeconds, or the
// host will abandon ExecuteAsync (killing in-flight sessions) before the drain window we
// implement ourselves ever gets to run.
int shutdownDrainSeconds = builder.Configuration.GetValue("Tcp:ShutdownDrainSeconds", 10);
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(shutdownDrainSeconds + 5));

builder.Services.AddSingleton<SessionRegistry>();
builder.Services.AddSingleton<SimulatorMetrics>();
builder.Services.AddSingleton<MeterAdmission>();

// Operator-set runtime knobs (network delay today, more later), persisted alongside — but
// deliberately not inside — the batch store. Registered before NetworkDelaySettings, which
// rehydrates from it on construction.
builder.Services.AddSingleton<IRuntimeConfigStore, JsonRuntimeConfigStore>();
// Singleton so the Setup page and the listener share one instance — that shared reference is
// what makes a delay change take effect on the next exchange without a restart.
builder.Services.AddSingleton<NetworkDelaySettings>();
// Field-impairment simulation. Also persisted, and also read from the listener's hot path, so it
// must be the same instance the BadComm page mutates.
builder.Services.AddSingleton<BadCommSettings>();
// Durable batch store first — MeterRegistry rehydrates from it on construction, so batches,
// their status, and the allocation cursor survive restarts/reboots/redeployments.
builder.Services.AddSingleton<IBatchStore, JsonBatchStore>();
builder.Services.AddSingleton<MeterRegistry>();

// ── Network registry ─────────────────────────────────────────────────────────────────────────
// Named, validated MQTT brokers and HES push targets that batches bind to (network_registry.md).
// The key ring is pinned to data/keys/ rather than left at its per-user default: broker passwords
// are encrypted with it, and a redeploy under a different service account would otherwise render
// every stored password undecryptable — surfacing much later as a broker that will not
// authenticate. It sits beside data/batches.json, so the same "survives a redeploy" rule covers it.
string dataFolder = builder.Configuration.GetValue("Persistence:Folder", "../data") ?? "../data";
string keyRingPath = Path.GetFullPath(Path.Combine(
    Path.IsPathRooted(dataFolder) ? dataFolder : Path.Combine(builder.Environment.ContentRootPath, dataFolder),
    builder.Configuration.GetValue("Persistence:KeyRingFolderName", "keys") ?? "keys"));
Directory.CreateDirectory(keyRingPath);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keyRingPath))
    .SetApplicationName("ManyMeterSimulator");

builder.Services.AddSingleton<ISecretProtector, DataProtectionSecretProtector>();
builder.Services.AddSingleton<INetworkRegistryStore, JsonNetworkRegistryStore>();
builder.Services.AddSingleton<EndpointProber>();
builder.Services.AddSingleton<NetworkRegistry>();
// Registered after MeterRegistry: it is the one place that sees both registries, which is what
// lets neither of them depend on the other.
builder.Services.AddSingleton<NetworkBindingValidator>();
// Depends on both MeterRegistry and BadCommSettings, so it is registered after the batch store.
builder.Services.AddSingleton<FleetCompositionCache>();
builder.Services.AddSingleton<TemplateRegistry>();
builder.Services.AddSingleton<MeterSessionManager>();
builder.Services.AddSingleton<PushCoordinator>();

// Bridge selection: the real in-process brain (default) or the echo stand-in (framing only).
string bridgeMode = builder.Configuration.GetValue("Brain:Mode", "Brain") ?? "Brain";
if (string.Equals(bridgeMode, "Simulated", StringComparison.OrdinalIgnoreCase))
{
    builder.Services.AddSingleton<IMeterSimBridge, SimulatedMeterSimBridge>();
}
else
{
    builder.Services.AddSingleton<IMeterSimBridge, BrainMeterSimBridge>();
}

builder.Services.AddHostedService<TcpNicListenerService>();
// NIC-agnostic housekeeping (idle reaping + metrics summary) — serves every NIC, not just TCP.
builder.Services.AddHostedService<SessionMaintenanceService>();

// ── MQTT NICs ────────────────────────────────────────────────────────────────────────────────
// One codec per variant. The direct-4G codec serves both c and d (same broker, topics and framing
// — the difference is meter hardware, not wire protocol). Wirepas/Kmesh carry their node id inside
// a protobuf payload, so until Phase F/G they can only subscribe and capture, not route.
builder.Services.AddSingleton<NicCaptureWriter>();
// A factory rather than three singletons: each broker binding needs its OWN codec instance, because
// Wirepas reassembles inbound fragments in per-instance state and two brokers sharing one codec
// would interleave their fragments into a single buffer (network_registry.md §5.4).
builder.Services.AddSingleton<NicCodecFactory>();
builder.Services.AddSingleton<MqttNicListenerService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<MqttNicListenerService>());

// Registered after the listener: for a broker that is IN USE the monitor reports that client's live
// status rather than probing, since a probe can succeed while the real client is stuck in backoff.
builder.Services.AddSingleton<NetworkHealthMonitor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<NetworkHealthMonitor>());

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddMudServices();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

// Route the Core library's diagnostics (formerly Console.WriteLine) through the same ILogger/Serilog
// pipeline as everything else, so they obey the level rules and show up in the live-logs UI.
MeterSimulator.Diagnostics.CoreLog.Configure(
    app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("MeterSimulator.Core"));

// ── Network registry: connect the two registries, then migrate once ──────────────────────────
// Done here rather than in a constructor because it is the first point at which both exist. The
// validator is the only object that sees both, so neither registry needs to know about the other.
{
    var networkRegistry = app.Services.GetRequiredService<NetworkRegistry>();
    var meterRegistry = app.Services.GetRequiredService<MeterRegistry>();
    networkRegistry.SetUsageSource(app.Services.GetRequiredService<NetworkBindingValidator>());

    // A batch store written before the registry existed was, by definition, talking to the single
    // configured broker — bind those batches to the seeded entry so an upgrade keeps working. The
    // schema version is bumped either way, so this decision happens exactly once and a later
    // deliberately-unbound batch is never silently bound (network_registry.md §3.2).
    string? defaultKey = networkRegistry.Broker(NetworkRegistry.DefaultBrokerKey) is null
        ? null
        : NetworkRegistry.DefaultBrokerKey;

    int migrated = meterRegistry.MigrateLegacyBindings(defaultKey);
    if (migrated > 0)
    {
        app.Services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("ManyMeterSimulator.Networking.Registry")
            .LogInformation(
                "Bound {Count} pre-registry MQTT batch(es) to broker '{Broker}'. Change them on the Network page.",
                migrated, defaultKey);
    }
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

// MapStaticAssets rather than UseStaticFiles: it content-hashes each asset at build time and
// serves it with a fingerprinted URL, so a CSS or JS change reaches browsers immediately.
// With UseStaticFiles the URL never changed, so an updated site.css sat behind the browser cache
// and the page rendered new markup against old styles.
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapAuthEndpoints();
app.MapBatchEndpoints();

app.MapStaticAssets();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
