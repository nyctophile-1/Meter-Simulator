using ManyMeterSimulator.Auth;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Components;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Provisioning;
using Microsoft.AspNetCore.Authentication.Cookies;
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
builder.Services.Configure<SimulatedBridgeOptions>(builder.Configuration.GetSection(SimulatedBridgeOptions.SectionName));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));
builder.Services.Configure<TemplateOptions>(builder.Configuration.GetSection(TemplateOptions.SectionName));
builder.Services.Configure<BrainOptions>(builder.Configuration.GetSection(BrainOptions.SectionName));
builder.Services.Configure<PersistenceOptions>(builder.Configuration.GetSection(PersistenceOptions.SectionName));
builder.Services.Configure<ExchangeDelayOptions>(builder.Configuration.GetSection(ExchangeDelayOptions.SectionName));

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

builder.Services.AddSingleton<ConnectionRegistry>();
builder.Services.AddSingleton<SimulatorMetrics>();
// Singleton so the Setup page and the listener share one instance — that shared reference is
// what makes a delay change take effect on the next exchange without a restart.
builder.Services.AddSingleton<ExchangeDelaySettings>();
// Durable batch store first — MeterRegistry rehydrates from it on construction, so batches,
// their status, and the allocation cursor survive restarts/reboots/redeployments.
builder.Services.AddSingleton<IBatchStore, JsonBatchStore>();
builder.Services.AddSingleton<MeterRegistry>();
builder.Services.AddSingleton<TemplateRegistry>();
builder.Services.AddSingleton<MeterSessionManager>();

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

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapAuthEndpoints();
app.MapBatchEndpoints();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
