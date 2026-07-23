using ManyMeterSimulator.Auth;
using ManyMeterSimulator.Components;
using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.MqttBridge;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Provisioning;
using Microsoft.AspNetCore.Authentication.Cookies;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSerilog((_, loggerConfiguration) => loggerConfiguration
    .MinimumLevel.Information()
    .Enrich.FromLogContext()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss.fff} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        "logs/nicsim-.log",
        rollingInterval: RollingInterval.Day,
        outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}"));

builder.Services.Configure<TcpOptions>(builder.Configuration.GetSection(TcpOptions.SectionName));
builder.Services.Configure<SimulatedBridgeOptions>(builder.Configuration.GetSection(SimulatedBridgeOptions.SectionName));
builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection(AuthOptions.SectionName));

// The host's own shutdown timeout must comfortably exceed Tcp:ShutdownDrainSeconds, or the
// host will abandon ExecuteAsync (killing in-flight sessions) before the drain window we
// implement ourselves ever gets to run.
int shutdownDrainSeconds = builder.Configuration.GetValue("Tcp:ShutdownDrainSeconds", 10);
builder.Services.Configure<HostOptions>(o => o.ShutdownTimeout = TimeSpan.FromSeconds(shutdownDrainSeconds + 5));

builder.Services.AddSingleton<ConnectionRegistry>();
builder.Services.AddSingleton<SimulatorMetrics>();
builder.Services.AddSingleton<MeterRegistry>();
builder.Services.AddSingleton<IMeterSimBridge, SimulatedMeterSimBridge>();
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

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapAuthEndpoints();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
