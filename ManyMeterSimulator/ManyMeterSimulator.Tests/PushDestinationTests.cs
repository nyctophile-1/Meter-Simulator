using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Where a batch's push goes now that push targets are registry rows: the binding is the default,
/// the dashboard box is the override (network_registry.md §6).
///
/// <para>
/// These exercise the resolution rules only — every case here fails before any socket is opened,
/// so no meters are materialized and nothing is sent.
/// </para>
/// </summary>
public class PushDestinationTests
{
    private const string Tpl = "test-template.xml";

    private static (PushCoordinator Push, MeterRegistry Batches, NetworkRegistry Network) NewPair()
    {
        var batches = new MeterRegistry();
        var network = new NetworkRegistry();
        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestEnvironment(),
            NullLogger<TemplateRegistry>.Instance);

        var sessions = new MeterSessionManager(
            batches,
            templates,
            Options.Create(new BrainOptions()),
            Options.Create(new ManyMeterSimulator.Networking.TcpOptions { AddressPrefix = "fd00:6d65:7472::/64" }),
            NullLogger<MeterSessionManager>.Instance);

        var push = new PushCoordinator(
            batches, sessions, network, Options.Create(new PushOptions()), NullLogger<PushCoordinator>.Instance);

        return (push, batches, network);
    }

    [Fact]
    public async Task ATcpBatchWithNoTargetAndNoTypedDestination_SaysSo()
    {
        (PushCoordinator push, MeterRegistry batches, _) = NewPair();
        MeterBatch batch = batches.AddBatch("b1", Tpl, 1, NicType.Tcp4G);

        PushBatchResult result = await push.PushBatchAsync(batch.Id);

        Assert.False(result.Ok);
        Assert.Contains("no push target bound", result.Error);
    }

    [Fact]
    public async Task ABatchBoundToAMissingTarget_SaysWhichKey()
    {
        (PushCoordinator push, MeterRegistry batches, _) = NewPair();
        MeterBatch batch = batches.AddBatch("b1", Tpl, 1, NicType.Tcp4G, null, null, "deleted");

        PushBatchResult result = await push.PushBatchAsync(batch.Id);

        Assert.False(result.Ok);
        Assert.Contains("deleted", result.Error);
    }

    /// <summary>
    /// Disabling means "stop talking to this". Honouring it for MQTT but ignoring it for push would
    /// make one toggle mean two different things on the same page.
    /// </summary>
    [Fact]
    public async Task ADisabledTarget_IsRefused()
    {
        (PushCoordinator push, MeterRegistry batches, NetworkRegistry network) = NewPair();
        network.AddPushTarget(new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1" }, verified: true);
        network.SetPushTargetEnabled("hes-1", false);
        MeterBatch batch = batches.AddBatch("b1", Tpl, 1, NicType.Tcp4G, null, null, "hes-1");

        PushBatchResult result = await push.PushBatchAsync(batch.Id);

        Assert.False(result.Ok);
        Assert.Contains("disabled", result.Error);
    }

    [Fact]
    public async Task AnMqttBatch_IsStillRefusedOutright()
    {
        (PushCoordinator push, MeterRegistry batches, _) = NewPair();
        MeterBatch batch = batches.AddBatch("b1", Tpl, 1, NicType.Mqtt4G, null, "eqa");

        PushBatchResult result = await push.PushBatchAsync(batch.Id, "[fd00::1]:4059");

        Assert.False(result.Ok);
        Assert.Contains("4G TCP", result.Error);
    }

    [Fact]
    public void BoundTarget_RendersTheBracketedFormPushCoordinatorParses()
    {
        var target = new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1", Port = 4059 };

        Assert.Equal("[fd00::1]:4059", target.Destination);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string ApplicationName { get; set; } = "tests";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public string EnvironmentName { get; set; } = "Test";
    }
}
