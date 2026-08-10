using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The migration path: each setup page's config exports to its own file and re-imports on another
/// deployment, so a fleet does not have to be re-registered with the HES by hand. Three separate
/// files, each tagged so it cannot be imported on the wrong page.
/// </summary>
public class ConfigBundleTests
{
    private const string Tpl = "test-template.xml";

    private sealed class Deployment
    {
        public MeterRegistry Batches { get; } = new();
        public NetworkRegistry Network { get; } = new();
        public BadCommSettings BadComm { get; }
        public NetworkDelaySettings Delay { get; }
        public ConfigBundleService Svc { get; }

        public Deployment()
        {
            var store = new InMemoryRuntimeConfigStore();
            BadComm = new BadCommSettings(store);
            Delay = new NetworkDelaySettings(
                Microsoft.Extensions.Options.Options.Create(new NetworkDelayOptions()), store);
            Svc = new ConfigBundleService(Batches, Network, BadComm, Delay);
        }
    }

    private static void Seed(Deployment d)
    {
        d.Network.AddBroker(new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Username = "meter", Password = "s3cret" }, verified: true);
        d.Network.AddPushTarget(new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1", Port = 4059 }, verified: true);
        d.Batches.AddBatch("mqtt-a", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        d.Batches.AddBatch("tcp-a", Tpl, 100, NicType.Tcp4G, null, null, "hes-1");
    }

    // ── Batches ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Batches_ExportImport_ReproducesTheFleetAndBindings()
    {
        var src = new Deployment();
        Seed(src);
        string json = src.Svc.ExportBatches("host-a");

        var dst = new Deployment();
        int count = dst.Svc.ImportBatches(json);

        Assert.Equal(2, count);
        Assert.Equal(new[] { "mqtt-a", "tcp-a" }, dst.Batches.Batches.Select(b => b.Name).OrderBy(n => n));
        Assert.Equal("eqa", dst.Batches.Batches.Single(b => b.Name == "mqtt-a").BrokerKey);
        Assert.Equal("hes-1", dst.Batches.Batches.Single(b => b.Name == "tcp-a").PushTargetKey);
    }

    [Fact]
    public void Batches_Import_ResetsTheAllocationCursorPastTheImportedSet()
    {
        var src = new Deployment();
        Seed(src);                            // indices 1-10, 11-110 → next is 111
        string json = src.Svc.ExportBatches();

        var dst = new Deployment();
        dst.Svc.ImportBatches(json);

        Assert.Equal(111, dst.Batches.AddBatch("after", Tpl, 5, NicType.Tcp4G).StartIndex);
    }

    [Fact]
    public void Batches_Import_ReplacesRatherThanMerges()
    {
        var src = new Deployment();
        Seed(src);
        string json = src.Svc.ExportBatches();

        var dst = new Deployment();
        dst.Batches.AddBatch("pre-existing", Tpl, 7, NicType.Tcp4G);
        dst.Svc.ImportBatches(json);

        Assert.DoesNotContain(dst.Batches.Batches, b => b.Name == "pre-existing");
    }

    // ── Network ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Network_ExportImport_CarriesPlaintextPasswordAcross()
    {
        var src = new Deployment();
        Seed(src);
        string json = src.Svc.ExportNetwork();
        Assert.Contains("s3cret", json);   // portable: plaintext in the file

        var dst = new Deployment();
        (int envs, _) = dst.Svc.ImportNetwork(json);

        Assert.True(envs >= 1);
        Assert.Equal("s3cret", dst.Network.Broker("eqa")!.Password);
        Assert.NotNull(dst.Network.PushTarget("hes-1"));
    }

    // ── BadComm ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void BadComm_ExportImport_CarriesBothKnobs()
    {
        var src = new Deployment();
        src.BadComm.TryUpdate(new BadCommConfig { Enabled = true, Seed = 42 }, out _);
        src.Delay.TryUpdate(120, 340);
        string json = src.Svc.ExportBadComm();

        var dst = new Deployment();
        dst.Svc.ImportBadComm(json);

        Assert.True(dst.BadComm.Snapshot().Enabled);
        Assert.Equal(42, dst.BadComm.Snapshot().Seed);
        Assert.Equal(120, dst.Delay.Current.LowerMs);
        Assert.Equal(340, dst.Delay.Current.UpperMs);
    }

    // ── Cross-kind protection ────────────────────────────────────────────────────────────────────

    [Fact]
    public void ImportingANetworkFileOnTheBatchPage_IsRejected()
    {
        var d = new Deployment();
        Seed(d);
        string networkJson = d.Svc.ExportNetwork();

        ArgumentException ex = Assert.Throws<ArgumentException>(() => d.Svc.ImportBatches(networkJson));
        Assert.Contains("Network Setup", ex.Message);
    }

    [Fact]
    public void ImportingABatchesFileOnTheNetworkPage_IsRejected()
    {
        var d = new Deployment();
        Seed(d);
        string batchesJson = d.Svc.ExportBatches();

        Assert.Throws<ArgumentException>(() => d.Svc.ImportNetwork(batchesJson));
    }

    [Fact]
    public void Import_RejectsGarbage()
    {
        var d = new Deployment();
        Assert.Throws<ArgumentException>(() => d.Svc.ImportBatches("{ not json"));
    }

    [Fact]
    public void Preview_DoesNotApply()
    {
        var src = new Deployment();
        Seed(src);
        string json = src.Svc.ExportBatches();

        var dst = new Deployment();
        Assert.Equal(2, dst.Svc.PreviewBatches(json));
        Assert.Empty(dst.Batches.Batches);   // nothing written
    }

    /// <summary>In-memory <see cref="IRuntimeConfigStore"/> so BadComm/Delay need no file.</summary>
    private sealed class InMemoryRuntimeConfigStore : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();

        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }
}
