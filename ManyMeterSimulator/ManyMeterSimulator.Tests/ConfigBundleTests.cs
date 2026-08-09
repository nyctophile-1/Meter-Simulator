using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The migration path: the whole operator config (batches + endpoints) exports to one file and
/// re-imports on another deployment, so a fleet does not have to be re-registered with the HES by
/// hand (network_registry.md §6 / config migration).
/// </summary>
public class ConfigBundleTests
{
    private const string Tpl = "test-template.xml";

    private static (ConfigBundleService Svc, MeterRegistry Batches, NetworkRegistry Network) NewDeployment()
    {
        var batches = new MeterRegistry();
        var network = new NetworkRegistry();
        return (new ConfigBundleService(batches, network), batches, network);
    }

    private static void Seed(MeterRegistry batches, NetworkRegistry network)
    {
        network.AddBroker(new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1", Username = "meter", Password = "s3cret" }, verified: true);
        network.AddPushTarget(new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1", Port = 4059 }, verified: true);
        batches.AddBatch("mqtt-a", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        batches.AddBatch("tcp-a", Tpl, 100, NicType.Tcp4G, null, null, "hes-1");
    }

    [Fact]
    public void ExportThenImportOnAFreshDeployment_ReproducesEverything()
    {
        (ConfigBundleService source, MeterRegistry sb, NetworkRegistry sn) = NewDeployment();
        Seed(sb, sn);
        string json = source.Export("source-host");

        (ConfigBundleService dest, MeterRegistry db, NetworkRegistry dn) = NewDeployment();
        ConfigImportSummary summary = dest.Import(json);

        Assert.Equal(2, summary.Batches);
        Assert.Equal(1, summary.Brokers);
        Assert.Equal(1, summary.PushTargets);
        Assert.Equal("source-host", summary.ExportedFrom);

        Assert.Equal(new[] { "mqtt-a", "tcp-a" }, db.Batches.Select(b => b.Name).OrderBy(n => n));
        Assert.Equal("eqa", db.Batches.Single(b => b.Name == "mqtt-a").BrokerKey);
        Assert.Equal("hes-1", db.Batches.Single(b => b.Name == "tcp-a").PushTargetKey);
        Assert.NotNull(dn.Broker("eqa"));
        // Plaintext password travels in the bundle, so it lands intact on the destination.
        Assert.Equal("s3cret", dn.Broker("eqa")!.Password);
        Assert.NotNull(dn.PushTarget("hes-1"));
    }

    /// <summary>
    /// After importing, the next batch must continue past the imported set — otherwise it would
    /// reissue node ids / addresses the HES already knows, the collision the whole store guards.
    /// </summary>
    [Fact]
    public void Import_ResetsTheAllocationCursorToContinuePastTheImportedBatches()
    {
        (ConfigBundleService source, MeterRegistry sb, NetworkRegistry sn) = NewDeployment();
        Seed(sb, sn);                       // indices 1-10 and 11-110 → next is 111
        string json = source.Export();

        (ConfigBundleService dest, MeterRegistry db, NetworkRegistry _) = NewDeployment();
        dest.Import(json);

        MeterBatch next = db.AddBatch("after-import", Tpl, 5, NicType.Tcp4G);
        Assert.Equal(111, next.StartIndex);
        Assert.All(db.Batches, b => Assert.True(b.Name == "after-import" || b.StartIndex < 111));
    }

    [Fact]
    public void Import_ReplacesRatherThanMerges()
    {
        (ConfigBundleService source, MeterRegistry sb, NetworkRegistry sn) = NewDeployment();
        Seed(sb, sn);
        string json = source.Export();

        (ConfigBundleService dest, MeterRegistry db, NetworkRegistry dn) = NewDeployment();
        db.AddBatch("pre-existing", Tpl, 7, NicType.Tcp4G);
        dn.AddBroker(new BrokerEndpoint { Key = "old-broker", Host = "1.2.3.4" }, verified: false);

        dest.Import(json);

        // The pre-existing batch and broker are gone — import is wholesale, not additive.
        Assert.DoesNotContain(db.Batches, b => b.Name == "pre-existing");
        Assert.Null(dn.Broker("old-broker"));
    }

    [Fact]
    public void Import_RejectsGarbage()
    {
        (ConfigBundleService svc, _, _) = NewDeployment();

        Assert.Throws<ArgumentException>(() => svc.Import("{ not json"));
    }

    /// <summary>Names are the cross-deployment identity, so a duplicate is ambiguous and refused.</summary>
    [Fact]
    public void Import_RejectsDuplicateBatchNames()
    {
        (ConfigBundleService svc, _, _) = NewDeployment();
        // PascalCase to match the (policy-free) serializer the service uses.
        string json = """
            {
              "Batches": {
                "Batches": [
                  { "Id": 1, "Name": "dupe", "TemplateName": "t.xml", "NicType": "Tcp4G", "StartIndex": 1, "Count": 5 },
                  { "Id": 2, "Name": "dupe", "TemplateName": "t.xml", "NicType": "Tcp4G", "StartIndex": 6, "Count": 5 }
                ]
              },
              "Network": {}
            }
            """;

        ArgumentException ex = Assert.Throws<ArgumentException>(() => svc.Import(json));
        Assert.Contains("dupe", ex.Message);
    }

    [Fact]
    public void Preview_DoesNotApply()
    {
        (ConfigBundleService source, MeterRegistry sb, NetworkRegistry sn) = NewDeployment();
        Seed(sb, sn);
        string json = source.Export();

        (ConfigBundleService dest, MeterRegistry db, NetworkRegistry dn) = NewDeployment();
        ConfigImportSummary preview = dest.Preview(json);

        Assert.Equal(2, preview.Batches);
        // Nothing was actually written.
        Assert.Empty(db.Batches);
        Assert.Empty(dn.Brokers);
    }
}
