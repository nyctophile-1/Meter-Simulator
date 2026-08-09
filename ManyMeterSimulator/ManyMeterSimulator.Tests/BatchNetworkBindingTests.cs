using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Phase 2 of network_registry.md: batches carry two nullable registry keys, null means unbound,
/// and a pre-registry store migrates onto the seeded default broker exactly once.
/// </summary>
public class BatchNetworkBindingTests
{
    private const string Tpl = "test-template.xml";

    [Fact]
    public void AddBatch_WithNoKeys_IsUnbound()
    {
        var registry = new MeterRegistry();

        MeterBatch batch = registry.AddBatch("b1", Tpl, 10, NicType.Mqtt4G);

        Assert.Null(batch.BrokerKey);
        Assert.Null(batch.PushTargetKey);
    }

    [Fact]
    public void AddBatch_WithBothKeysNull_IsLegal()
    {
        var registry = new MeterRegistry();

        MeterBatch batch = registry.AddBatch("b1", Tpl, 10, NicType.Tcp4G, null, null, null);

        Assert.Null(batch.BrokerKey);
        Assert.Null(batch.PushTargetKey);
    }

    /// <summary>Unbound must be one state, not three that compare differently against a key.</summary>
    [Fact]
    public void AddBatch_BlankKeys_NormalizeToNull()
    {
        var registry = new MeterRegistry();

        MeterBatch batch = registry.AddBatch("b1", Tpl, 10, NicType.Mqtt4G, null, "   ", "");

        Assert.Null(batch.BrokerKey);
        Assert.Null(batch.PushTargetKey);
    }

    [Fact]
    public void SetNetworkBinding_RebindsAndReportsChange()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", Tpl, 10, NicType.Mqtt4G, null, "eqa");

        Assert.True(registry.SetNetworkBinding(batch.Id, "pune", null));
        Assert.Equal("pune", registry.Batches.Single().BrokerKey);

        // Same values again — nothing changed, so the caller can skip the reconcile.
        Assert.False(registry.SetNetworkBinding(batch.Id, "pune", null));
    }

    [Fact]
    public void SetNetworkBinding_ToNull_Unbinds()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", Tpl, 10, NicType.Mqtt4G, null, "eqa");

        Assert.True(registry.SetNetworkBinding(batch.Id, null, null));
        Assert.Null(registry.Batches.Single().BrokerKey);
    }

    [Fact]
    public void BatchesUsingBroker_NamesTheBoundBatches()
    {
        var registry = new MeterRegistry();
        registry.AddBatch("b1", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        registry.AddBatch("b2", Tpl, 10, NicType.MqttWirepas, null, "EQA");   // case-insensitive
        registry.AddBatch("b3", Tpl, 10, NicType.Mqtt4G, null, "pune");

        Assert.Equal(new[] { "b1", "b2" }, registry.BatchesUsingBroker("eqa"));
        Assert.Empty(registry.BatchesUsingBroker("never-used"));
    }

    [Fact]
    public void Bindings_SurviveAStoreRoundTrip()
    {
        var store = new InMemoryBatchStore();
        var first = new MeterRegistry(store);
        first.AddBatch("b1", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        first.AddBatch("b2", Tpl, 10, NicType.Tcp4G, null, null, "hes-1");

        var reloaded = new MeterRegistry(store);

        Assert.Equal("eqa", reloaded.Batches[0].BrokerKey);
        Assert.Equal("hes-1", reloaded.Batches[1].PushTargetKey);
    }

    // ── Migration ────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// A pre-registry store (no Version, no keys) was by definition talking to the one configured
    /// broker, so its MQTT batches bind to the seeded default rather than silently going unbound.
    /// </summary>
    [Fact]
    public void MigrateLegacyBindings_BindsMqttBatchesOnly()
    {
        var store = new InMemoryBatchStore(LegacySnapshot());
        var registry = new MeterRegistry(store);

        int bound = registry.MigrateLegacyBindings("default");

        Assert.Equal(2, bound);
        Assert.Equal("default", registry.Batches.Single(b => b.Name == "mqtt-a").BrokerKey);
        Assert.Equal("default", registry.Batches.Single(b => b.Name == "wirepas-a").BrokerKey);
        // TCP is broker-agnostic — it must not acquire one.
        Assert.Null(registry.Batches.Single(b => b.Name == "tcp-a").BrokerKey);
    }

    [Fact]
    public void MigrateLegacyBindings_RunsOnlyOnce()
    {
        var store = new InMemoryBatchStore(LegacySnapshot());
        var registry = new MeterRegistry(store);

        Assert.Equal(2, registry.MigrateLegacyBindings("default"));
        Assert.Equal(0, registry.MigrateLegacyBindings("default"));
    }

    [Fact]
    public void MigrateLegacyBindings_AfterARestart_DoesNotRunAgain()
    {
        var store = new InMemoryBatchStore(LegacySnapshot());
        new MeterRegistry(store).MigrateLegacyBindings("default");

        // Restart. The version is persisted, so an operator who later unbinds a batch by hand does
        // not find it silently rebound on the next start.
        var reloaded = new MeterRegistry(store);
        reloaded.SetNetworkBinding(reloaded.Batches.Single(b => b.Name == "mqtt-a").Id, null, null);

        var afterRestart = new MeterRegistry(store);
        Assert.Equal(0, afterRestart.MigrateLegacyBindings("default"));
        Assert.Null(afterRestart.Batches.Single(b => b.Name == "mqtt-a").BrokerKey);
    }

    /// <summary>
    /// No configured broker to migrate onto: nothing is bound, but the decision is still recorded,
    /// so adding a broker named "default" later cannot retroactively bind old batches.
    /// </summary>
    [Fact]
    public void MigrateLegacyBindings_WithNoDefaultBroker_StillMarksTheStoreMigrated()
    {
        var store = new InMemoryBatchStore(LegacySnapshot());
        var registry = new MeterRegistry(store);

        Assert.Equal(0, registry.MigrateLegacyBindings(null));
        Assert.Null(registry.Batches.Single(b => b.Name == "mqtt-a").BrokerKey);
        Assert.Equal(0, registry.MigrateLegacyBindings("default"));
    }

    private static BatchStoreSnapshot LegacySnapshot() => new()
    {
        // Version deliberately absent — this is what a file written before the feature looks like.
        NextIndex = 31,
        NextBatchId = 4,
        Batches =
        {
            new PersistedBatch { Id = 1, Name = "mqtt-a", TemplateName = Tpl, NicType = NicType.Mqtt4G, StartIndex = 1, Count = 10 },
            new PersistedBatch { Id = 2, Name = "wirepas-a", TemplateName = Tpl, NicType = NicType.MqttWirepas, StartIndex = 11, Count = 10 },
            new PersistedBatch { Id = 3, Name = "tcp-a", TemplateName = Tpl, NicType = NicType.Tcp4G, StartIndex = 21, Count = 10 },
        },
    };

    /// <summary>A store that keeps the snapshot in memory, so a "restart" is just a new registry.</summary>
    private sealed class InMemoryBatchStore : IBatchStore
    {
        private BatchStoreSnapshot _snapshot;

        public InMemoryBatchStore(BatchStoreSnapshot? initial = null) => _snapshot = initial ?? new BatchStoreSnapshot();

        public BatchStoreSnapshot Load() => _snapshot;

        public void Save(BatchStoreSnapshot snapshot) => _snapshot = snapshot;
    }
}
