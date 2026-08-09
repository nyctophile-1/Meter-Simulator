using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The rule that replaced the old <c>Nics:&lt;x&gt;:Enabled</c> flags: a broker client exists when a
/// RUNNING MQTT batch references a PRESENT, ENABLED broker. Getting it wrong is silent in both
/// directions, so it is tested directly rather than inferred from a running listener.
/// </summary>
public class BrokerBindingPlannerTests
{
    private const string Tpl = "test-template.xml";

    private static BrokerEndpoint Enabled(string key) =>
        new() { Key = key, Host = $"{key}.example", Enabled = true };

    private static Func<string, BrokerEndpoint?> Registry(params BrokerEndpoint[] brokers) =>
        key => brokers.FirstOrDefault(b => string.Equals(b.Key, key, StringComparison.OrdinalIgnoreCase));

    private static MeterRegistry Fleet(params (string Name, NicType Nic, string? Broker, bool Running)[] batches)
    {
        var registry = new MeterRegistry();
        foreach ((string name, NicType nic, string? broker, bool running) in batches)
        {
            MeterBatch batch = registry.AddBatch(name, Tpl, 10, nic, null, broker);
            if (running)
            {
                registry.TryStart(batch.Id);
            }
        }

        return registry;
    }

    [Fact]
    public void OneClientPerBrokerPerTransport()
    {
        MeterRegistry fleet = Fleet(
            ("a", NicType.Mqtt4G, "eqa", true),
            ("b", NicType.Mqtt4G, "pune", true),
            ("c", NicType.MqttWirepas, "eqa", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(
            fleet.Batches, Registry(Enabled("eqa"), Enabled("pune")));

        Assert.Equal(3, plan.Desired.Count);
        Assert.Contains(new BrokerBinding(NicType.Mqtt4G, "eqa"), plan.Desired.Keys);
        Assert.Contains(new BrokerBinding(NicType.Mqtt4G, "pune"), plan.Desired.Keys);
        Assert.Contains(new BrokerBinding(NicType.MqttWirepas, "eqa"), plan.Desired.Keys);
    }

    [Fact]
    public void TwoBatchesOnOneBrokerAndTransport_ShareOneClient()
    {
        MeterRegistry fleet = Fleet(
            ("a", NicType.Mqtt4G, "eqa", true),
            ("b", NicType.Mqtt4G, "eqa", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry(Enabled("eqa")));

        Assert.Single(plan.Desired);
    }

    /// <summary>
    /// IMG folds into the direct-4G transport: same broker, topics and framing, so two clients
    /// would subscribe twice and receive every message twice.
    /// </summary>
    [Fact]
    public void ImgAnd4GOnOneBroker_ShareOneClient()
    {
        MeterRegistry fleet = Fleet(
            ("a", NicType.Mqtt4G, "eqa", true),
            ("b", NicType.Mqtt4GImg, "eqa", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry(Enabled("eqa")));

        BrokerBinding binding = Assert.Single(plan.Desired).Key;
        Assert.Equal(NicType.Mqtt4G, binding.Transport);
    }

    [Fact]
    public void ImgOnADifferentBrokerThan4G_GetsItsOwnClient()
    {
        MeterRegistry fleet = Fleet(
            ("a", NicType.Mqtt4G, "eqa", true),
            ("b", NicType.Mqtt4GImg, "pune", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(
            fleet.Batches, Registry(Enabled("eqa"), Enabled("pune")));

        Assert.Equal(2, plan.Desired.Count);
    }

    [Fact]
    public void ANotStartedBatch_ContributesNothing()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Mqtt4G, "eqa", false));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry(Enabled("eqa")));

        Assert.Empty(plan.Desired);
        // Not started is not "unreachable" — nobody expected it to answer yet.
        Assert.Empty(plan.Unreachable);
    }

    [Fact]
    public void ATcpBatch_ContributesNothing()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Tcp4G, null, true));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry());

        Assert.Empty(plan.Desired);
        Assert.Empty(plan.Unreachable);
    }

    [Fact]
    public void ARunningUnboundMqttBatch_IsReportedUnreachable()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Mqtt4G, null, true));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry());

        Assert.Empty(plan.Desired);
        Assert.Equal(UnreachableReason.Unbound, Assert.Single(plan.Unreachable).Reason);
    }

    [Fact]
    public void ABatchBoundToAMissingBroker_IsReportedUnreachable()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Mqtt4G, "deleted", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry(Enabled("eqa")));

        Assert.Empty(plan.Desired);
        Assert.Equal(UnreachableReason.MissingBroker, Assert.Single(plan.Unreachable).Reason);
    }

    /// <summary>The per-endpoint kill switch that replaced the per-transport config flag.</summary>
    [Fact]
    public void ADisabledBroker_ContributesNoBinding()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Mqtt4G, "eqa", true));
        var disabled = new BrokerEndpoint { Key = "eqa", Host = "eqa.example", Enabled = false };

        BindingPlan plan = BrokerBindingPlanner.Compute(fleet.Batches, Registry(disabled));

        Assert.Empty(plan.Desired);
        Assert.Equal(UnreachableReason.DisabledBroker, Assert.Single(plan.Unreachable).Reason);
    }

    [Fact]
    public void DisablingOneBroker_LeavesTheOthersRunning()
    {
        MeterRegistry fleet = Fleet(
            ("a", NicType.Mqtt4G, "eqa", true),
            ("b", NicType.Mqtt4G, "pune", true));

        BindingPlan plan = BrokerBindingPlanner.Compute(
            fleet.Batches,
            Registry(new BrokerEndpoint { Key = "eqa", Host = "x", Enabled = false }, Enabled("pune")));

        Assert.Equal(new BrokerBinding(NicType.Mqtt4G, "pune"), Assert.Single(plan.Desired).Key);
    }

    [Fact]
    public void StoppingTheLastBatchOnABroker_RemovesItsBinding()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("a", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        registry.TryStart(batch.Id);

        Assert.Single(BrokerBindingPlanner.Compute(registry.Batches, Registry(Enabled("eqa"))).Desired);

        registry.TryStop(batch.Id);

        Assert.Empty(BrokerBindingPlanner.Compute(registry.Batches, Registry(Enabled("eqa"))).Desired);
    }

    /// <summary>
    /// The kill switch is reversible: a disabled broker contributes nothing, and flipping it back on
    /// makes the running batch's binding reappear on the next reconcile — no restart.
    /// </summary>
    [Fact]
    public void ReEnablingABroker_BringsItsBindingBack()
    {
        MeterRegistry fleet = Fleet(("a", NicType.Mqtt4G, "eqa", true));
        var disabled = new BrokerEndpoint { Key = "eqa", Host = "x", Enabled = false };
        var enabled = new BrokerEndpoint { Key = "eqa", Host = "x", Enabled = true };

        Assert.Empty(BrokerBindingPlanner.Compute(fleet.Batches, Registry(disabled)).Desired);
        Assert.Single(BrokerBindingPlanner.Compute(fleet.Batches, Registry(enabled)).Desired);
    }

    /// <summary>
    /// Rebinding a running batch changes what the reconcile pass will act on: the old broker's
    /// binding disappears and the new one's appears, which is how live traffic follows the rebind.
    /// </summary>
    [Fact]
    public void RebindingARunningBatch_MovesTheDesiredBinding()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("a", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        registry.TryStart(batch.Id);

        Func<string, BrokerEndpoint?> lookup = Registry(Enabled("eqa"), Enabled("pune"));
        Assert.Equal(
            new BrokerBinding(NicType.Mqtt4G, "eqa"),
            Assert.Single(BrokerBindingPlanner.Compute(registry.Batches, lookup).Desired).Key);

        registry.SetNetworkBinding(batch.Id, "pune", null);

        Assert.Equal(
            new BrokerBinding(NicType.Mqtt4G, "pune"),
            Assert.Single(BrokerBindingPlanner.Compute(registry.Batches, lookup).Desired).Key);
    }
}
