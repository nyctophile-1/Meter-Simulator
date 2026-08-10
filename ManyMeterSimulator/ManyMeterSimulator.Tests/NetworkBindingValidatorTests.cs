using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class NetworkBindingValidatorTests
{
    private const string Tpl = "test-template.xml";

    private static (NetworkBindingValidator Validator, NetworkRegistry Network, MeterRegistry Batches) NewPair()
    {
        var network = new NetworkRegistry();
        var batches = new MeterRegistry();
        var validator = new NetworkBindingValidator(network, batches);
        network.SetUsageSource(validator);

        network.AddBroker(new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1" }, verified: true);
        network.AddPushTarget(new PushTargetEndpoint { Key = "hes-1", Address = "fd00::1" }, verified: true);

        return (validator, network, batches);
    }

    [Fact]
    public void NullKeys_AreAlwaysValid()
    {
        (NetworkBindingValidator validator, _, _) = NewPair();

        Assert.True(validator.Validate(NicType.Mqtt4G, null, null, out _));
        Assert.True(validator.Validate(NicType.Tcp4G, null, null, out _));
    }

    [Fact]
    public void KnownKeysOfTheRightKind_AreValid()
    {
        (NetworkBindingValidator validator, _, _) = NewPair();

        Assert.True(validator.Validate(NicType.Mqtt4G, "eqa", null, out _));
        Assert.True(validator.Validate(NicType.MqttWirepas, "eqa", null, out _));
        Assert.True(validator.Validate(NicType.Tcp4G, null, "hes-1", out _));
    }

    [Fact]
    public void UnknownBrokerKey_IsRejected()
    {
        (NetworkBindingValidator validator, _, _) = NewPair();

        Assert.False(validator.Validate(NicType.Mqtt4G, "nope", null, out string error));
        Assert.Contains("nope", error);
    }

    [Fact]
    public void AnyBatch_CanBindToAnEnvironmentKey()
    {
        // In the unified environment model, any NIC type can bind to an environment key;
        // the coordinator picks the TCP or MQTT half at push/pull time.
        (NetworkBindingValidator validator, NetworkRegistry network, _) = NewPair();
        network.AddBroker(new BrokerEndpoint { Key = "eqa", Host = "10.0.0.1" }, verified: true);

        Assert.True(validator.Validate(NicType.Tcp4G, "eqa", null, out _));
        Assert.True(validator.Validate(NicType.Mqtt4G, "eqa", null, out _));
    }

    /// <summary>
    /// The delete guard, end to end: the registry refuses through the usage source rather than
    /// knowing about batches itself.
    /// </summary>
    [Fact]
    public void DeletingABoundBroker_IsRefusedAndNamesTheBatch()
    {
        (_, NetworkRegistry network, MeterRegistry batches) = NewPair();
        batches.AddBatch("field-trial", Tpl, 10, NicType.Mqtt4G, null, "eqa");

        Assert.False(network.TryDeleteBroker("eqa", out string error));
        Assert.Contains("field-trial", error);
    }

    [Fact]
    public void DeletingABrokerAfterRebinding_Succeeds()
    {
        (_, NetworkRegistry network, MeterRegistry batches) = NewPair();
        MeterBatch batch = batches.AddBatch("field-trial", Tpl, 10, NicType.Mqtt4G, null, "eqa");

        batches.SetNetworkBinding(batch.Id, null, null);

        Assert.True(network.TryDeleteBroker("eqa", out _));
    }

    [Fact]
    public void IsUnreachable_OnlyForARunningMqttBatchWithNoBroker()
    {
        var registry = new MeterRegistry();
        MeterBatch unbound = registry.AddBatch("mqtt-unbound", Tpl, 10, NicType.Mqtt4G);
        MeterBatch bound = registry.AddBatch("mqtt-bound", Tpl, 10, NicType.Mqtt4G, null, "eqa");
        MeterBatch tcp = registry.AddBatch("tcp", Tpl, 10, NicType.Tcp4G);

        // Not started yet — unbound is not yet a problem.
        Assert.False(NetworkBindingValidator.IsUnreachable(unbound));

        registry.TryStart(unbound.Id);
        registry.TryStart(bound.Id);
        registry.TryStart(tcp.Id);

        Assert.True(NetworkBindingValidator.IsUnreachable(unbound));
        Assert.False(NetworkBindingValidator.IsUnreachable(bound));
        // TCP needs no broker — it is reachable regardless.
        Assert.False(NetworkBindingValidator.IsUnreachable(tcp));
    }
}
