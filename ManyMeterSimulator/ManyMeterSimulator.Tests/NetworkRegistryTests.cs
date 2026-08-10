using ManyMeterSimulator.Networking.Registry;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class NetworkRegistryTests
{
    private static BrokerEndpoint Broker(string key = "eqa", string host = "10.0.0.1") =>
        new() { Key = key, Host = host, Port = 1883, Username = "meter", Password = "s3cret" };

    private static PushTargetEndpoint PushTarget(string key = "hes-1", string address = "fd00::1") =>
        new() { Key = key, Address = address, Port = 4059 };

    private static NetworkRegistry NewRegistry(INetworkRegistryStore? store = null) =>
        new(store ?? NullNetworkRegistryStore.Instance);

    [Fact]
    public void AddBroker_ThenLookup_RoundTrips()
    {
        NetworkRegistry registry = NewRegistry();

        registry.AddBroker(Broker(), verified: true);

        BrokerEndpoint? found = registry.Broker("eqa");
        Assert.NotNull(found);
        Assert.Equal("10.0.0.1", found!.Host);
        Assert.True(found.Verified);
        Assert.NotNull(found.LastVerifiedUtc);
        Assert.True(found.Enabled);
    }

    [Fact]
    public void Broker_KeyLookup_IsCaseInsensitive()
    {
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker("EQA"), verified: true);

        Assert.NotNull(registry.Broker("eqa"));
    }

    [Fact]
    public void AddBroker_DuplicateKey_UpdatesBrokerHalf()
    {
        // In the unified environment model, calling AddBroker twice with the same key updates
        // the broker half of the environment rather than throwing.
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker(), verified: true);
        registry.AddBroker(Broker(host: "10.0.0.2"), verified: true);

        Assert.Equal("10.0.0.2", registry.Broker("eqa")!.Host);
    }

    [Fact]
    public void AddPushTarget_AfterAddBroker_SameKey_MergesIntoOneEnvironment()
    {
        // An environment is a pair: broker + TCP push. Adding both with the same key
        // results in one environment that has both halves set.
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker("shared-name"), verified: true);
        registry.AddPushTarget(PushTarget("shared-name"), verified: true);

        var env = registry.Environment("shared-name");
        Assert.NotNull(env);
        Assert.True(env!.HasBroker);
        Assert.True(env.HasTcp);
    }

    [Fact]
    public void AddBroker_UnverifiedPath_StoredWithoutAVerificationTime()
    {
        NetworkRegistry registry = NewRegistry();

        registry.AddBroker(Broker(), verified: false);

        BrokerEndpoint found = registry.Broker("eqa")!;
        Assert.False(found.Verified);
        Assert.Null(found.LastVerifiedUtc);
    }

    [Fact]
    public void AddPushTarget_IPv4_Rejected()
    {
        NetworkRegistry registry = NewRegistry();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => registry.AddPushTarget(PushTarget(address: "192.168.1.10"), verified: true));

        Assert.Contains("IPv4", ex.Message);
    }

    [Fact]
    public void PushTarget_BracketedIPv6_IsAccepted()
    {
        Assert.True(PushTargetEndpoint.TryParseAddress("[fd00::1]", out _, out _));
    }

    [Fact]
    public void PushTarget_Destination_IsBracketedForPushCoordinator()
    {
        Assert.Equal("[fd00::1]:4059", PushTarget().Destination);
    }

    [Fact]
    public void SetBrokerEnabled_TogglesAndReportsWhetherAnythingChanged()
    {
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker(), verified: true);

        Assert.True(registry.SetBrokerEnabled("eqa", false));
        Assert.False(registry.Broker("eqa")!.Enabled);

        // Already disabled — no change, so no reconcile should be triggered.
        Assert.False(registry.SetBrokerEnabled("eqa", false));
    }

    [Fact]
    public void UpdateBroker_PreservesTheEnabledToggle()
    {
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker(), verified: true);
        registry.SetBrokerEnabled("eqa", false);

        // An edit dialog that did not surface the toggle must not silently re-enable the endpoint.
        registry.UpdateBroker(Broker(host: "10.0.0.9"), verified: true);

        Assert.False(registry.Broker("eqa")!.Enabled);
        Assert.Equal("10.0.0.9", registry.Broker("eqa")!.Host);
    }

    [Fact]
    public void TryDeleteBroker_WhileABatchIsBound_Refused()
    {
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker(), verified: true);
        registry.SetUsageSource(new StubUsage("eqa", "batch-1"));

        Assert.False(registry.TryDeleteBroker("eqa", out string error));
        Assert.Contains("batch-1", error);
        Assert.NotNull(registry.Broker("eqa"));
    }

    [Fact]
    public void TryDeleteBroker_WhenUnused_Succeeds()
    {
        NetworkRegistry registry = NewRegistry();
        registry.AddBroker(Broker(), verified: true);

        Assert.True(registry.TryDeleteBroker("eqa", out string error));
        Assert.Empty(error);
        Assert.Null(registry.Broker("eqa"));
    }

    [Fact]
    public void Broker_NullOrUnknownKey_IsUnbound()
    {
        NetworkRegistry registry = NewRegistry();

        Assert.Null(registry.Broker(null));
        Assert.Null(registry.Broker("   "));
        Assert.Null(registry.Broker("never-added"));
    }

    [Fact]
    public void Changed_FiresOnMutationsThatAffectBindings()
    {
        NetworkRegistry registry = NewRegistry();
        int fired = 0;
        registry.Changed += () => fired++;

        registry.AddBroker(Broker(), verified: true);
        registry.SetBrokerEnabled("eqa", false);
        registry.TryDeleteBroker("eqa", out _);

        Assert.Equal(3, fired);
    }

    private sealed class StubUsage : IEndpointUsageSource
    {
        private readonly string _key;
        private readonly string _batch;

        public StubUsage(string key, string batch)
        {
            _key = key;
            _batch = batch;
        }

        public IReadOnlyList<string> BatchesUsingEnvironment(string key) =>
            string.Equals(key, _key, StringComparison.OrdinalIgnoreCase)
                ? new[] { _batch }
                : Array.Empty<string>();
    }
}
