using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The brain funnel is keyed by meter INDEX, not by transport address. These tests pin the property
/// that makes NIC virtualisation possible: whichever NIC a request arrives on, the same meter
/// resolves to the same live DLMS session — so a meter's state can never fork per transport.
/// </summary>
public class MeterSessionManagerTests
{
    private const string Template = "SA1231166HP_values.xml";
    private const string Prefix = "fd00:6d65:7472::/64";

    private static MeterSessionManager BuildManager(out MeterRegistry registry)
    {
        registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", Template, 10);
        registry.TryStart(batch.Id);

        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestHostEnvironment(),
            NullLogger<TemplateRegistry>.Instance);

        return new MeterSessionManager(
            registry,
            templates,
            Options.Create(new BrainOptions()),
            NullLogger<MeterSessionManager>.Instance);
    }

    [Fact]
    public void SameMeter_OnDifferentNics_ResolvesToTheSameSession()
    {
        MeterSessionManager sessions = BuildManager(out _);

        // Index 3 reached two ways: as a TCP connection to its IPv6, and as an MQTT node id.
        MeterRef viaTcp = MeterRef.FromTcpAddress(MeterAddressing.ComputeAddress(Prefix, 3));
        Assert.True(MeterRef.TryFromNodeId("3", NicType.Mqtt4G, out MeterRef viaMqtt));

        DLMSServerSession first = sessions.GetOrCreate(viaTcp);
        DLMSServerSession second = sessions.GetOrCreate(viaMqtt);

        Assert.Same(first, second);       // one meter, one brain — not one per transport
        Assert.Equal(1, sessions.LiveMeterCount);
    }

    [Fact]
    public void DifferentMeters_GetDistinctSessions()
    {
        MeterSessionManager sessions = BuildManager(out _);

        Assert.True(MeterRef.TryFromNodeId("1", NicType.Mqtt4G, out MeterRef one));
        Assert.True(MeterRef.TryFromNodeId("2", NicType.Mqtt4G, out MeterRef two));

        Assert.NotSame(sessions.GetOrCreate(one), sessions.GetOrCreate(two));
        Assert.Equal(2, sessions.LiveMeterCount);
    }

    [Fact]
    public void MeterOutsideEveryBatch_Throws_AndIsNotCached()
    {
        MeterSessionManager sessions = BuildManager(out _);

        // The batch covers indices 1..10, so 999 belongs to nothing.
        Assert.True(MeterRef.TryFromNodeId("999", NicType.Mqtt4G, out MeterRef unprovisioned));

        Assert.Throws<InvalidOperationException>(() => sessions.GetOrCreate(unprovisioned));
        Assert.Equal(0, sessions.LiveMeterCount); // a failed build must not be cached
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
