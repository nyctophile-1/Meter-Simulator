using System.Net;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// <see cref="MeterRef"/> is the identity every NIC hands to the brain funnel. What matters is that
/// each NIC's own address form resolves to the SAME index — that is what makes one brain serve many
/// NICs — and that the node id never drifts from the serial.
/// </summary>
public class MeterRefTests
{
    private const string Prefix = "fd00:6d65:7472::/64";

    [Theory]
    [InlineData(1)]
    [InlineData(1005)]
    [InlineData(70_000)]        // past a 16-bit boundary
    [InlineData(999_999_999)]
    public void TcpAddress_AndNodeId_ResolveToTheSameMeter(long index)
    {
        IPAddress address = MeterAddressing.ComputeAddress(Prefix, index);

        MeterRef fromTcp = MeterRef.FromTcpAddress(address);
        Assert.True(MeterRef.TryFromNodeId(MeterIdentityNodeId(index), NicType.Mqtt4G, out MeterRef fromNode));

        Assert.Equal(index, fromTcp.Index);
        Assert.Equal(index, fromNode.Index);

        // Same meter, different NICs: the index agrees even though the NicType does not.
        Assert.Equal(fromTcp.Index, fromNode.Index);
        Assert.Equal(NicType.Tcp4G, fromTcp.Nic);
        Assert.Equal(NicType.Mqtt4G, fromNode.Nic);
    }

    [Fact]
    public void NodeId_AndSerial_AgreeWithTheRegistrysOwnFormat()
    {
        var meter = new MeterRef(5, NicType.MqttWirepas);

        Assert.Equal("5", meter.NodeId);
        Assert.Equal("MY000000005", meter.Serial);
        Assert.Equal(MeterRegistry.FormatSerial(5), meter.Serial);
    }

    /// <summary>A fixed-width node id from a topic or protobuf field must still resolve.</summary>
    [Theory]
    [InlineData("1005", 1005)]
    [InlineData("0001005", 1005)]
    [InlineData("00000000001", 1)]
    public void TryFromNodeId_ToleratesZeroPadding(string nodeId, long expected)
    {
        Assert.True(MeterRef.TryFromNodeId(nodeId, NicType.Mqtt4G, out MeterRef meter));
        Assert.Equal(expected, meter.Index);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-node")]
    [InlineData("0")]           // index is 1-based; 0 is not a meter
    [InlineData("-4")]
    public void TryFromNodeId_RejectsJunk(string? nodeId)
    {
        Assert.False(MeterRef.TryFromNodeId(nodeId, NicType.Mqtt4G, out MeterRef meter));
        Assert.Equal(default, meter);
    }

    /// <summary>
    /// Equality is on (index, nic) — the session registry keys on the index alone, so two refs for
    /// the same meter must never be distinguishable by anything that could drift, like a string form.
    /// </summary>
    [Fact]
    public void Equality_IsByIndexAndNic()
    {
        Assert.Equal(new MeterRef(7, NicType.Mqtt4G), new MeterRef(7, NicType.Mqtt4G));
        Assert.NotEqual(new MeterRef(7, NicType.Mqtt4G), new MeterRef(8, NicType.Mqtt4G));
    }

    private static string MeterIdentityNodeId(long index) => MeterSimulator.Models.MeterIdentity.NodeId(index);
}
