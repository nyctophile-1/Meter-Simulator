using System.Buffers.Binary;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Logging.Abstractions;
using MeterSimulator.Models;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class CustomPullIngressTests
{
    [Fact]
    public void ResolvesTheBatchBeforeParsingAndProducesTypedInboundWork()
    {
        MeterRegistry registry = RegistryFor(templateId: 41, startIndex: 42);
        var ingress = new CustomPullIngress(registry, ResolverForLegacyTemplate(41));

        CustomPullIngressResult result = ingress.Decode(
            new MeterRef(42, NicType.MqttWirepas),
            Request(CustomPullWireProfile.Legacy, 42, 42));

        Assert.True(result.IsComplete, result.Detail);
        Assert.Equal(41, result.Inbound!.Value.Protocol.HesTemplateId);
        Assert.Equal(42u, result.Inbound!.Value.Request.FromNodeId);
        Assert.Equal(42u, result.Inbound!.Value.Request.ToNodeId);
    }

    [Fact]
    public void RejectsInnerNodeIdsThatDoNotMatchTheWirepasDestination()
    {
        MeterRegistry registry = RegistryFor(templateId: 41, startIndex: 42);
        var ingress = new CustomPullIngress(registry, ResolverForLegacyTemplate(41));

        CustomPullIngressResult result = ingress.Decode(
            new MeterRef(42, NicType.MqttWirepas),
            Request(CustomPullWireProfile.Legacy, 41, 42));

        Assert.Equal(CustomPullIngressStatus.Malformed, result.Status);
        Assert.Contains("do not match outer destination 42", result.Detail);
    }

    [Fact]
    public void DoesNotParseAnUnprovisionedMeterWithAGuessedTemplate()
    {
        var ingress = new CustomPullIngress(new MeterRegistry(), ResolverForLegacyTemplate(41));

        CustomPullIngressResult result = ingress.Decode(
            new MeterRef(42, NicType.MqttWirepas),
            Request(CustomPullWireProfile.Legacy, 42, 42));

        Assert.Equal(CustomPullIngressStatus.Unsupported, result.Status);
        Assert.Contains("not provisioned", result.Detail);
    }

    [Fact]
    public void RejectsLegacyThreeByteTemplateForAnUnrepresentableMeterId()
    {
        const long tooLargeForThreeBytes = 0x01_00_00_00;
        MeterRegistry registry = RegistryFor(templateId: 41, startIndex: tooLargeForThreeBytes);
        var ingress = new CustomPullIngress(registry, ResolverForLegacyTemplate(41));

        CustomPullIngressResult result = ingress.Decode(
            new MeterRef(tooLargeForThreeBytes, NicType.MqttWirepas),
            Request(CustomPullWireProfile.Legacy, 0, 0));

        Assert.Equal(CustomPullIngressStatus.Unsupported, result.Status);
        Assert.Contains("does not fit", result.Detail);
    }

    private static MeterRegistry RegistryFor(int templateId, long startIndex)
    {
        var registry = new MeterRegistry();
        registry.AddBatch("wirepas", "meter.xml", 1, NicType.MqttWirepas, hesTemplateId: templateId);

        // The parameterless registry always begins at index 1. Use a fixture that exercises its
        // actual allocation rules for ordinary cases; the large-id case is covered by a persisted
        // registry setup below if the requested starting index cannot be allocated directly.
        if (startIndex == 1)
        {
            return registry;
        }

        if (startIndex == 42)
        {
            registry.Reset();
            registry.ImportSnapshot(new BatchStoreSnapshot
            {
                NextIndex = 43,
                NextBatchId = 2,
                Batches =
                [
                    new PersistedBatch
                    {
                        Id = 1,
                        Name = "wirepas",
                        TemplateName = "meter.xml",
                        NicType = NicType.MqttWirepas,
                        HesTemplateId = templateId,
                        StartIndex = 42,
                        Count = 1,
                    },
                ],
            });
            return registry;
        }

        registry.Reset();
        registry.ImportSnapshot(new BatchStoreSnapshot
        {
            NextIndex = startIndex + 1,
            NextBatchId = 2,
            Batches =
            [
                new PersistedBatch
                {
                    Id = 1,
                    Name = "wirepas",
                    TemplateName = "meter.xml",
                    NicType = NicType.MqttWirepas,
                    HesTemplateId = templateId,
                    StartIndex = startIndex,
                    Count = 1,
                },
            ],
        });
        return registry;
    }

    private static CustomPullProtocolResolver ResolverForLegacyTemplate(int templateId)
    {
        string folder = Path.Combine(Path.GetTempPath(), $"custom-pull-ingress-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "MeterTemplate.csv"),
                "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"IsFG23\"\n" +
                $"\"{templateId}\",\"legacy\",\"10\",\"10\",\"0\"\n");
            HesDataModel model = new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);
            return new CustomPullProtocolResolver(model);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static byte[] Request(CustomPullWireProfile profile, uint fromNode, uint toNode)
    {
        var wire = new byte[profile.PacketLength];
        wire[0] = checked((byte)wire.Length);
        wire[1] = 1;
        wire[2] = 1;

        int at = 3;
        WriteUnsigned(wire.AsSpan(at, profile.FrameIdBytes), 1234);
        at += profile.FrameIdBytes;
        WriteUnsigned(wire.AsSpan(at, profile.NodeIdBytes), fromNode);
        at += profile.NodeIdBytes;
        WriteUnsigned(wire.AsSpan(at, profile.NodeIdBytes), toNode);
        at += profile.NodeIdBytes;
        wire[at++] = 4;
        wire[at++] = (byte)CustomPullWireSelector.GetWithoutData;
        wire[at++] = 0;
        BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(at, 4), 0);
        at += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(at, 4), 0);
        return wire;
    }

    private static void WriteUnsigned(Span<byte> destination, uint value)
    {
        for (int i = 0; i < destination.Length; i++)
        {
            destination[i] = (byte)(value >> (8 * i));
        }
    }
}
