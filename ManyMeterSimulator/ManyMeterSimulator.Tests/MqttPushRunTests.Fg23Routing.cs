using ManyMeterSimulator.Brain;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;
using ManyMeterSimulator.Provisioning;
using ProtoBuf;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Fg23RoutingPublishes247EnvelopeWithoutMeterTemplates(bool prepared)
    {
        var fixture = new Fixture(1001, ciphering: true);
        var batch = fixture.Batches.AddBatch("routing only", "missing.xml", 1001,
            NicType.MqttWirepas, null, "local");
        fixture.Batches.TryStart(batch.Id);
        var request = fixture.Request with
        {
            BatchIds = [batch.Id],
            PushSetupLogicalName = MqttPushProfiles.Fg23Routing,
            Qos = 1
        };
        await using var run = await fixture.Push.OpenMqttRunAsync(request);

        if (prepared)
        {
            await run.PrepareAsync();
            Assert.Empty(fixture.Publisher.Messages);
            Assert.Equal(1001, run.PreparedMessages);
        }

        var before = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeMilliseconds();
        var result = prepared ? await run.FireAsync() : await run.SendLiveAsync();

        Assert.Equal(1001, result.MetersSent);
        Assert.Equal(1001, result.MessagesSent);
        Assert.Equal(0, result.MessagesFailed);
        Assert.Equal(0, fixture.Sessions.LiveMeterCount);
        Assert.Equal(1001, fixture.Publisher.Messages.Select(m => m.Topic).Distinct().Count());
        Assert.Equal((4, 1), Assert.Single(fixture.Publisher.PoolSettings));

        foreach (var message in fixture.Publisher.Messages)
        {
            using var stream = new MemoryStream(message.Payload);
            var packet = Serializer.Deserialize<GenericMessage>(stream).wirepas.packet_received_event;
            Assert.True(MeterNodeIds.TryGetIndex(packet.source_address.ToString(), out long index));
            var route = BatchGatewayAssignment.For(batch.Id, batch.StartIndex, index);

            Assert.InRange(index, batch.StartIndex, batch.EndIndex);
            Assert.Equal($"gw-event/received_data/{route.Gateway}/{route.Sink}/{packet.source_address}/247/247", message.Topic);
            Assert.Equal(route.Gateway, packet.header.gw_id);
            Assert.Equal(route.Sink, packet.header.sink_id);
            Assert.Equal(247u, packet.source_endpoint);
            Assert.Equal(247u, packet.destination_endpoint);
            Assert.Equal(0, packet.destination_address);
            Assert.Equal(1u, packet.hop_count);
            Assert.Equal(0u, packet.payload_size);
            Assert.True(packet.payload is null || packet.payload.Length == 0);
            Assert.InRange(packet.rx_time_ms_epoch, (ulong)before,
                (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        }

        Assert.Contains(fixture.Publisher.Messages, m => m.Topic.Contains($"/gate_{batch.Id}_2/"));
    }

    [Theory]
    [InlineData(NicType.Mqtt4G)]
    [InlineData(NicType.Mqtt4GImg)]
    [InlineData(NicType.MqttKmesh)]
    [InlineData(NicType.Tcp4G)]
    public async Task Fg23RoutingRejectsMixedTransportsBeforeOpeningPools(NicType nic)
    {
        var fixture = new Fixture(1);
        var batch = fixture.Batches.AddBatch("other", "missing.xml", 1, nic, null, "local");

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.Push.OpenMqttRunAsync(
            fixture.Request with
            {
                BatchIds = [fixture.Batch.Id, batch.Id],
                PushSetupLogicalName = MqttPushProfiles.Fg23Routing
            }));

        Assert.Contains("requires Wirepas", error.Message);
        Assert.Empty(fixture.Publisher.Pools);
    }

    [Fact]
    public async Task Fg23RoutingRandomLimitDoesNotDuplicateMeters()
    {
        var fixture = new Fixture(100);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with
        {
            PushSetupLogicalName = MqttPushProfiles.Fg23Routing,
            MaximumMetersPerBatch = 99,
            SelectRandomly = true
        });

        var result = await run.SendLiveAsync();

        Assert.Equal(99, result.MessagesSent);
        Assert.Equal(99, fixture.Publisher.Messages.Select(m => m.Topic).Distinct().Count());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Fg23RoutingInvalidatesPreparedDataOnStopOrBrokerChange(bool brokerChanged)
    {
        var fixture = new Fixture(3);
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with
        {
            PushSetupLogicalName = MqttPushProfiles.Fg23Routing
        });
        await run.PrepareAsync();

        if (brokerChanged)
        {
            fixture.Network.UpdateBroker(new BrokerEndpoint { Key = "local", Host = "changed.invalid" }, verified: false);
        }
        else
        {
            fixture.Batches.TryStop(fixture.Batch.Id);
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => run.FireAsync());
        Assert.Empty(fixture.Publisher.Messages);
    }

    [Fact]
    public async Task Fg23RoutingLoopsReusePoolsAndRebuildEnvelopes()
    {
        var fixture = new Fixture(1);
        using var stop = new CancellationTokenSource();
        fixture.Publisher.AfterPublish = () =>
        {
            if (fixture.Publisher.Messages.Count >= 3)
            {
                stop.Cancel();
            }
        };
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with
        {
            PushSetupLogicalName = MqttPushProfiles.Fg23Routing
        }, stop.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.SendLoopAsync(new()));

        var messages = fixture.Publisher.Messages.ToArray();
        Assert.Equal(3, messages.Length);
        Assert.Single(fixture.Publisher.Pools);
        Assert.Equal(messages[0].Topic, messages[1].Topic);
        Assert.NotEqual(messages[0].Payload, messages[1].Payload);
        Assert.Equal(0, fixture.Sessions.LiveMeterCount);
    }

    [Fact]
    public async Task AllMeterProfilesDoNotIncludeFg23Routing()
    {
        var fixture = new Fixture(1, template: "SA1231166HP_values.xml");
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PushSetupLogicalName = null });

        await run.SendLiveAsync();

        Assert.NotEmpty(fixture.Publisher.Messages);
        Assert.DoesNotContain(fixture.Publisher.Messages, m => m.Topic.EndsWith("/247/247"));
        Assert.Equal("FG23 Routing", MqttPushProfiles.Label(MqttPushProfiles.Fg23Routing));
    }
}
