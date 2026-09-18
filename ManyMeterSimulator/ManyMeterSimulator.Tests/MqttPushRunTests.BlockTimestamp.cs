using System.Buffers.Binary;
using ManyMeterSimulator.KimbalSpecifics.Wirepas;
using ManyMeterSimulator.Networking.SmartNic;
using ProtoBuf;

namespace ManyMeterSimulator.Tests;

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(15, 29, 59, 15, 83)]
    [InlineData(30, 29, 59, 0, 167)]
    [InlineData(15, 30, 0, 30, 83)]
    [InlineData(30, 30, 0, 30, 167)]
    public async Task CustomBlockUsesCompletedCaptureBoundaryAndConfiguredEnergyPeriod(
        int period, int minute, int second, int expectedMinute, int expectedEnergy)
    {
        const int template = 777;
        var now = new DateTimeOffset(2026, 9, 17, 18, minute, second, TimeSpan.Zero);
        var fixture = new Fixture(1, customTemplateId: template, encoder: CustomPushFixtureModel.BlockEncoder(template),
            customPullOptions: new CustomPullOptions { BlockPeriodMinutesByTemplate = new() { [template] = period } }, clock: new BlockClock(now));
        await using var run = await fixture.Push.OpenMqttRunAsync(fixture.Request with { PushSetupLogicalName = "custom:block" });
        Assert.Equal(1, (await run.SendLiveAsync()).MessagesSent);
        using var stream = new MemoryStream(Assert.Single(fixture.Publisher.Messages).Payload);
        var packet = Serializer.Deserialize<GenericMessage>(stream).wirepas.packet_received_event.payload;
        Assert.Equal(6, packet[12]);
        var decoded = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(23))).AddMinutes(-330);
        Assert.Equal(new DateTimeOffset(2026, 9, 17, 18, expectedMinute, 0, TimeSpan.Zero), decoded);
        Assert.True(decoded <= now);
        Assert.Equal((uint)expectedEnergy, BinaryPrimitives.ReadUInt32LittleEndian(packet.AsSpan(27)));
        Assert.Equal(0, fixture.Sessions.LiveMeterCount);
    }

    private sealed class BlockClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
