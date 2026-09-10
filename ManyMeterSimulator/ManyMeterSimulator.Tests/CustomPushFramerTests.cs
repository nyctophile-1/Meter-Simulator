using ManyMeterSimulator.Networking.CustomPush;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class CustomPushFramerTests
{
    [Fact]
    public void OldHeader_IsTenBytes_WithOnlyTheHesReadFieldsPopulated()
    {
        byte[] packet = CustomPushFramer.FrameOld([0xAA, 0xBB], 0x1234);

        Assert.Equal([0x0C, 1, 1, 0x34, 0x12, 0, 0, 0, 0, 0, 0xAA, 0xBB], packet);
    }

    [Fact]
    public void NewHeader_MatchesTheHesScheduledPushReaderLayout()
    {
        byte[] packet = CustomPushFramer.FrameNew([0xAA, 0xBB], 0x01020304, 0x12345678);

        Assert.Equal([0x78, 0x56, 0x34, 0x12, 0x0E, 0, 1, 1, 4, 3, 2, 1, 0xAA, 0xBB], packet);
    }

    [Fact]
    public void NewHeader_ReproducesTemplate93Capture()
    {
        // The framed payload comprises the 11-byte custom profile header followed by its 8-byte body.
        byte[] body =
        [
            0x1D, 0x01, 0x41, 0x53, 0xE9, 0x44, 0x12, 0x00, 0x00, 0x00, 0x00,
            0x3A, 0xF9, 0xA1, 0x6A, 0x03, 0x12, 0x08, 0x07,
        ];

        byte[] packet = CustomPushFramer.FrameNew(body, frameId: 6, magicNumber: 0x0011090E);

        Assert.Equal(
        [
            0x0E, 0x09, 0x11, 0x00, 0x1F, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x00,
            0x1D, 0x01, 0x41, 0x53, 0xE9, 0x44, 0x12, 0x00, 0x00, 0x00, 0x00,
            0x3A, 0xF9, 0xA1, 0x6A, 0x03, 0x12, 0x08, 0x07,
        ], packet);
    }

    [Fact]
    public void Template93DailyPush_UsesTheLiveEqaDailyFieldLayout()
    {
        byte[] payload = Template93.BuildDaily1P(
            meterIndex: 12,
            utcNow: DateTimeOffset.FromUnixTimeSeconds(1_788_999_997));

        Assert.Equal(31, payload.Length);
        Assert.Equal(5, payload[0]);
        Assert.Equal(1, payload[1]);
        Assert.Equal(
        [
            0x3D, 0xF9, 0xA1, 0x6A, // RTC
            0x80, 0xB5, 0x01, 0x00, // import kWh = 112000 -> 112.000
            0x90, 0xDC, 0x01, 0x00, // import kVAh = 122000 -> 122.000
            0x0C, 0x00, 0x00, 0x00, // export kWh = 12 -> 0.012
            0x70, 0x00, 0x00, 0x00, // export kVAh = 112 -> 0.112
        ], payload[11..]);
    }

    [Fact]
    public void WirepasEnvelope_UsesTheVayuCoreNewNormalDataTopic()
    {
        var publish = WirepasCustomPushEnvelope.Create("gw-1", "sink-1", "1197289", 10, [0x01]);

        Assert.Equal("gw-event/received_data/gw-1/sink-1/1197289/10/10", publish.Topic);
    }
}
