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
}
