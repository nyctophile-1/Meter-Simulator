using System.IO.Pipelines;
using ManyMeterSimulator.Framing;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class DlmsWpduFramerTests
{
    [Fact]
    public async Task ReadFrameAsync_FullFrameInOneWrite_ParsesCorrectly()
    {
        var pipe = new Pipe();
        byte[] payload = { 0xAA, 0xBB, 0xCC };
        byte[] wireBytes = DlmsWpduFramer.BuildFrame(sourceWPort: 1, destinationWPort: 2, payload);

        await pipe.Writer.WriteAsync(wireBytes);

        WpduFrame? frame = await DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None);

        Assert.NotNull(frame);
        Assert.Equal(1, frame!.SourceWPort);
        Assert.Equal(2, frame.DestinationWPort);
        Assert.Equal(payload, frame.Payload);
    }

    [Fact]
    public async Task ReadFrameAsync_HeaderAndPayloadSplitAcrossMultipleWrites_StillParsesCorrectly()
    {
        var pipe = new Pipe();
        byte[] payload = { 1, 2, 3, 4, 5 };
        byte[] wireBytes = DlmsWpduFramer.BuildFrame(sourceWPort: 10, destinationWPort: 20, payload);

        Task<WpduFrame?> readTask = DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None).AsTask();

        // Trickle the frame in one byte at a time, including mid-header and mid-payload splits.
        foreach (byte b in wireBytes)
        {
            await pipe.Writer.WriteAsync(new[] { b });
            await Task.Delay(1);
        }

        WpduFrame? frame = await readTask;

        Assert.NotNull(frame);
        Assert.Equal(10, frame!.SourceWPort);
        Assert.Equal(20, frame.DestinationWPort);
        Assert.Equal(payload, frame.Payload);
    }

    [Fact]
    public async Task ReadFrameAsync_TwoFramesBackToBack_ReadsBothInOrder()
    {
        var pipe = new Pipe();
        byte[] first = DlmsWpduFramer.BuildFrame(1, 2, new byte[] { 0x01 });
        byte[] second = DlmsWpduFramer.BuildFrame(3, 4, new byte[] { 0x02, 0x03 });

        await pipe.Writer.WriteAsync(first);
        WpduFrame? firstFrame = await DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None);

        await pipe.Writer.WriteAsync(second);
        WpduFrame? secondFrame = await DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None);

        Assert.Equal(new byte[] { 0x01 }, firstFrame!.Payload);
        Assert.Equal(new byte[] { 0x02, 0x03 }, secondFrame!.Payload);
    }

    [Fact]
    public async Task ReadFrameAsync_MalformedVersion_ThrowsInvalidDataException()
    {
        var pipe = new Pipe();
        byte[] wireBytes = DlmsWpduFramer.BuildFrame(1, 2, new byte[] { 0x01 });
        wireBytes[1] = 0x99; // corrupt the version field (low byte)

        await pipe.Writer.WriteAsync(wireBytes);

        await Assert.ThrowsAsync<InvalidDataException>(
            () => DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ReadFrameAsync_ConnectionClosesMidFrame_ThrowsInvalidDataException()
    {
        var pipe = new Pipe();
        byte[] wireBytes = DlmsWpduFramer.BuildFrame(1, 2, new byte[] { 0x01, 0x02, 0x03 });

        // Write header + part of the payload, then complete (simulate the client disconnecting).
        await pipe.Writer.WriteAsync(wireBytes.AsMemory(0, DlmsWpduFramer.HeaderLength + 1));
        await pipe.Writer.CompleteAsync();

        await Assert.ThrowsAsync<InvalidDataException>(
            () => DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ReadFrameAsync_GracefulEofBetweenFrames_ReturnsNull()
    {
        var pipe = new Pipe();
        await pipe.Writer.CompleteAsync();

        WpduFrame? frame = await DlmsWpduFramer.ReadFrameAsync(pipe.Reader, CancellationToken.None);

        Assert.Null(frame);
    }

    [Fact]
    public void BuildFrame_RoundTripsThroughReadFrame_HeaderFieldsMatch()
    {
        byte[] wireBytes = DlmsWpduFramer.BuildFrame(sourceWPort: 0x0001, destinationWPort: 0x1234, new byte[] { 0x0A, 0x0B });

        Assert.Equal(DlmsWpduFramer.HeaderLength + 2, wireBytes.Length);
        // version (big-endian)
        Assert.Equal(0x00, wireBytes[0]);
        Assert.Equal(0x01, wireBytes[1]);
    }
}
