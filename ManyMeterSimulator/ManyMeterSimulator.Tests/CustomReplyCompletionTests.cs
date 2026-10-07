using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Mqtt;
using ManyMeterSimulator.Networking.Nic;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class CustomReplyCompletionTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OnlyCustomOwnedSessionClosesAfterEveryPacketSucceeds(bool custom)
    {
        var registry = new SessionRegistry();
        var session = Session(custom);
        Assert.True(registry.TryRegister(session.Meter, session));
        var packets = new[] { new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } };
        var published = new List<byte>();

        bool complete = await CustomReplyCompletion.PublishAsync(packets, packet =>
        {
            Assert.Equal(1, registry.ActiveCount);
            Assert.False(session.SessionCts.IsCancellationRequested);
            published.Add(packet[0]);
            return Task.FromResult(true);
        }, session, registry, new SimulatorMetrics());

        Assert.True(complete);
        Assert.Equal(new byte[] { 1, 2, 3 }, published);
        Assert.Equal(custom ? 0 : 1, registry.ActiveCount);
        Assert.Equal(custom, session.SessionCts.IsCancellationRequested);
        Assert.Equal(1, session.ExchangeCount);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrCancelledPublishRetainsSession(bool cancel)
    {
        var registry = new SessionRegistry();
        var session = Session(true);
        registry.TryRegister(session.Meter, session);
        int count = 0;
        Task<bool> Publish(byte[] _)
        {
            if (++count == 2)
            {
                if (cancel)
                {
                    throw new OperationCanceledException();
                }

                return Task.FromResult(false);
            }

            return Task.FromResult(true);
        }

        var task = CustomReplyCompletion.PublishAsync(new[] { new byte[] { 1 }, new byte[] { 2 }, new byte[] { 3 } },
            Publish, session, registry, new SimulatorMetrics());
        if (cancel)
        {
            await Assert.ThrowsAsync<OperationCanceledException>(() => task);
        }
        else
        {
            Assert.False(await task);
        }

        Assert.Equal(2, count);
        Assert.Equal(1, registry.ActiveCount);
        Assert.False(session.SessionCts.IsCancellationRequested);
        Assert.Equal(0, session.ExchangeCount);
    }

    [Fact]
    public async Task CompletionCannotRemoveReplacementSession()
    {
        var registry = new SessionRegistry();
        var old = Session(true);
        var current = Session(true);
        registry.TryRegister(current.Meter, current);
        Assert.True(await CustomReplyCompletion.PublishAsync(new[] { new byte[] { 1 } }, _ => Task.FromResult(true),
            old, registry, new SimulatorMetrics()));
        Assert.True(registry.TryGet(current.Meter, out var active));
        Assert.Same(current, active);
        Assert.False(current.SessionCts.IsCancellationRequested);
    }

    private static ConnectionState Session(bool custom) => new()
    {
        Meter = new MeterRef(1, NicType.MqttWirepas),
        IsVirtual = true,
        IsCustomCommand = custom,
        SessionCts = new CancellationTokenSource()
    };
}
