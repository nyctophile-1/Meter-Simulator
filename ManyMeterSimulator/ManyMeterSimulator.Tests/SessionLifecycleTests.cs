using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// A connectionless NIC has no accept and no close, so the idle sweep is the ONLY thing that ends a
/// session. That makes reaping load-bearing rather than housekeeping: a virtual session that is
/// cancelled but left in the registry would block its meter as "already active" forever.
/// </summary>
public class SessionLifecycleTests
{
    private static SessionMaintenanceService Sweeper(SessionRegistry sessions, SimulatorMetrics metrics) =>
        new(NullLogger<SessionMaintenanceService>.Instance,
            Options.Create(new SessionMaintenanceOptions
            {
                IdleTimeoutSeconds = 0,       // anything with a past timestamp is idle
                SweepIntervalSeconds = 1,
                MetricsIntervalSeconds = 3600,
            }),
            sessions,
            metrics);

    private static async Task<bool> WaitUntilAsync(Func<bool> condition, int timeoutMs = 8000)
    {
        DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return true;
            }

            await Task.Delay(25);
        }

        return condition();
    }

    [Fact]
    public async Task AVirtualSession_IsCancelledAndRemovedFromTheRegistry()
    {
        var sessions = new SessionRegistry();
        var metrics = new SimulatorMetrics();
        var meter = new MeterRef(1, NicType.Mqtt4G);
        var state = new ConnectionState
        {
            Meter = meter,
            SessionCts = new CancellationTokenSource(),
            IsVirtual = true,
        };

        Assert.True(sessions.TryRegister(meter, state));

        SessionMaintenanceService sweeper = Sweeper(sessions, metrics);
        await sweeper.StartAsync(CancellationToken.None);
        try
        {
            Assert.True(await WaitUntilAsync(() => sessions.ActiveCount == 0));
            Assert.True(state.IdleTimedOut);
            Assert.True(state.SessionCts.IsCancellationRequested);

            // Removed, so the meter can open a fresh session on its next message.
            Assert.True(sessions.TryRegister(meter, new ConnectionState
            {
                Meter = meter,
                SessionCts = new CancellationTokenSource(),
                IsVirtual = true,
            }));
        }
        finally
        {
            await sweeper.StopAsync(CancellationToken.None);
        }
    }

    /// <summary>
    /// A TCP session must be cancelled but NOT unregistered here — its own loop does that in its
    /// finally, and removing it early would let a second connection in while the first is still
    /// closing down.
    /// </summary>
    [Fact]
    public async Task ATcpSession_IsCancelledButLeftForItsOwnLoopToUnregister()
    {
        var sessions = new SessionRegistry();
        var metrics = new SimulatorMetrics();
        var meter = new MeterRef(2, NicType.Tcp4G);
        var state = new ConnectionState
        {
            Meter = meter,
            MeterAddress = System.Net.IPAddress.IPv6Loopback,
            SessionCts = new CancellationTokenSource(),
            IsVirtual = false,
        };

        sessions.TryRegister(meter, state);

        SessionMaintenanceService sweeper = Sweeper(sessions, metrics);
        await sweeper.StartAsync(CancellationToken.None);
        try
        {
            Assert.True(await WaitUntilAsync(() => state.IdleTimedOut));
            Assert.Equal(1, sessions.ActiveCount);   // still owned by its connection handler
        }
        finally
        {
            await sweeper.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public void IdleTimeoutsAreCountedAgainstTheMetersOwnNic()
    {
        var metrics = new SimulatorMetrics();

        metrics.RecordIdleTimeout(NicType.MqttWirepas);
        metrics.RecordIdleTimeout(NicType.MqttWirepas);
        metrics.RecordIdleTimeout(NicType.Tcp4G);

        Assert.Equal(2, metrics.Snapshot(NicType.MqttWirepas, 0).TotalIdleTimeouts);
        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalIdleTimeouts);
        Assert.Equal(3, metrics.Snapshot(0).TotalIdleTimeouts);
    }
}

public class NicTypesTests
{
    [Fact]
    public void ImgSharesTheDirect4GTransport()
    {
        Assert.Equal(NicType.Mqtt4G, NicTypes.TransportFor(NicType.Mqtt4GImg));
        Assert.Equal(NicType.MqttKmesh, NicTypes.TransportFor(NicType.MqttKmesh));
        Assert.Equal(NicType.Tcp4G, NicTypes.TransportFor(NicType.Tcp4G));
    }

    [Theory]
    // The direct-4G transport serves both of its NIC types...
    [InlineData(NicType.Mqtt4G, NicType.Mqtt4G, true)]
    [InlineData(NicType.Mqtt4G, NicType.Mqtt4GImg, true)]
    [InlineData(NicType.Mqtt4GImg, NicType.Mqtt4G, true)]
    // ...but nothing crosses a transport boundary.
    [InlineData(NicType.Mqtt4G, NicType.MqttWirepas, false)]
    [InlineData(NicType.Mqtt4G, NicType.Tcp4G, false)]
    [InlineData(NicType.Tcp4G, NicType.Mqtt4G, false)]
    [InlineData(NicType.MqttWirepas, NicType.MqttKmesh, false)]
    public void CanServe_OnlyWithinOneTransport(NicType transport, NicType provisioned, bool expected)
    {
        Assert.Equal(expected, NicTypes.CanServe(transport, provisioned));
    }
}
