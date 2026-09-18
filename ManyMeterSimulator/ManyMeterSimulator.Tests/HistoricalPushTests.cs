using Gurux.DLMS;
using Gurux.DLMS.Enums;
using ManyMeterSimulator.BadComm;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using ManyMeterSimulator.Settings;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Task = System.Threading.Tasks.Task;

namespace ManyMeterSimulator.Tests;

public class HistoricalPushTests
{
    [Theory]
    [InlineData(900)]
    [InlineData(1800)]
    [InlineData(3600)]
    public void SlotsHonorInclusiveBoundsAndFractionalSeconds(int seconds)
    {
        var boundary = new DateTimeOffset(2026, 9, 18, 0, 0, 0, TimeSpan.Zero);
        Assert.Equal(boundary, HistoricalPushRun.FirstSlot(boundary, seconds));
        Assert.Equal(boundary.AddSeconds(seconds), HistoricalPushRun.FirstSlot(boundary.AddTicks(1), seconds));
        Assert.Equal(86400 / seconds + 1, HistoricalPushRun.SlotCount(boundary.AddDays(-1), boundary, seconds));
        Assert.Equal(86400 / seconds, HistoricalPushRun.SlotCount(boundary.AddDays(-1).AddTicks(1), boundary.AddTicks(1), seconds));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BackdatedDlmsKeepsIdentityAndCipheringWithoutRewindingLiveValues(bool ciphering)
    {
        var session = new DLMSServerSession(new DLMSMeter(909, "1.0.0.0.0.255", 16, 1),
            Path.Combine(AppContext.BaseDirectory, "Templates", "D1_Master.xml"));
        session.Initialize(true);
        var values = session.Meter.GetAllValues().ToDictionary(x => x.Key, x => x.Value);
        var time = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
        foreach (var profile in new[] { "0.0.25.9.0.255", "0.5.25.9.0.255" })
        {
            var payload = Assert.Single(session.BuildPushPayloads(ciphering, profile, time));
            var decoded = DailyPushTests.Decode(payload);
            Assert.Equal("CRY" + MeterIdentity.Serial(909), decoded[0]);
            Assert.Equal(profile.Split('.').Select(byte.Parse).ToArray(), Assert.IsType<byte[]>(decoded[1]));
            Assert.Equal(time, ReadTime(decoded[2]));
            Assert.All(values, v => Assert.Equal(v.Value, session.Meter.GetValue(v.Key)));
        }
        var live = DailyPushTests.Decode(Assert.Single(session.BuildPushPayloads(ciphering, "0.0.25.9.0.255")));
        Assert.InRange(ReadTime(live[2]), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    internal static DateTimeOffset ReadTime(object value) =>
        ((GXDateTime)GXDLMSClient.ChangeType(Assert.IsType<byte[]>(value), DataType.DateTime)).Value.ToUniversalTime();

    internal sealed class Store : IRuntimeConfigStore
    {
        public MayaRuntimeConfig Current { get; } = new();
        public void Update(Action<MayaRuntimeConfig> mutate) => mutate(Current);
    }

    internal static BadCommSettings Impaired(CommClass classification, double loss = 100)
    {
        var settings = new BadCommSettings(new Store());
        Assert.True(settings.TryUpdate(new BadCommConfig { Enabled = true, Auto = new() { BadCommPercent = 0, NonCommPercent = 0 },
            Rules = [new() { Id = 1, Name = "Push test", Match = MatchKind.Range, From = 1, To = long.MaxValue,
                Effect = classification, FailureRatePercent = loss, MultiplierMin = 1, MultiplierMax = 1 }] }, out _, CommunicationDirection.Push));
        return settings;
    }
}

public partial class MqttPushRunTests
{
    [Theory]
    [InlineData(CommClass.BadComm)]
    [InlineData(CommClass.NonComm)]
    public async Task MqttStressBypassesBadCommWhileOrdinaryAndScheduledPushHonorIt(CommClass classification)
    {
        var settings = HistoricalPushTests.Impaired(CommClass.Healthy);
        var f = new Fixture(2, badComm: settings);
        await using var prepared = await f.Push.OpenMqttRunAsync(f.Request);
        await prepared.PrepareAsync();
        Assert.True(settings.TryUpdate(HistoricalPushTests.Impaired(classification).Snapshot(CommunicationDirection.Push), out _, CommunicationDirection.Push));
        Assert.Equal(2, (await prepared.FireAsync()).MetersSent);
        await using var live = await f.Push.OpenMqttRunAsync(f.Request);
        Assert.Equal(2, (await live.SendLiveAsync()).MetersSent);
        Assert.Equal(0, (await f.Push.PushBatchAsync(f.Batch.Id, pushSetupLogicalName: MqttPushProfiles.CustomDaily)).Sent);
        await using var scheduled = await f.Push.OpenBatchTrafficAsync(f.Batch, BatchTrafficKind.Daily, default);
        await Assert.ThrowsAsync<PushSkippedException>(() => scheduled.SendAsync(f.Batch.StartIndex, default));
        Assert.Equal(4, f.Publisher.Messages.Count);
        Assert.Equal(3, f.Metrics.Snapshot(0).TotalPushMetersSkipped);
    }

    [Fact]
    public async Task HistoricalRunSendsEachSlotOnceAndStopsAtCapturedEndUsingOnePool()
    {
        var end = new DateTimeOffset(2026, 9, 18, 12, 7, 33, TimeSpan.Zero);
        var f = new Fixture(1, clock: new BlockClock(end));
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 2, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        var request = new HistoricalPushRequest { BatchIds = [batch.Id], Days = 1, InstantaneousIntervalMinutes = 60, RecordsPerSecond = 300000 };
        await using var run = await f.Push.OpenHistoricalRunAsync(request, default);
        var result = await run.SendAsync(_ => { }, default);
        int period = f.Sessions.GetOrCreate(new MeterRef(batch.StartIndex, batch.NicType)).BlockPushPeriodSeconds;
        Assert.Equal(2 * (24 + 86400 / period), result.Total);
        Assert.Equal(result.Total, result.Sent);
        Assert.Equal(0, result.Failed);
        Assert.Equal(end, result.To);
        Assert.Single(f.Publisher.Pools);
        var records = f.Publisher.Messages.Select(m => DailyPushTests.Decode(m.Payload)).ToArray();
        Assert.Equal(result.Total, records.Select(r => (r[0], Convert.ToHexString((byte[])r[1]), HistoricalPushTests.ReadTime(r[2]))).Distinct().LongCount());
        Assert.All(records, r => Assert.InRange(HistoricalPushTests.ReadTime(r[2]), end.AddDays(-1), end));
        Assert.Equal(records.Select(r => HistoricalPushTests.ReadTime(r[2])).Order(), records.Select(r => HistoricalPushTests.ReadTime(r[2])));
    }

    [Fact]
    public async Task HistoricalBadCommCreatesPartialGapsWithoutCountingThemAsFailures()
    {
        var f = new Fixture(1, badComm: HistoricalPushTests.Impaired(CommClass.BadComm, 50));
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 10, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        await using var run = await f.Push.OpenHistoricalRunAsync(new() { BatchIds = [batch.Id], Days = 1, RecordsPerSecond = 300000 }, default);
        var result = await run.SendAsync(_ => { }, default);
        Assert.InRange(result.Skipped, result.Total / 4, result.Total * 3 / 4);
        Assert.Equal(result.Total, result.Processed);
        Assert.Equal(0, result.Failed);
        Assert.Equal(result.Sent, f.Publisher.Messages.Count);
    }

    [Fact]
    public async Task StoppingHistoricalServiceCancelsDeliveryAndDisposesPool()
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Publisher.BeforePublish = async ct => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); };
        await using var service = new HistoricalPushService(f.Push, new TestLifetime());
        service.Start(new() { BatchIds = [batch.Id], Days = 7 });
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Throws<InvalidOperationException>(() => service.Start(new() { BatchIds = [batch.Id] }));
        await service.StopAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("Stopped", service.State.Phase);
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
        Assert.Empty(f.Publisher.Messages);
    }

    [Fact]
    public async Task HistoricalServiceChangesRateWhileConnectingAndSendingWithoutRestart()
    {
        var f = new Fixture(1);
        var batch = f.Batches.AddBatch("history", "D1_Master.xml", 1, NicType.Mqtt4G, null, "local");
        f.Batches.TryStart(batch.Id);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Publisher.BeforePublish = async ct => { entered.TrySetResult(); await Task.Delay(Timeout.Infinite, ct); };
        await using var service = new HistoricalPushService(f.Push, new TestLifetime());
        Assert.Throws<InvalidOperationException>(() => service.SetRecordsPerSecond(100));
        service.Start(new() { BatchIds = [batch.Id] });
        service.SetRecordsPerSecond(100);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(100, service.State.Request!.RecordsPerSecond);
        service.SetRecordsPerSecond(300000);
        Assert.Equal(300000, service.State.Request.RecordsPerSecond);
        Assert.Throws<ArgumentOutOfRangeException>(() => service.SetRecordsPerSecond(99));
        Assert.Equal(300000, service.State.Request.RecordsPerSecond);
        service.SetRecordsPerSecond(0);
        Assert.Equal(0, service.State.Request.RecordsPerSecond);
        Assert.Single(f.Publisher.Pools);
        await service.StopAsync();
        Assert.Throws<InvalidOperationException>(() => service.SetRecordsPerSecond(100));
        Assert.All(f.Publisher.Pools, p => Assert.True(p.Disposed));
    }
}
