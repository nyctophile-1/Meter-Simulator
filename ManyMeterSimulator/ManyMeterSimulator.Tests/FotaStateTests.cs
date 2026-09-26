using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects.Enums;
using MeterSimulator.Fota;

namespace ManyMeterSimulator.Tests;

public sealed class FotaStateTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "maya-fota-test-" + Guid.NewGuid().ToString("N"));
    private readonly FotaLimits _limits = new();
    private FotaSettings _settings = new() { Enabled = true, TargetVersion = "MAYA-2", BlockSize = 32 };

    private FotaMeter Meter(string key = "a", FotaStateStore? store = null) =>
        new(store ?? new FotaStateStore(_root, _limits), key, () => _settings with { }, _limits);

    private static ErrorCode Init(FotaMeter meter, uint size = 65) => meter.Invoke(1, new object[] { new byte[] { 1, 2 }, size });
    private static ErrorCode Block(FotaMeter meter, uint index, int length = 32, byte value = 0) =>
        meter.Invoke(2, new object[] { index, Enumerable.Repeat(value, length).ToArray() });

    [Fact]
    public void ReorderedBlocks_Duplicates_Restart_Activation_AndMeterIsolation()
    {
        var meter = Meter();
        Assert.Equal(ErrorCode.Ok, Init(meter));
        Assert.Equal(ErrorCode.Ok, Block(meter, 2, 1));
        Assert.Equal(0U, meter.Read(4));
        Assert.Equal("001", meter.Read(3));
        Assert.Equal(ErrorCode.Ok, Block(meter, 0));
        Assert.Equal(ErrorCode.Ok, Block(meter, 0));
        Assert.Equal(ErrorCode.OtherReason, Block(meter, 0, value: 1));
        Assert.Equal(ErrorCode.OtherReason, meter.Invoke(3, 0));
        Assert.Null(meter.ActiveVersion);

        meter = Meter();
        Assert.Equal(1U, meter.Read(4));
        Assert.Equal(ErrorCode.Ok, Block(meter, 1));
        Assert.Equal(3U, meter.Read(4));
        Assert.Equal(ErrorCode.Ok, meter.Invoke(3, 0));
        Assert.Equal(ErrorCode.Ok, meter.Invoke(4, 0));
        Assert.Equal(ErrorCode.Ok, meter.Invoke(4, 0));
        Assert.Equal(ErrorCode.Ok, Block(meter, 0));
        Assert.Equal((byte)ImageTransferStatus.ActivationSuccessful, meter.Read(6));
        Assert.Equal("MAYA-2", Meter().ActiveVersion);
        Assert.Null(Meter("b").ActiveVersion);
        Assert.Equal("", Meter("b").Read(3));

        Assert.Equal(ErrorCode.Ok, Init(meter));
        Assert.Equal("000", meter.Read(3));
        Assert.Equal("MAYA-2", meter.ActiveVersion);
    }

    [Fact]
    public void FaultCountersAreDurable_AndSettingsAreFrozen()
    {
        _settings.RejectBlock = 0;
        _settings.RejectAttempts = 2;
        var meter = Meter();
        Assert.Equal(ErrorCode.Ok, Init(meter, 32));
        Assert.Equal(ErrorCode.TemporaryFailure, Block(meter, 0));
        _settings.Enabled = false;
        _settings.TargetVersion = "CHANGED";
        meter = Meter();
        Assert.Equal(ErrorCode.TemporaryFailure, Block(meter, 0));
        Assert.Equal(ErrorCode.Ok, Block(Meter(), 0));
        Assert.Equal(ErrorCode.Ok, Meter().Invoke(3, 0));
        Assert.Equal(ErrorCode.Ok, Meter().Invoke(4, 0));
        Assert.Equal("MAYA-2", Meter().ActiveVersion);
        Assert.Equal(ErrorCode.ReadWriteDenied, Init(Meter()));
    }

    [Theory]
    [InlineData(true, false, ImageTransferStatus.VerificationFailed)]
    [InlineData(false, true, ImageTransferStatus.ActivationFailed)]
    public void FailureScenariosNeverChangeActiveVersion(bool verify, bool activate, ImageTransferStatus expected)
    {
        _settings.FailVerification = verify;
        _settings.FailActivation = activate;
        var meter = Meter();
        Assert.Equal(ErrorCode.Ok, Init(meter, 32));
        Assert.Equal(ErrorCode.ReadWriteDenied, meter.Invoke(4, 0));
        Assert.Equal(ErrorCode.Ok, Block(meter, 0));
        Assert.Equal(verify ? ErrorCode.OtherReason : ErrorCode.Ok, meter.Invoke(3, 0));
        Assert.NotEqual(ErrorCode.Ok, meter.Invoke(4, 0));
        Assert.Equal((byte)expected, Meter().Read(6));
        Assert.Null(Meter().ActiveVersion);
    }

    [Fact]
    public void InvalidParameters_AndLimits_AreRejectedWithoutProgress()
    {
        var meter = Meter();
        Assert.Equal(ErrorCode.ReadWriteDenied, Block(meter, 0));
        Assert.Equal(ErrorCode.UnmatchedType, Init(meter, 0));
        Assert.Equal(ErrorCode.UnmatchedType, Init(meter, uint.MaxValue));
        Assert.Equal(ErrorCode.UnmatchedType, meter.Invoke(1, new object[] { "id", 32 }));
        Assert.Equal(ErrorCode.Ok, Init(meter));
        Assert.Equal(ErrorCode.UnmatchedType, Block(meter, 0, 31));
        Assert.Equal(ErrorCode.UnmatchedType, Block(meter, 2, 32));
        Assert.Equal(ErrorCode.UnmatchedType, Block(meter, 3));
        Assert.Equal(ErrorCode.UnmatchedType, meter.Invoke(2, new object[] { -1, new byte[32] }));
        Assert.Equal(ErrorCode.UnmatchedType, meter.Invoke(3, "bad"));
        Assert.Equal("000", meter.Read(3));
    }

    [Fact]
    public void InterruptedAppendIsDiscarded_CompleteCorruptionFailsClosed()
    {
        Assert.Equal(ErrorCode.Ok, Init(Meter()));
        string journal = Directory.GetFiles(_root, "*.journal").Single();
        File.AppendAllText(journal, "partial record");
        Assert.Equal("000", Meter().Read(3));
        Assert.Equal(ErrorCode.Ok, Block(Meter(), 0));
        File.AppendAllText(journal, "corrupt complete record\n");
        Assert.Equal(ErrorCode.TemporaryFailure, Block(Meter(), 1));
    }

    [Fact]
    public void WriteFailureDoesNotAcknowledgeOrAdvanceState()
    {
        var meter = Meter();
        Assert.Equal(ErrorCode.Ok, Init(meter));
        string journal = Directory.GetFiles(_root, "*.journal").Single();
        using (var held = new FileStream(journal, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            Assert.Equal(ErrorCode.TemporaryFailure, Block(meter, 0));
        }

        Assert.Equal("000", Meter().Read(3));
        Assert.Equal(ErrorCode.Ok, Block(meter, 0));
    }

    [Fact]
    public void SnapshotCompaction_ReplayAndResetPreserveVersion()
    {
        var store = new FotaStateStore(_root, _limits);
        var meter = Meter(store: store);
        Assert.Equal(ErrorCode.Ok, Init(meter, 32 * 300));
        for (uint index = 0; index < 300; index++)
        {
            Assert.Equal(ErrorCode.Ok, Block(meter, index));
        }

        Assert.Single(Directory.GetFiles(_root, "*.snapshot"));
        Assert.Equal(300U, Meter().Read(4));
        Assert.Equal(ErrorCode.Ok, meter.Invoke(3, 0));
        Assert.Equal(ErrorCode.Ok, meter.Invoke(4, 0));
        Assert.Equal(ErrorCode.Ok, store.Change("a", _ => new(ErrorCode.Ok, new FotaEvent { Kind = "reset" })));
        Assert.Equal("", Meter().Read(3));
        Assert.Equal("MAYA-2", Meter().ActiveVersion);
    }

    [Fact]
    public void CacheIsBoundedAndEvictedMetersResume()
    {
        _limits.CachedMeters = 2;
        var store = new FotaStateStore(_root, _limits);
        for (int index = 0; index < 10; index++)
        {
            Assert.Equal(ErrorCode.Ok, Init(Meter(index.ToString(), store)));
            Assert.True(store.CachedMeterCount <= 2);
        }

        Assert.Equal("000", Meter("0", store).Read(3));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, true);
        }
    }
}
