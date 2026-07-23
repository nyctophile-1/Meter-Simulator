using System.Net;
using ManyMeterSimulator.Provisioning;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class MeterRegistryTests
{
    private const string Prefix = "fd00:6d65:7472::/64";
    private const string Tpl = "test-template.xml";

    [Fact]
    public void AddBatch_SmallCount_MatchesSimpleHexScheme()
    {
        var registry = new MeterRegistry();

        MeterBatch batch = registry.AddBatch("batch-1", Tpl, 100);
        (IPAddress first, IPAddress last) = registry.GetAddressRange(batch, Prefix);

        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::1"), first);
        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::64"), last);
        Assert.Equal(BatchStatus.NotStarted, batch.Status);
    }

    [Fact]
    public void AddBatch_PastSingleGroupLimit_DoesNotThrowAndCarriesOver()
    {
        var registry = new MeterRegistry();

        // 65535 = 0xFFFF, the largest index that fits in one IPv6 group. One past that
        // (65536 = 0x10000) is exactly what crashed the old string-concatenation scheme.
        MeterBatch batch = registry.AddBatch("big-batch", Tpl, 65_537);
        var meters = registry.GetMeters(batch, Prefix).ToList();

        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::ffff"), meters[65_534].Address); // index 65535
        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::1:0"), meters[65_535].Address); // index 65536, carries into next group
        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::1:1"), meters[65_536].Address); // index 65537
    }

    [Fact]
    public void AddBatch_SequentialBatches_ContinueFromPreviousEnd()
    {
        var registry = new MeterRegistry();
        registry.AddBatch("first", Tpl, 100);

        MeterBatch second = registry.AddBatch("second", Tpl, 5);
        (IPAddress first, IPAddress last) = registry.GetAddressRange(second, Prefix);

        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::65"), first);
        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::69"), last);
        Assert.Equal("MY000000101", MeterRegistry.FormatSerial(second.StartIndex));
    }

    [Fact]
    public void PreviewNextBatch_ReflectsAlreadyReservedCount()
    {
        var registry = new MeterRegistry();
        registry.AddBatch("first", Tpl, 100);

        BatchPreview preview = registry.PreviewNextBatch(Prefix, 5);

        Assert.Equal(IPAddress.Parse("fd00:6d65:7472::65"), preview.FirstAddress);
        Assert.Equal("MY000000101", preview.FirstSerial);
    }

    [Fact]
    public void AddBatch_ZeroOrNegativeCount_Throws()
    {
        var registry = new MeterRegistry();

        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AddBatch("x", Tpl, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AddBatch("x", Tpl, -1));
    }

    [Fact]
    public void AddBatch_EmptyTemplate_Throws()
    {
        var registry = new MeterRegistry();

        Assert.Throws<ArgumentException>(() => registry.AddBatch("x", "", 10));
        Assert.Throws<ArgumentException>(() => registry.AddBatch("x", "   ", 10));
    }

    [Fact]
    public void AddBatch_ExceedingMaxIndex_ThrowsWithoutReservingAnything()
    {
        var registry = new MeterRegistry();
        registry.AddBatch("first", Tpl, MeterRegistry.MaxIndex - 5); // leaves 5 remaining

        Assert.Throws<InvalidOperationException>(() => registry.AddBatch("too-big", Tpl, 6));

        // The failed attempt must not have consumed any of the range - next preview should be unaffected.
        BatchPreview preview = registry.PreviewNextBatch(Prefix, 5);
        IPAddress expectedFirst = MeterAddressing.ComputeAddress(Prefix, MeterRegistry.MaxIndex - 4);
        Assert.Equal(expectedFirst, preview.FirstAddress);

        // Exactly 5 remaining should still succeed.
        MeterBatch lastPossible = registry.AddBatch("fits-exactly", Tpl, 5);
        Assert.Equal(MeterRegistry.MaxIndex, lastPossible.EndIndex);
    }

    [Fact]
    public void FormatSerial_MatchesExpectedConvention()
    {
        Assert.Equal("MY000000001", MeterRegistry.FormatSerial(1));
        Assert.Equal("MY999999999", MeterRegistry.FormatSerial(999_999_999));
        Assert.Equal(MeterRegistry.MaxIndex, 999_999_999);
    }

    [Fact]
    public void StartStopDelete_TransitionStatusCorrectly()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", Tpl, 10);

        Assert.Equal(BatchStatus.NotStarted, registry.Batches.Single().Status);

        Assert.True(registry.TryStart(batch.Id));
        Assert.Equal(BatchStatus.Running, registry.Batches.Single().Status);

        Assert.True(registry.TryStop(batch.Id));
        Assert.Equal(BatchStatus.Stopped, registry.Batches.Single().Status);

        Assert.True(registry.Delete(batch.Id));
        Assert.Empty(registry.Batches);

        Assert.False(registry.TryStart(batch.Id));
        Assert.False(registry.Delete(batch.Id));
    }

    [Fact]
    public void GetBatchStatusForAddress_ReflectsOwningBatch_AndNullForUnprovisioned()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", Tpl, 10);
        registry.TryStart(batch.Id);

        (IPAddress inRange, _) = registry.GetAddressRange(batch, Prefix);
        IPAddress notInAnyBatch = IPAddress.Parse("fd00:6d65:7472::ffff:ffff");

        Assert.Equal(BatchStatus.Running, registry.GetBatchStatusForAddress(inRange, Prefix));
        Assert.Null(registry.GetBatchStatusForAddress(notInAnyBatch, Prefix));
    }

    [Theory]
    [InlineData("fd00:6d65:7472::/64", true)]
    [InlineData("2406:da1a:abcd:1234::/64", true)]
    [InlineData("", false)]                          // unset
    [InlineData("fd00:6d65:7472::", false)]          // missing /64
    [InlineData("fd00:6d65:7472::/48", false)]       // wrong prefix length
    [InlineData("10.0.0.0/64", false)]               // IPv4
    [InlineData("fd00:6d65:7472::1/64", false)]      // non-zero host bits
    [InlineData("not-an-address/64", false)]         // garbage
    public void TryValidatePrefix_AcceptsOnlySlash64NetworkAddresses(string prefix, bool expectedValid)
    {
        bool valid = MeterAddressing.TryValidatePrefix(prefix, out string error);

        Assert.Equal(expectedValid, valid);
        if (!expectedValid)
        {
            Assert.NotEmpty(error);
        }
    }

    [Fact]
    public void GetTemplateNameForAddress_ReturnsBatchTemplate_AndNullForUnprovisioned()
    {
        var registry = new MeterRegistry();
        MeterBatch batch = registry.AddBatch("b1", "cool-template.xml", 10);

        (IPAddress inRange, _) = registry.GetAddressRange(batch, Prefix);
        IPAddress notInAnyBatch = IPAddress.Parse("fd00:6d65:7472::ffff:ffff");

        Assert.Equal("cool-template.xml", registry.GetTemplateNameForAddress(inRange));
        Assert.Null(registry.GetTemplateNameForAddress(notInAnyBatch));
    }
}
