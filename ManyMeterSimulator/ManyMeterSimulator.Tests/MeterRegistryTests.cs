using System.Net;
using ManyMeterSimulator.Networking.Nic;
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
    [InlineData("2406:da1a:1c29:500:1a2b::/80", true)]  // AWS ENI prefix delegation issues /80
    [InlineData("2406:da1a:1c29:500:1a00::/72", true)]  // anywhere in the accepted band
    [InlineData("2406:da1a:1c29:500:1a2b::/72", false)] // byte 9 is a host bit under a /72
    [InlineData("", false)]                          // unset
    [InlineData("fd00:6d65:7472::", false)]          // missing prefix length
    [InlineData("fd00:6d65:7472::/48", false)]       // wider than /64
    [InlineData("fd00:6d65:7472::/96", false)]       // narrower than /80 — would truncate the index
    [InlineData("10.0.0.0/64", false)]               // IPv4
    [InlineData("fd00:6d65:7472::1/64", false)]      // non-zero host bits
    [InlineData("2406:da1a:1c29:500:1a2b::1/80", false)] // non-zero host bits below a /80
    [InlineData("not-an-address/64", false)]         // garbage
    public void TryValidatePrefix_AcceptsSlash64ThroughSlash80NetworkAddresses(string prefix, bool expectedValid)
    {
        bool valid = MeterAddressing.TryValidatePrefix(prefix, out string error);

        Assert.Equal(expectedValid, valid);
        if (!expectedValid)
        {
            Assert.NotEmpty(error);
        }
    }

    /// <summary>
    /// The index lives in the low 48 bits, so bytes 8..9 — which belong to the PREFIX under a /80 —
    /// must survive untouched. Getting this wrong silently emits addresses outside the delegated
    /// range, which looks like correct config but is unreachable (see deploy_task.md R-4).
    /// </summary>
    [Theory]
    [InlineData(1, "2406:da1a:1c29:500:1a2b::1")]
    [InlineData(100, "2406:da1a:1c29:500:1a2b::64")]
    [InlineData(65_536, "2406:da1a:1c29:500:1a2b::1:0")]
    [InlineData(999_999_999, "2406:da1a:1c29:500:1a2b::3b9a:c9ff")]
    public void ComputeAddress_PreservesPrefixBytes_UnderSlash80(long index, string expected)
    {
        IPAddress address = MeterAddressing.ComputeAddress("2406:da1a:1c29:500:1a2b::/80", index);

        Assert.Equal(IPAddress.Parse(expected), address);
        Assert.Equal(index, MeterAddressing.ExtractIndex(address));
    }

    /// <summary>Narrowing the index to 48 bits must not shift any address in the supported range.</summary>
    [Theory]
    [InlineData(1, "fd00:6d65:7472::1")]
    [InlineData(65_535, "fd00:6d65:7472::ffff")]
    [InlineData(65_536, "fd00:6d65:7472::1:0")]
    [InlineData(MeterRegistry.MaxIndex, "fd00:6d65:7472::3b9a:c9ff")]
    public void ComputeAddress_Slash64_IsUnchangedByTheSlash80Support(long index, string expected)
    {
        IPAddress address = MeterAddressing.ComputeAddress("fd00:6d65:7472::/64", index);

        Assert.Equal(IPAddress.Parse(expected), address);
        Assert.Equal(index, MeterAddressing.ExtractIndex(address));
    }

    [Fact]
    public void ComputeAddress_RejectsIndexBeyondTheEncodableRange()
    {
        // Far above MeterRegistry.MaxIndex, so this guard is defence-in-depth, not a live limit.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => MeterAddressing.ComputeAddress("fd00:6d65:7472::/64", MeterAddressing.MaxEncodableIndex + 1));

        Assert.True(MeterRegistry.MaxIndex < MeterAddressing.MaxEncodableIndex);
    }

    [Fact]
    public void Reset_ClearsAllBatchesAndRewindsCursorToOne()
    {
        var store = new InMemoryBatchStore();
        var registry = new MeterRegistry(store);
        registry.AddBatch("a", Tpl, 100);
        registry.AddBatch("b", Tpl, 50);

        registry.Reset();

        Assert.Empty(registry.Batches);

        // Numbering starts over: next batch is index 1 / id 1 again, and it survives a restart.
        MeterBatch fresh = registry.AddBatch("fresh", Tpl, 1);
        Assert.Equal(1, fresh.StartIndex);
        Assert.Equal(1, fresh.Id);

        var restarted = new MeterRegistry(store);
        MeterBatch reloaded = Assert.Single(restarted.Batches);
        Assert.Equal("fresh", reloaded.Name);
        Assert.Equal(1, reloaded.StartIndex);
    }

    [Fact]
    public void Persistence_RehydratesBatchesStatusAndCursor_AcrossRestart()
    {
        var store = new InMemoryBatchStore();

        // First "process": create two batches, start the second.
        var first = new MeterRegistry(store);
        first.AddBatch("b1", Tpl, 100);
        MeterBatch b2 = first.AddBatch("b2", Tpl, 5);
        first.TryStart(b2.Id);

        // Second "process" over the same store simulates a restart/redeploy.
        var restarted = new MeterRegistry(store);

        Assert.Equal(2, restarted.Batches.Count);
        Assert.Equal(BatchStatus.Running, restarted.Batches.Single(b => b.Name == "b2").Status);

        // Cursor survived: the next batch continues at index 106, it does NOT restart at 1
        // (which would reissue already-known addresses).
        BatchPreview preview = restarted.PreviewNextBatch(Prefix, 1);
        Assert.Equal(MeterAddressing.ComputeAddress(Prefix, 106), preview.FirstAddress);

        // Batch ids are not reused either.
        MeterBatch b3 = restarted.AddBatch("b3", Tpl, 1);
        Assert.Equal(3, b3.Id);
    }

    [Fact]
    public void Persistence_DeleteDoesNotReclaimTheRange_AcrossRestart()
    {
        var store = new InMemoryBatchStore();

        var first = new MeterRegistry(store);
        MeterBatch b1 = first.AddBatch("b1", Tpl, 100);
        first.Delete(b1.Id);

        var restarted = new MeterRegistry(store);

        Assert.Empty(restarted.Batches);
        // The deleted range stays retired: the next batch still starts past it, not back at 1.
        BatchPreview preview = restarted.PreviewNextBatch(Prefix, 1);
        Assert.Equal(MeterAddressing.ComputeAddress(Prefix, 101), preview.FirstAddress);
    }

    [Fact]
    public void JsonBatchStore_RoundTripsThroughARealFile()
    {
        string path = Path.Combine(Path.GetTempPath(), $"mms-batchstore-{Guid.NewGuid():N}", "batches.json");
        try
        {
            var writeRegistry = new MeterRegistry(new JsonBatchStore(path));
            MeterBatch b = writeRegistry.AddBatch("persisted", Tpl, 42);
            writeRegistry.TryStart(b.Id);

            Assert.True(File.Exists(path));

            // A brand-new store instance reading the same file must see the same state.
            var readRegistry = new MeterRegistry(new JsonBatchStore(path));
            MeterBatch reloaded = Assert.Single(readRegistry.Batches);
            Assert.Equal("persisted", reloaded.Name);
            Assert.Equal(42, reloaded.Count);
            Assert.Equal(BatchStatus.Running, reloaded.Status);
        }
        finally
        {
            string? dir = Path.GetDirectoryName(path);
            if (dir is not null && Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    [Fact]
    public void JsonBatchStore_RoundTripsTheNicType()
    {
        string path = Path.Combine(Path.GetTempPath(), $"mms-batchstore-{Guid.NewGuid():N}", "batches.json");
        try
        {
            var writeRegistry = new MeterRegistry(new JsonBatchStore(path));
            writeRegistry.AddBatch("rf", Tpl, 5, NicType.MqttWirepas);

            MeterBatch reloaded = Assert.Single(new MeterRegistry(new JsonBatchStore(path)).Batches);
            Assert.Equal(NicType.MqttWirepas, reloaded.NicType);
        }
        finally
        {
            string? dir = Path.GetDirectoryName(path);
            if (dir is not null && Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    /// <summary>
    /// A store written before NIC types existed has no "NicType" field. It must rehydrate as
    /// Tcp4G — the behaviour those batches already had — so upgrading needs no migration and
    /// no operator action. This is the compatibility guarantee, so it is asserted against
    /// literal legacy JSON rather than against anything the current code can produce.
    /// </summary>
    [Fact]
    public void JsonBatchStore_ReadsALegacyFileWithNoNicType_AsTcp()
    {
        string dir = Path.Combine(Path.GetTempPath(), $"mms-batchstore-{Guid.NewGuid():N}");
        string path = Path.Combine(dir, "batches.json");
        try
        {
            Directory.CreateDirectory(dir);
            File.WriteAllText(path, """
            {
              "NextIndex": 11,
              "NextBatchId": 2,
              "Batches": [
                {
                  "Id": 1,
                  "Name": "legacy",
                  "TemplateName": "meter.xml",
                  "StartIndex": 1,
                  "Count": 10,
                  "Status": "Running",
                  "CreatedAtUtc": "2026-01-01T00:00:00+00:00"
                }
              ]
            }
            """);

            var registry = new MeterRegistry(new JsonBatchStore(path));

            MeterBatch reloaded = Assert.Single(registry.Batches);
            Assert.Equal(NicType.Tcp4G, reloaded.NicType);
            Assert.Equal("legacy", reloaded.Name);
            Assert.Equal(BatchStatus.Running, reloaded.Status);

            // The allocation cursor must survive too — reissuing indices is what the store prevents.
            Assert.Equal("11", registry.PreviewNextBatch(Prefix, 1).FirstNodeId);
        }
        finally
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
    }

    /// <summary>In-memory <see cref="IBatchStore"/> that holds the last saved snapshot, for restart simulation.</summary>
    private sealed class InMemoryBatchStore : IBatchStore
    {
        private BatchStoreSnapshot _snapshot = new();

        public BatchStoreSnapshot Load() => _snapshot;

        public void Save(BatchStoreSnapshot snapshot) => _snapshot = snapshot;
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
