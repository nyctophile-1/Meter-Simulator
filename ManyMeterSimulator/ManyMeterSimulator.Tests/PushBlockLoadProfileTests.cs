using System.Buffers.Binary;
using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// On-demand push of the Block Load (Load Survey) profile via SA1231166HP_values.xml's own
/// "Block Load Push Setup" (0.5.25.9.0.255) — a SEPARATE PushSetup from Instant's, at its own
/// channel OBIS, because the HES dispatches on that SelfLN element
/// (DLMSGenericParser.ParseAndSavePushDataToDb: PushType.BlockLoadProfilePush = 0.5.25.9.0.255).
/// Bundling Instant and Block Load under one channel (an earlier iteration of this) made every
/// push look like an Instant push regardless of what data was actually inside it.
///
/// <para>
/// Like Instant, the structure is flat — matching vayu-core's BLOCK_DLMS_PUSH_1P schema
/// (ProfileTemplateId 59, SerialNumber 1-8: RtcDateTime, AverageVoltage,
/// CumulativeEnergyKwhImport, CumulativeEnergyKvahImport, CumulativeEnergyKwhExport,
/// CumulativeEnergyKvahExport, AverageCurrent, NeutralCurrent) — but unlike Instant, whose values
/// live directly on their own Registers, Block Load's values come from the LATEST row of the
/// Block Load profile's buffer (DLMSServerSession.SyncProfileBackedPushValues — generalized to
/// find whichever profile's CaptureObjects overlap a PushSetup's own object list, not hardcoded
/// to Block Load specifically), because a push represents one captured block, not a live
/// instantaneous reading. Block Load's RTC uses its profile capture-period boundary;
/// a scheduled cycle keeps that boundary even if transmission takes time.
/// </para>
/// </summary>
public class PushBlockLoadProfileTests
{
    private const string BlockLoadPushSetupLN = "0.5.25.9.0.255";

    private readonly ITestOutputHelper _output;

    public PushBlockLoadProfileTests(ITestOutputHelper output) => _output = output;

    private static byte[] Key16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

    private static DLMSServerSession BuildSession(long meterIndex = 508, string? templatePath = null)
    {
        var meter = new DLMSMeter(meterIndex, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, templatePath ?? Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        return session;
    }

    private static GXDLMSSecureClient BuildHesReceivingClient()
    {
        var client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        client.Ciphering.Security = Security.Encryption;
        client.Ciphering.BlockCipherKey = Key16();
        client.Ciphering.AuthenticationKey = Key16();
        return client;
    }

    private List<object> DecodePush(byte[] frame)
    {
        GXDLMSClient client = BuildHesReceivingClient();
        var data = new GXReplyData();
        var notify = new GXReplyData();
        client.GetData(new GXByteBuffer(frame), data, notify);
        object? value = notify.Value ?? data.Value;
        Assert.NotNull(value);
        return Assert.IsAssignableFrom<System.Collections.IEnumerable>(value).Cast<object>().ToList();
    }

    [Fact]
    public void BuildPushPayloads_FilteredToBlockLoad_SendsOnlyTheBlockLoadPushSetup()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: BlockLoadPushSetupLN);

        Assert.Single(payloads);
        var parsed = DecodePush(payloads[0]);

        // [0] Device ID, [1] SelfLN (0.5.25.9.0.255 — proves this is the Block Load channel, NOT
        // Instant's 0.0...), [2] RTC, then 6 flat scalar fields. 10 elements total.
        Assert.Equal(10, parsed.Count);
        Assert.Equal("CRY" + MeterIdentity.Serial(508), parsed[0]);
        Assert.Equal(new byte[] { 0, 5, 25, 9, 0, 255 }, (byte[])parsed[1]);
        Assert.Equal(12, ((byte[])parsed[2]).Length); // RTC — a real 12-byte COSEM date-time

        _output.WriteLine($"Decoded {parsed.Count} elements: {string.Join(", ", parsed.Select(p => p is byte[] b ? Convert.ToHexString(b) : p?.ToString()))}");
    }

    /// <summary>
    /// The Block Load profile's buffer timestamps are rolled forward to "now" at template load
    /// time (MeterObjectLoader.ShiftBufferTimestamps — keeps the demo data looking fresh), so the
    /// latest row's exact date/time is whatever moment the test happens to run, not a fixed value
    /// from the XML.
    ///
    /// <para>
    /// This template's buffer is chronologically sorted EXCEPT for one stray, much-older row that
    /// happens to sit at the last array index — a real data artifact, caught by comparing a live
    /// push against the template directly rather than a hand-picked hardcoded row. Regression test
    /// for exactly that bug: an earlier version read <c>Buffer[^1]</c> (the last array slot) and
    /// pushed that stray row's month-old timestamp on every send. "Latest" must mean the row with
    /// the MAXIMUM timestamp, found explicitly, matching how ShiftBufferTimestamps itself decides
    /// what "latest" means (via Max()) — never array position.
    /// </para>
    /// </summary>
    [Fact]
    public void BuildPushPayloads_BlockLoad_UsesLatestRowValues_WithCurrentIndianRtc()
    {
        DLMSServerSession session = BuildSession();

        // Independently find the true latest row directly from the (shared, already-loaded)
        // template — same technique ShiftBufferTimestamps and SyncProfileBackedPushValues use — so
        // the expected values are never hardcoded and can't silently drift out of sync with the data.
        var profile = TemplateModelCache.Shared
            .Get(Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"))
            .FindByLN(ObjectType.ProfileGeneric, "1.0.99.1.0.255") as GXDLMSProfileGeneric;
        Assert.NotNull(profile);
        object[] expectedRow = profile!.Buffer
            .OrderByDescending(row => ((GXDateTime)row[0]).Value)
            .First();
        object[] lastArrayRow = profile.Buffer[^1];
        Assert.NotSame(expectedRow, lastArrayRow); // sanity: this template really does have the anomaly

        var parsed = DecodePush(session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: BlockLoadPushSetupLN)[0]);

        var rtcBytes = (byte[])parsed[2];
        // COSEM date-time: year(2 BE), month, day, dow, hour, minute, second, hundredths, deviation(2), status.
        int year = (rtcBytes[0] << 8) | rtcBytes[1];
        int month = rtcBytes[2];
        int day = rtcBytes[3];
        int hour = rtcBytes[5];
        int minute = rtcBytes[6];
        int second = rtcBytes[7];

        TimeSpan period = TimeSpan.FromSeconds(profile.CapturePeriod);
        DateTime before = FloorToPeriod(DateTime.UtcNow.AddMinutes(330).AddSeconds(-2), period);
        DateTime after = FloorToPeriod(DateTime.UtcNow.AddMinutes(330).AddSeconds(2), period);
        var actual = new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc);
        Assert.InRange(actual, before, after);
        Assert.Equal(0, BinaryPrimitives.ReadInt16BigEndian(rtcBytes.AsSpan(9, 2)));

        Assert.Equal(Convert.ToDouble(expectedRow[1]), Convert.ToDouble(parsed[3]), precision: 3); // AverageVoltage
        Assert.Equal(Convert.ToDouble(expectedRow[2]), Convert.ToDouble(parsed[4]), precision: 3); // CumulativeEnergyKwhImport
        Assert.Equal(Convert.ToDouble(expectedRow[3]), Convert.ToDouble(parsed[5]), precision: 3); // CumulativeEnergyKvahImport
        Assert.Equal(Convert.ToDouble(expectedRow[4]), Convert.ToDouble(parsed[6]), precision: 3); // CumulativeEnergyKwhExport
        Assert.Equal(Convert.ToDouble(expectedRow[5]), Convert.ToDouble(parsed[7]), precision: 3); // CumulativeEnergyKvahExport
        Assert.Equal(Convert.ToDouble(expectedRow[6]), Convert.ToDouble(parsed[8]), precision: 3); // AverageCurrent
        Assert.Equal(Convert.ToDouble(expectedRow[7]), Convert.ToDouble(parsed[9]), precision: 3); // NeutralCurrent

        // And explicitly: the values must NOT match the stray last-array-slot row (unless it were
        // ever coincidentally the same, which it isn't for this template).
        Assert.NotEqual(Convert.ToDouble(lastArrayRow[1]), Convert.ToDouble(parsed[3]));
    }

    [Theory]
    [InlineData(900, 14, 45)]
    [InlineData(1800, 14, 30)]
    public void ScheduledBlockLoadRtcUsesProfilePeriodAndFrozenIndianSlot(int captureSeconds, int hour, int minute)
    {
        string path = CreateTemplateWithBlockPeriod(captureSeconds);
        try
        {
            var session = BuildSession(templatePath: path);
            var slot = DateTimeOffset.Parse("2026-09-25T09:15:00Z");
            var fields = DecodePush(Assert.Single(session.BuildPushPayloads(true, BlockLoadPushSetupLN,
                scheduledBlockSlot: slot)));
            var rtc = Assert.IsType<byte[]>(fields[2]);
            Assert.Equal(2026, BinaryPrimitives.ReadUInt16BigEndian(rtc.AsSpan(0, 2)));
            Assert.Equal(9, rtc[2]);
            Assert.Equal(25, rtc[3]);
            Assert.Equal(hour, rtc[5]);
            Assert.Equal(minute, rtc[6]);
            Assert.Equal(0, rtc[7]);
            Assert.Equal(0, BinaryPrimitives.ReadInt16BigEndian(rtc.AsSpan(9, 2)));
        }
        finally { File.Delete(path); }
    }

    private static string CreateTemplateWithBlockPeriod(int seconds)
    {
        string source = Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml");
        string xml = File.ReadAllText(source);
        int profile = xml.IndexOf("<LN>1.0.99.1.0.255</LN>", StringComparison.Ordinal);
        Assert.True(profile >= 0);
        const string open = "<CapturePeriod>";
        int start = xml.IndexOf(open, profile, StringComparison.Ordinal);
        int end = xml.IndexOf("</CapturePeriod>", start, StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start);
        string changed = xml[..(start + open.Length)] + seconds + xml[end..];
        string path = Path.Combine(Path.GetTempPath(), $"maya-block-period-{Guid.NewGuid():N}.xml");
        File.WriteAllText(path, changed);
        return path;
    }

    private static DateTime FloorToPeriod(DateTime value, TimeSpan period)
    {
        return value.AddTicks(-(value.TimeOfDay.Ticks % period.Ticks));
    }

    /// <summary>
    /// Selecting Instant must not pull in the Block Load PushSetup, and vice versa — each channel
    /// dispatches to a different HES parser, so sending the wrong one alongside is worse than not
    /// sending it at all.
    /// </summary>
    [Fact]
    public void BuildPushPayloads_FilteredToInstant_DoesNotIncludeBlockLoad()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: "0.0.25.9.0.255");

        Assert.Single(payloads);
        var parsed = DecodePush(payloads[0]);
        Assert.Equal(new byte[] { 0, 0, 25, 9, 0, 255 }, (byte[])parsed[1]); // Instant's own LN, not Block Load's
    }

    /// <summary>
    /// Regression guard for a real bug this session's push generalization surfaced: the profile's
    /// own identity LN ("1.0.99.1.0.255") is NOT the same as its PushSetup's dispatch LN
    /// ("0.5.25.9.0.255") — passing the former where the latter is required must find nothing to
    /// send, not silently substitute the right one. (See ProfileSimulationOptions.AutoPushSetupLogicalName.)
    /// </summary>
    [Fact]
    public void BuildPushPayloads_FilteredToTheProfilesOwnLN_FindsNothing()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: "1.0.99.1.0.255");

        Assert.Empty(payloads);
    }

    [Fact]
    public void BuildPushPayloads_Unfiltered_SendsInstantBlockLoadAndEswAsSeparatePayloads()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true);

        Assert.Equal(5, payloads.Count);
        var selfLns = payloads.Select(p => Convert.ToHexString((byte[])DecodePush(p)[1])).ToHashSet();
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 0, 25, 9, 0, 255 }), selfLns); // Instant
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 5, 25, 9, 0, 255 }), selfLns); // Block Load
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 4, 25, 9, 0, 255 }), selfLns);
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 6, 25, 9, 0, 255 }), selfLns);
    }
}
