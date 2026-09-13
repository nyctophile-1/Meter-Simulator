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
/// instantaneous reading. The row's own timestamp is rounded to the nearest 30-minute block
/// (Block Load's own CapturePeriod) rather than sent verbatim.
/// </para>
/// </summary>
public class PushBlockLoadProfileTests
{
    private const string BlockLoadPushSetupLN = "0.5.25.9.0.255";

    private readonly ITestOutputHelper _output;

    public PushBlockLoadProfileTests(ITestOutputHelper output) => _output = output;

    private static byte[] Key16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

    private static DLMSServerSession BuildSession(long meterIndex = 508)
    {
        var meter = new DLMSMeter(meterIndex, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
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
    public void BuildPushPayloads_BlockLoad_UsesTheLatestRow_WithRtcRoundedToNearestHalfHour()
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

        // Round the SAME way DLMSServerSession does before comparing — the raw row time can sit in
        // the last ~15 minutes of an hour (e.g. 16:52), which rounds UP into the next hour (17:00).
        // Comparing rounded fields (hour/day/month/year) against the row's unrounded fields would
        // then fail exactly at that boundary despite the push being correct — round the expectation
        // first so the assertion reflects what the row is actually supposed to produce.
        DateTimeOffset expectedTime = ((GXDateTime)expectedRow[0]).Value;
        long blockTicks = TimeSpan.FromMinutes(30).Ticks;
        long remainder = expectedTime.Ticks % blockTicks;
        long roundedTicks = remainder < blockTicks / 2 ? expectedTime.Ticks - remainder : expectedTime.Ticks + (blockTicks - remainder);
        DateTimeOffset expectedRounded = new(roundedTicks, expectedTime.Offset);

        Assert.Equal(expectedRounded.Year, year);
        Assert.Equal(expectedRounded.Month, month);
        Assert.Equal(expectedRounded.Day, day);
        Assert.Equal(expectedRounded.Hour, hour);
        Assert.Equal(expectedRounded.Minute, minute);
        Assert.True(minute == 0 || minute == 30, $"Expected the rounded minute to be :00 or :30, was :{minute:D2}");
        Assert.Equal(0, second); // rounding to the half-hour must also zero the seconds

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
    public void BuildPushPayloads_Unfiltered_SendsBothInstantAndBlockLoadAsSeparatePayloads()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true);

        Assert.Equal(2, payloads.Count);
        var selfLns = payloads.Select(p => Convert.ToHexString((byte[])DecodePush(p)[1])).ToHashSet();
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 0, 25, 9, 0, 255 }), selfLns); // Instant
        Assert.Contains(Convert.ToHexString(new byte[] { 0, 5, 25, 9, 0, 255 }), selfLns); // Block Load
    }
}
