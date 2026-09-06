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
/// Block Load profile's buffer (DLMSServerSession.SyncBlockLoadPushValues), because a push
/// represents one captured block, not a live instantaneous reading. The row's own timestamp is
/// rounded to the nearest 30-minute block rather than sent verbatim.
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
    /// from the XML. What's actually checked: the RTC is a real, recent 12-byte COSEM date-time
    /// whose minute landed on a 30-minute boundary (proving the rounding ran), and the 6 numeric
    /// columns — which ShiftBufferTimestamps does NOT touch — match the template's static values
    /// for that row exactly.
    /// </summary>
    [Fact]
    public void BuildPushPayloads_BlockLoad_UsesTheLatestRow_WithRtcRoundedToNearestHalfHour()
    {
        DLMSServerSession session = BuildSession();

        var parsed = DecodePush(session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: BlockLoadPushSetupLN)[0]);

        var rtcBytes = (byte[])parsed[2];
        // COSEM date-time: year(2 BE), month, day, dow, hour, minute, second, hundredths, deviation(2), status.
        int year = (rtcBytes[0] << 8) | rtcBytes[1];
        int minute = rtcBytes[6];
        int second = rtcBytes[7];

        Assert.InRange(year, 2024, 2030); // sane, not some default/epoch value
        Assert.True(minute == 0 || minute == 30, $"Expected the rounded minute to be :00 or :30, was :{minute:D2}");
        Assert.Equal(0, second); // rounding to the half-hour must also zero the seconds

        Assert.Equal(253.18, Convert.ToDouble(parsed[3]), precision: 2);      // AverageVoltage
        Assert.Equal(5.91, Convert.ToDouble(parsed[4]), precision: 2);        // CumulativeEnergyKwhImport
        Assert.Equal(13.65, Convert.ToDouble(parsed[5]), precision: 2);       // CumulativeEnergyKvahImport
        Assert.Equal(0.0, Convert.ToDouble(parsed[6]));                      // CumulativeEnergyKwhExport
        Assert.Equal(0.0, Convert.ToDouble(parsed[7]));                      // CumulativeEnergyKvahExport
        Assert.Equal(0.2, Convert.ToDouble(parsed[8]), precision: 2);         // AverageCurrent
        Assert.Equal(0.2, Convert.ToDouble(parsed[9]), precision: 2);         // NeutralCurrent
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
