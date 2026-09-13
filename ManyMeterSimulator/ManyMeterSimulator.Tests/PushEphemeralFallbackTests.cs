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
/// A meter should be able to push anything it can already answer on pull, even when its template
/// never declared a PushSetup for that profile. HP_Template_111.xml is the fixture for this: it has
/// a real, populated Load Survey profile ("1.0.99.1.0.255", 15-minute Block Load rows) but only
/// Instant and Alert PushSetups — no Block Load PushSetup at all, unlike SA1231166HP_values.xml.
/// </summary>
public class PushEphemeralFallbackTests
{
    private const string BlockLoadDispatchLN = "0.5.25.9.0.255";
    private const string BlockLoadProfileLN = "1.0.99.1.0.255";

    private readonly ITestOutputHelper _output;

    public PushEphemeralFallbackTests(ITestOutputHelper output) => _output = output;

    private static byte[] Key16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

    private static DLMSServerSession BuildSession(long meterIndex = 700)
    {
        var meter = new DLMSMeter(meterIndex, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "HP_Template_111.xml"));
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

    /// <summary>
    /// Sanity check on the fixture itself: this template must NOT already have a Block Load
    /// PushSetup, or this test suite would be proving nothing about the fallback path.
    /// </summary>
    [Fact]
    public void Fixture_HasNoDeclaredBlockLoadPushSetup()
    {
        DLMSServerSession session = BuildSession();
        Assert.DoesNotContain(BlockLoadDispatchLN, session.GetPushSetupLogicalNames());
    }

    [Fact]
    public void BuildPushPayloads_NoPushSetupDeclared_BuildsEphemeralPushFromThePullProfile()
    {
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: BlockLoadDispatchLN);

        Assert.Single(payloads);
        var parsed = DecodePush(payloads[0]);

        // [0] Device ID, [1] SelfLN (must be the dispatch code, 0.5..., not the profile's own LN
        // 1.0.99.1...), [2] RTC, then the profile's own captured columns.
        Assert.True(parsed.Count > 3);
        Assert.Equal(new byte[] { 0, 5, 25, 9, 0, 255 }, (byte[])parsed[1]);
        Assert.Equal(12, ((byte[])parsed[2]).Length); // a real 12-byte COSEM date-time

        _output.WriteLine($"Decoded {parsed.Count} elements: {string.Join(", ", parsed.Select(p => p is byte[] b ? Convert.ToHexString(b) : p?.ToString()))}");
    }

    /// <summary>
    /// The ephemeral push must carry the SAME latest-row values the pull path would return for this
    /// profile — proving it's genuinely built from pull data, not some separate/stale source.
    /// </summary>
    [Fact]
    public void BuildPushPayloads_EphemeralPush_MatchesTheLatestRowFromThePullProfile()
    {
        DLMSServerSession session = BuildSession();

        var profile = Assert.IsType<GXDLMSProfileGeneric>(
            TemplateModelCache.Shared.Get(Path.Combine(AppContext.BaseDirectory, "Templates", "HP_Template_111.xml"))
                .FindByLN(ObjectType.ProfileGeneric, BlockLoadProfileLN));
        object[] expectedRow = profile.Buffer.OrderByDescending(row => ((GXDateTime)row[0]).Value).First();

        var parsed = DecodePush(session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: BlockLoadDispatchLN)[0]);

        // parsed[3..] line up 1:1 with the profile's CaptureObjects[1..], same as expectedRow[1..].
        for (int i = 1; i < expectedRow.Length; i++)
        {
            Assert.Equal(Convert.ToDouble(expectedRow[i]), Convert.ToDouble(parsed[2 + i]), precision: 3);
        }
    }

    [Fact]
    public void BuildPushPayloads_UnrecognizedDispatchLN_WithNoPushSetup_SendsNothing()
    {
        DLMSServerSession session = BuildSession();

        // Not a well-known dispatch code and no declared PushSetup — must not guess.
        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: "9.9.9.9.9.255");

        Assert.Empty(payloads);
    }

    [Fact]
    public void BuildPushPayloads_Unfiltered_DoesNotIncludeEphemeralFallbacks()
    {
        // pushSetupLogicalName == null means "send every non-empty PushSetup the template
        // configures" — it must stay literal. Ephemeral pushes only ever get built for an
        // EXPLICITLY requested dispatch LN, never invented speculatively for "send everything".
        DLMSServerSession session = BuildSession();

        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true);

        Assert.Equal(2, payloads.Count); // Instant + Alert only — no Block Load
        byte[] blockLoadSelfLn = { 0, 5, 25, 9, 0, 255 };
        bool anyContainsBlockLoadSelfLn = payloads
            .SelectMany(DecodePush)
            .OfType<byte[]>()
            .Any(value => value.AsSpan().SequenceEqual(blockLoadSelfLn));
        Assert.False(anyContainsBlockLoadSelfLn, "Unfiltered push must never include the Block Load ephemeral fallback.");
    }
}
