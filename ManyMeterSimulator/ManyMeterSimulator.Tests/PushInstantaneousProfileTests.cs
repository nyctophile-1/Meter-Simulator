using System.Text;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Secure;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// On-demand push of the Instantaneous Profile via SA1231166HP_values.xml's "Instant Push Setup"
/// (0.0.25.9.0.255).
///
/// <para>
/// The push structure is FLAT — [DeviceId, PushSetup's own LN, Clock, Voltage, PhaseCurrent, ...,
/// LoadLimitValueKw] — NOT the ProfileGeneric's Buffer (which would nest a whole Array/Structure
/// as one slot). This matches how the real HES parser actually reads it
/// (DLMSGenericParser.ParseAndSaveInstantProfile in vayu-core): it indexes straight into the outer
/// structure at <c>SerialNumber + 1</c> for each named field of the INSTANT_DLMS_PUSH_1P schema,
/// with no concept of a nested row array. A nested ProfileGeneric buffer decoded fine on our side
/// but broke the HES's flat indexing — confirmed against vayu-core's TCPDataReceiverClient.cs and
/// DLMSGenericParser.cs.
/// </para>
///
/// <para>
/// Load Survey / Block Load is NOT part of this PushSetup — it has its OWN PushSetup object at its
/// OWN channel OBIS (0.5.25.9.0.255, see PushBlockLoadProfileTests), so the SelfLN element
/// correctly dispatches to ParseAndSaveBlockloadProfile on the HES side rather than the Instant
/// parser. Bundling every profile under channel 0 (an earlier iteration of this) made every push
/// look like an Instant push regardless of content. Daily Profile doesn't have one yet.
/// </para>
///
/// <para>
/// Decodes the encrypted frame exactly the way the real HES does (per the HES-side source this
/// mirrors): a client with <c>Ciphering.Security = Security.Encryption</c> (NOT
/// AuthenticationEncryption) and the demo key on both BlockCipherKey and AuthenticationKey, fed
/// through the 3-arg <c>GetData(reply, data, notify)</c> overload so the push lands in
/// <c>notify.Value</c> as a Structure/List, matching the HES's own parsing branch.
/// </para>
/// </summary>
public class PushInstantaneousProfileTests
{
    private readonly ITestOutputHelper _output;

    public PushInstantaneousProfileTests(ITestOutputHelper output) => _output = output;

    private static byte[] Key16() => Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");

    private static DLMSServerSession BuildSession(long meterIndex = 508)
    {
        var meter = new DLMSMeter(meterIndex, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var session = new DLMSServerSession(
            meter, Path.Combine(AppContext.BaseDirectory, "Templates", "SA1231166HP_values.xml"));
        session.Initialize(true);
        return session;
    }

    /// <summary>Same shape as the HES's own secure client (TCPDataReceiverClient.UpdateDLMSState).</summary>
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
    public void BuildPushPayloads_Encrypted_DecodesOnAnHesShapedClient_AsAFlatStructure()
    {
        DLMSServerSession session = BuildSession(meterIndex: 508);

        // Filtered to the Instant channel specifically: the template now also has a Block Load
        // PushSetup (see PushBlockLoadProfileTests), and an unfiltered call would return both.
        IReadOnlyList<byte[]> payloads = session.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: "0.0.25.9.0.255");

        Assert.Single(payloads);
        byte[] frame = payloads[0];
        _output.WriteLine($"Encrypted push frame: {Convert.ToHexString(frame)}");

        var parsed = DecodePush(frame);

        // [0] Device ID, [1] PushSetup's own LN, [2] Clock (=RtcDateTime), then 22 flat scalar
        // fields — SerialNumber 2-23 of the INSTANT_DLMS_PUSH_1P schema, including the 23rd
        // (NICSignalPower) that only ProfileTemplateId 59 ("APRAAVA HP (RSSI)") uses; the base
        // 22-field variants just never read that far. No nested Array/Structure anywhere in
        // here — every slot is a plain value.
        Assert.Equal(25, parsed.Count);

        // Per-meter override (ApplyDeviceIdOverride) — not the template's static "CRYSA1231166",
        // which every meter on this template would otherwise push identically.
        Assert.Equal("CRY" + MeterIdentity.Serial(508), parsed[0]);
        Assert.Equal(new byte[] { 0, 0, 25, 9, 0, 255 }, (byte[])parsed[1]); // PushSetup's own LN
        Assert.Equal(12, ((byte[])parsed[2]).Length);                         // Clock / RtcDateTime

        Assert.Equal(244.6091, Convert.ToDouble(parsed[3]), precision: 3);   // Voltage
        Assert.Equal(0.3755, Convert.ToDouble(parsed[4]), precision: 2);    // PhaseCurrent
        Assert.Equal(0.3755, Convert.ToDouble(parsed[5]), precision: 2);    // NeutralCurrent
        Assert.Equal(50.1, Convert.ToDouble(parsed[7]), precision: 1);      // Frequency

        // LoadLimitFunctionStatus / LoadLimitValueKw (indices 22-23) are plain GXDLMSData
        // stand-ins, not GXDLMSDisconnectControl/GXDLMSLimiter — those two classes' Load(reader)
        // has a bug in this vendored Gurux version where an edited OutputState/ThresholdActive
        // still decodes back as the class default (false / None) regardless of what the template
        // says. A live push confirmed the None crashes the real HES's non-null-checked
        // ConvertByteToDecimalDivideBy(object, int) overload. The HES indexes these slots purely
        // by position, so a plain Data object with the same value works identically on the wire.
        Assert.Equal(true, parsed[22]);                                      // LoadLimitFunctionStatus
        Assert.Equal(15120.0, Convert.ToDouble(parsed[23]), precision: 1);  // LoadLimitValueKw
        Assert.Equal(-70, Convert.ToInt32(parsed[24]));                     // NICSignalPower

        // Every slot must be a plain scalar / byte[] — never an Array or nested Structure, which
        // is exactly what broke the HES's flat SerialNumber-based indexing before this fix.
        foreach (object? item in parsed)
        {
            Assert.False(item is IEnumerable<object> && item is not byte[],
                $"Found a nested collection ({item?.GetType()}) — the push must be fully flat.");
        }

        _output.WriteLine($"Decoded {parsed.Count} flat elements. DeviceId={parsed[0]}");
    }

    [Fact]
    public void BuildPushPayloads_DeviceId_IsUniquePerMeter_NotTheTemplatesStaticValue()
    {
        DLMSServerSession sessionA = BuildSession(meterIndex: 508);
        DLMSServerSession sessionB = BuildSession(meterIndex: 600);

        const string instantPushSetupLN = "0.0.25.9.0.255";
        string deviceIdA = (string)DecodePush(sessionA.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: instantPushSetupLN)[0])[0];
        string deviceIdB = (string)DecodePush(sessionB.BuildPushPayloads(useCiphering: true, pushSetupLogicalName: instantPushSetupLN)[0])[0];

        Assert.NotEqual("CRYSA1231166", deviceIdA); // not the template's raw static value
        Assert.NotEqual(deviceIdA, deviceIdB);       // and the two meters differ from each other
        Assert.Equal("CRY" + MeterIdentity.Serial(508), deviceIdA);
        Assert.Equal("CRY" + MeterIdentity.Serial(600), deviceIdB);
    }

    // The "filter to one PushSetup by its own LN" behavior (Instant vs Block Load vs unfiltered)
    // is covered in PushBlockLoadProfileTests, once there's a second PushSetup to distinguish it
    // from.
}
