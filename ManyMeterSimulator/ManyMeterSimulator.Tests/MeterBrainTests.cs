using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using System.Text;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Verifies the merged brain: a DLMSServerSession builds from a real template XML and applies the
/// per-meter overrides (identity + serial). This is the in-process proof that the brain half works
/// end to end with the actual seeded templates — real DLMS-over-TCP is validated against the HES.
/// </summary>
public class MeterBrainTests
{
    private static string TemplatePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Templates", name);

    [Theory]
    [InlineData("SA1231166HP_values.xml")]
    [InlineData("SA1231166HP_values_bill.xml")]
    public void Session_BuildsFromTemplate_AndPopulatesObjectModel(string template)
    {
        const long index = 42;
        var meter = new DLMSMeter(index, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);

        var session = new DLMSServerSession(meter, TemplatePath(template));
        session.Initialize(true);

        Assert.NotEmpty(session.Items); // object model loaded from the template
    }

    [Fact]
    public void Session_OverridesSerialNumber_WithPerMeterSerial()
    {
        const long index = 42;
        var meter = new DLMSMeter(index, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        Assert.Equal("MY000000042", meter.MeterNo);

        var session = new DLMSServerSession(meter, TemplatePath("SA1231166HP_values.xml"));
        session.Initialize(true);

        var serial = session.Items.FindByLN(ObjectType.Data, "0.0.96.1.0.255") as GXDLMSData;
        Assert.NotNull(serial);
        Assert.Equal(meter.MeterNo, serial!.Value); // template's baked-in serial was rewritten
    }
}

/// <summary>
/// Meter identity is a FIXED shared crypto identity (system title + keys are the same
/// for every meter so a client configured with them can talk to any meter); only the
/// serial number is per-index.
/// </summary>
public class MeterIdentityTests
{
    [Fact]
    public void SystemTitle_Is8Bytes_StartsWithManufacturer_AndIsDeterministic()
    {
        byte[] a = MeterIdentity.SystemTitle(1);
        byte[] b = MeterIdentity.SystemTitle(1);

        Assert.Equal(8, a.Length);
        Assert.Equal(new byte[] { (byte)'S', (byte)'I', (byte)'M' }, a[..3]);
        Assert.Equal(a, b); // deterministic
    }

    [Fact]
    public void CryptoIdentity_IsShared_ButSerialIsDistinctPerIndex()
    {
        // System title + keys are FIXED/shared across meters (reverted from per-index),
        // so any client configured with them can talk to any meter.
        Assert.Equal(MeterIdentity.SystemTitle(1), MeterIdentity.SystemTitle(2));
        Assert.Equal(MeterIdentity.BlockCipherKey(1), MeterIdentity.BlockCipherKey(2));
        Assert.Equal(MeterIdentity.AuthenticationKey(1), MeterIdentity.AuthenticationKey(2));
        Assert.Equal(MeterIdentity.HlsKey(1), MeterIdentity.HlsKey(2));

        // The fixed values are the well-known test identity.
        Assert.Equal(Encoding.ASCII.GetBytes("SIMULATR"), MeterIdentity.SystemTitle(1));
        Assert.Equal(Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA"), MeterIdentity.BlockCipherKey(1));

        // Only the serial number stays per-index.
        Assert.NotEqual(MeterIdentity.Serial(1), MeterIdentity.Serial(2));
    }

    [Fact]
    public void Keys_Are16Bytes_LlsIs8_AndSerialMatchesRegistryFormat()
    {
        Assert.Equal(16, MeterIdentity.BlockCipherKey(5).Length);
        Assert.Equal(16, MeterIdentity.AuthenticationKey(5).Length);
        Assert.Equal(16, MeterIdentity.HlsKey(5).Length);
        Assert.Equal(8, MeterIdentity.LlsKey(5).Length);
        Assert.Equal("MY000000005", MeterIdentity.Serial(5));
    }
}
