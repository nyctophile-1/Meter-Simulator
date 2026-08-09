using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
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

        // The serial now lives in the meter's own value store, which is what PreRead answers reads
        // from. It is deliberately NOT written onto the template object: that object is shared by
        // every meter using this template, so writing there would give the whole fleet whichever
        // serial happened to be built last.
        Assert.Equal(meter.MeterNo, meter.GetValue("0.0.96.1.0.255"));
        Assert.NotNull(session.Items.FindByLN(ObjectType.Data, "0.0.96.1.0.255"));
    }

    /// <summary>
    /// The property that makes a shared template model safe: two meters built from the SAME
    /// template must not be able to see each other's identity or values.
    /// </summary>
    [Fact]
    public void TwoMetersOnOneTemplate_DoNotShareIdentityOrValues()
    {
        string template = TemplatePath("SA1231166HP_values.xml");

        var meterA = new DLMSMeter(1, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);
        var meterB = new DLMSMeter(2, "1.0.0.0.0.255", clientAddress: 16, serverAddress: 1);

        var sessionA = new DLMSServerSession(meterA, template);
        var sessionB = new DLMSServerSession(meterB, template);
        sessionA.Initialize(true);
        sessionB.Initialize(true);

        // Identity stays per meter even though the object model is shared.
        Assert.Equal("MY000000001", meterA.GetValue("0.0.96.1.0.255"));
        Assert.Equal("MY000000002", meterB.GetValue("0.0.96.1.0.255"));

        // The two sessions really are sharing one object graph (that is the point) …
        var objA = sessionA.Items.FindByLN(ObjectType.Data, "0.0.96.1.0.255");
        var objB = sessionB.Items.FindByLN(ObjectType.Data, "0.0.96.1.0.255");
        Assert.Same(objA, objB);

        // … and a write to one meter must not be visible on the other.
        meterA.SetValue("1.0.1.8.0.255", 12345u);
        Assert.NotEqual(12345u, meterB.GetValue("1.0.1.8.0.255"));
    }
}

/// <summary>Per-meter identity derivation must be deterministic and distinct per index.</summary>
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
    public void Identity_IsDistinctPerIndex()
    {
        Assert.NotEqual(MeterIdentity.SystemTitle(1), MeterIdentity.SystemTitle(2));
        Assert.NotEqual(MeterIdentity.BlockCipherKey(1), MeterIdentity.BlockCipherKey(2));
        Assert.NotEqual(MeterIdentity.AuthenticationKey(1), MeterIdentity.AuthenticationKey(2));
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

    /// <summary>
    /// The node id HES registers a meter under is defined as the serial minus its alphabetic prefix
    /// and leading zeros. Asserting that relationship directly (rather than just "it's the index")
    /// is what keeps the simulator and HES from ever disagreeing about who a meter is.
    /// </summary>
    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(1005)]
    [InlineData(999_999_999)]
    public void NodeId_IsSerialStrippedOfPrefixAndLeadingZeros(long index)
    {
        string expected = MeterIdentity.Serial(index).TrimStart('M', 'Y').TrimStart('0');

        Assert.Equal(expected, MeterIdentity.NodeId(index));
        Assert.Equal(index.ToString(), MeterIdentity.NodeId(index));
    }
}
