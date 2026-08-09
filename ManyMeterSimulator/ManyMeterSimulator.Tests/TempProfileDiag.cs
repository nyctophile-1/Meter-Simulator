using Gurux.DLMS.Objects;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

// TEMPORARY diagnostic — delete once the profile-buffer issue is resolved.
public class TempProfileDiag
{
    private readonly ITestOutputHelper _out;
    public TempProfileDiag(ITestOutputHelper o) => _out = o;

    private static string TemplatePath(string n) =>
        Path.Combine(AppContext.BaseDirectory, "Templates", n);

    [Theory]
    [InlineData("Values_SZ0000014HP.xml")]
    [InlineData("SA1231166HP_values.xml")]
    public void DumpProfileState(string template)
    {
        var meter = new DLMSMeter(42, "1.0.0.0.0.255", 16, 1);
        var session = new DLMSServerSession(meter, TemplatePath(template));
        session.Initialize(true);

        var profiles = session.Items.OfType<GXDLMSProfileGeneric>().ToList();
        _out.WriteLine($"=== {template}: {profiles.Count} profiles in Items ===");

        foreach (var p in profiles.Take(8))
        {
            _out.WriteLine(
                $"{p.LogicalName}  cols={p.CaptureObjects.Count,3}  rows={p.Buffer.Count,6}  " +
                $"entriesInUse={p.EntriesInUse,6}  profileEntries={p.ProfileEntries,6}  " +
                $"sortObj={(p.SortObject?.LogicalName ?? "null")}");
        }

        int withRows = profiles.Count(p => p.Buffer.Count > 0);
        _out.WriteLine($"profiles WITH buffer rows: {withRows} / {profiles.Count}");

        // Is the CaptureObject key the same instance that is registered in Items?
        foreach (var p in profiles.Where(x => x.CaptureObjects.Count > 0).Take(3))
        {
            foreach (var kv in p.CaptureObjects.Take(3))
            {
                var inItems = session.Items.FindByLN(kv.Key.ObjectType, kv.Key.LogicalName);
                _out.WriteLine(
                    $"  {p.LogicalName} col {kv.Key.ObjectType} {kv.Key.LogicalName} " +
                    $"attr={kv.Value.AttributeIndex} inItems={(inItems == null ? "MISSING" : (ReferenceEquals(inItems, kv.Key) ? "same" : "DIFFERENT"))} " +
                    $"dataType={kv.Key.GetDataType(kv.Value.AttributeIndex)}");
            }
        }

        Assert.True(true);
    }
}
