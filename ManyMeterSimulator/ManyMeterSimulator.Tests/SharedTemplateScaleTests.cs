using System.Diagnostics;
using MeterSimulator.DLMS;
using MeterSimulator.Models;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Guards the property that makes a large fleet possible: a meter must cost a small delta on top of
/// a SHARED template model, not its own copy of one.
///
/// Before the shared model, every meter re-parsed the whole template (4 MB of XML for
/// Values_SZ0000014HP) and retained its own object graph — several MB each, so a big batch could not
/// fit in RAM at all. The thresholds below are deliberately loose: they are not performance targets,
/// they exist to fail loudly if per-meter template loading is ever reintroduced, which would blow
/// them by two orders of magnitude.
/// </summary>
public class SharedTemplateScaleTests
{
    private readonly ITestOutputHelper _out;
    public SharedTemplateScaleTests(ITestOutputHelper output) => _out = output;

    private static string TemplatePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Templates", name);

    [Theory]
    [InlineData("Values_SZ0000014HP.xml", 150)]   // 4 MB template — the worst case
    [InlineData("SA1231166HP_values.xml", 60)]    // 0.1 MB template
    public void MeterCost_StaysFarBelowTemplateSize(string template, double maxKbPerMeter)
    {
        const int count = 50;
        string path = TemplatePath(template);

        // Warm the cache first: the one-off template parse is not a per-meter cost.
        var warm = new DLMSServerSession(new DLMSMeter(0, "1.0.0.0.0.255", 16, 1), path);
        warm.Initialize(true);

        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        long before = GC.GetTotalMemory(true);
        var sw = Stopwatch.StartNew();

        var sessions = new List<DLMSServerSession>(count);
        for (int i = 1; i <= count; i++)
        {
            var s = new DLMSServerSession(new DLMSMeter(i, "1.0.0.0.0.255", 16, 1), path);
            s.Initialize(true);
            sessions.Add(s);
        }

        sw.Stop();
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
        long after = GC.GetTotalMemory(true);

        double kbPerMeter = (after - before) / 1024.0 / count;
        _out.WriteLine($"{template}: {kbPerMeter:F1} KB/meter, {sw.Elapsed.TotalMilliseconds / count:F2} ms/meter");

        Assert.Equal(count, sessions.Count);
        Assert.True(kbPerMeter < maxKbPerMeter,
            $"{template}: {kbPerMeter:F1} KB/meter exceeds {maxKbPerMeter} KB — the template model is " +
            "probably being built per meter again instead of shared (see TemplateModelCache).");
    }

    /// <summary>
    /// The template is parsed once however many meters use it — the cache is what turns a
    /// multi-megabyte per-meter cost into a shared one.
    /// </summary>
    [Fact]
    public void Template_IsParsedOnce_AndSharedByEveryMeter()
    {
        string path = TemplatePath("SA1231166HP_values.xml");

        var a = new DLMSServerSession(new DLMSMeter(101, "1.0.0.0.0.255", 16, 1), path);
        var b = new DLMSServerSession(new DLMSMeter(102, "1.0.0.0.0.255", 16, 1), path);
        a.Initialize(true);
        b.Initialize(true);

        // Same profile instance — including its Buffer, which is the bulk of every template.
        var profileA = a.Items.FirstOrDefault(o => o is Gurux.DLMS.Objects.GXDLMSProfileGeneric);
        var profileB = b.Items.FirstOrDefault(o => o is Gurux.DLMS.Objects.GXDLMSProfileGeneric);

        Assert.NotNull(profileA);
        Assert.Same(profileA, profileB);
    }
}
