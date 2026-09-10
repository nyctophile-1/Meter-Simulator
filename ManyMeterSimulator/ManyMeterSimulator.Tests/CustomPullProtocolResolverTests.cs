using ManyMeterSimulator.Networking.SmartNic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ManyMeterSimulator.Tests;

public class CustomPullProtocolResolverTests
{
    private static HesDataModel LoadFrom(string content)
    {
        string folder = Path.Combine(Path.GetTempPath(), $"custom-pull-profile-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "MeterTemplate.csv"), content);
            return new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static HesDataModel LoadFrom(string templates, string magics)
    {
        string folder = Path.Combine(Path.GetTempPath(), $"custom-pull-profile-{Guid.NewGuid():N}");
        Directory.CreateDirectory(folder);
        try
        {
            File.WriteAllText(Path.Combine(folder, "MeterTemplate.csv"), templates);
            File.WriteAllText(Path.Combine(folder, "MagicNumberMapping.csv"), magics);
            return new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);
        }
        finally
        {
            Directory.Delete(folder, true);
        }
    }

    private static MeterBatch Batch(int? templateId) => new()
    {
        Id = 8,
        Name = "wirepas",
        TemplateName = "meter.xml",
        StartIndex = 1,
        Count = 1,
        HesTemplateId = templateId
    };

    [Fact]
    public void ResolvesLegacyWidthsFromTheBatchTemplate()
    {
        const string header = "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"IsFG23\"\n";
        var resolver = new CustomPullProtocolResolver(LoadFrom(header + "\"41\",\"legacy\",\"10\",\"10\",\"0\"\n"));

        Assert.True(resolver.TryResolve(Batch(41), out CustomPullProtocolProfile profile, out string error), error);
        Assert.Equal(CustomPullWireProfile.Legacy, profile.WireProfile);
        Assert.Null(profile.ResponseMagicNumber);
    }

    [Fact]
    public void ResolvesFg23LegacyWithFourByteNodeIds()
    {
        const string rows = "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"IsFG23\"\n" +
            "\"42\",\"fg23\",\"10\",\"10\",\"1\"\n";
        var resolver = new CustomPullProtocolResolver(LoadFrom(rows));

        Assert.True(resolver.TryResolve(Batch(42), out CustomPullProtocolProfile profile, out string error), error);
        Assert.Equal(CustomPullWireProfile.LegacyFg23, profile.WireProfile);
    }

    [Fact]
    public void ResolvesNewHeaderOnlyWithOneMagicMapping()
    {
        const string templates = "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"IsFG23\"\n" +
            "\"43\",\"new\",\"12\",\"12\",\"0\"\n";
        const string magics = "\"MagicNumber\",\"TemplateId\"\n\"551\",\"43\"\n";
        var resolver = new CustomPullProtocolResolver(LoadFrom(templates, magics));

        Assert.True(resolver.TryResolve(Batch(43), out CustomPullProtocolProfile profile, out string error), error);
        Assert.Equal(CustomPullWireProfile.NewHeader, profile.WireProfile);
        Assert.Equal(551u, profile.ResponseMagicNumber);
    }

    [Theory]
    [InlineData(null, "has no HES template id")]
    [InlineData(404, "is absent")]
    public void RefusesMissingBatchOrMetadata(int? templateId, string expectedError)
    {
        var resolver = new CustomPullProtocolResolver(LoadFrom("\"Id\"\n"));

        Assert.False(resolver.TryResolve(Batch(templateId), out _, out string error));
        Assert.Contains(expectedError, error);
    }

    [Fact]
    public void RefusesInconsistentHeadersAndAmbiguousMagic()
    {
        const string templates = "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"IsFG23\"\n" +
            "\"44\",\"bad\",\"10\",\"12\",\"0\"\n" +
            "\"45\",\"ambiguous\",\"12\",\"12\",\"0\"\n";
        const string magics = "\"MagicNumber\",\"TemplateId\"\n\"10\",\"45\"\n\"11\",\"45\"\n";
        var resolver = new CustomPullProtocolResolver(LoadFrom(templates, magics));

        Assert.False(resolver.TryResolve(Batch(44), out _, out string inconsistent));
        Assert.Contains("incompatible custom header lengths", inconsistent);

        Assert.False(resolver.TryResolve(Batch(45), out _, out string ambiguous));
        Assert.Contains("select one explicitly", ambiguous);
    }
}
