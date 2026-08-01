using ManyMeterSimulator.Networking.SmartNic;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// The loader treats the CSVs as truth: no cross-table validation, no fallbacks, no guessing. A
/// template that turns out to be wrong is a finding to fix in HES and re-export, not something to
/// paper over here — so these tests check that data is read FAITHFULLY, not that it is sensible.
/// </summary>
public class HesDataModelTests
{
    private readonly ITestOutputHelper _output;

    public HesDataModelTests(ITestOutputHelper output) => _output = output;

    private static HesDataModel LoadFrom(string folder) =>
        new HesDataModelLoader(NullLogger<HesDataModelLoader>.Instance).Load(folder);

    private static string WriteFixture(params (string Name, string Content)[] files)
    {
        string dir = Path.Combine(Path.GetTempPath(), $"hesdm-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        foreach ((string name, string content) in files)
        {
            File.WriteAllText(Path.Combine(dir, name), content);
        }

        return dir;
    }

    [Fact]
    public void AbsentFolder_LoadsAnEmptyModel_RatherThanThrowing()
    {
        // A deployment that never uses the custom channel need not ship the exports at all.
        HesDataModel model = LoadFrom(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}"));

        Assert.Equal(0, model.TemplateCount);
        Assert.False(model.TryGetTemplate(1, out _));
    }

    [Fact]
    public void ReadsQuotedCsv_IncludingCommasAndDoubledQuotes()
    {
        string dir = WriteFixture(("MeterTemplate.csv",
            "\"Id\",\"TemplateName\",\"PushHeaderLength\",\"PullHeaderLength\",\"PushPayloadType\",\"PullPayloadType\",\"IsFG23\"\n" +
            "\"133\",\"MonteCarlo/NCC-MSEDCL-RF, 63 Bill\",\"12\",\"12\",\"2\",\"2\",\"0\"\n" +
            "\"136\",\"Anvil \"\"Sikkim\"\" KMESH\",\"0\",\"7\",\"3\",\"3\",\"1\"\n"));

        try
        {
            HesDataModel model = LoadFrom(dir);

            Assert.True(model.TryGetTemplate(133, out MeterTemplateRow rf));
            Assert.Equal("MonteCarlo/NCC-MSEDCL-RF, 63 Bill", rf.TemplateName);   // embedded comma
            Assert.Equal(12, rf.PullHeaderLength);
            Assert.True(rf.UsesNewHeader);

            Assert.True(model.TryGetTemplate(136, out MeterTemplateRow kmesh));
            Assert.Equal("Anvil \"Sikkim\" KMESH", kmesh.TemplateName);           // doubled quotes
            Assert.False(kmesh.UsesNewHeader);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    /// <summary>
    /// Field order IS the byte layout, and the export's row order cannot be relied on — so the
    /// loader sorts by SerialNumber. This feeds it deliberately shuffled.
    /// </summary>
    [Fact]
    public void FieldsAreOrderedBySerialNumber_WhateverOrderTheyWereExportedIn()
    {
        string dir = WriteFixture(("MeterTemplateDetail.csv",
            "\"ProfileTemplateId\",\"CommandTypeId\",\"MeterCategory\",\"ParameterName\",\"ProfileType\",\"Profile\",\"SerialNumber\",\"Scalar\",\"DataType\"\n" +
            "\"35\",\"4\",\"3P\",\"Third\",\"BLOCK_CUSTOM_PULL_3P\",\"2\",\"30\",\"0\",\"UInt16\"\n" +
            "\"35\",\"4\",\"3P\",\"First\",\"BLOCK_CUSTOM_PULL_3P\",\"2\",\"10\",\"0\",\"UInt32\"\n" +
            "\"35\",\"4\",\"3P\",\"Second\",\"BLOCK_CUSTOM_PULL_3P\",\"2\",\"20\",\"-2\",\"UInt16\"\n"));

        try
        {
            IReadOnlyList<TemplateField> fields = LoadFrom(dir).GetFields(35, "BLOCK_CUSTOM_PULL_3P");

            Assert.Equal(new[] { "First", "Second", "Third" }, fields.Select(f => f.ParameterName));
            Assert.Equal(-2, fields[1].Scalar);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    /// <summary>
    /// A magic number pointing at a template that has since been re-typed is ordinary drift. It
    /// must load, not fail — the lookup simply never happens for that template.
    /// </summary>
    [Fact]
    public void MagicNumbersLoadEvenWhenTheyPointAtNothing()
    {
        string dir = WriteFixture(
            ("MagicNumberMapping.csv", "\"MagicNumber\",\"TemplateId\"\n\"168823084\",\"122\"\n\"999\",\"99999\"\n"),
            ("MeterTemplate.csv", "\"Id\",\"TemplateName\",\"PullHeaderLength\"\n\"122\",\"HPL\",\"12\"\n"));

        try
        {
            HesDataModel model = LoadFrom(dir);

            Assert.True(model.TryGetTemplateByMagic(168823084, out int templateId));
            Assert.Equal(122, templateId);

            // Loaded despite pointing at a template that is not present.
            Assert.True(model.TryGetTemplateByMagic(999, out int orphan));
            Assert.Equal(99999, orphan);
            Assert.False(model.TryGetTemplate(orphan, out _));

            // Reverse direction: we are the meter, so we emit the magic number for OUR template.
            Assert.True(model.TryGetMagicForTemplate(122, out uint magic));
            Assert.Equal(168823084u, magic);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void AttributeMappingIsKeyedByProfileCategoryAndParameter()
    {
        string dir = WriteFixture(("ProfileAttributeMapping.csv",
            "\"Id\",\"ProfileType\",\"Category\",\"Attribute\",\"ObisCode\",\"IsValidated\",\"AttributeIndex\"\n" +
            "\"x\",\"2\",\"3P\",\"BlockPowerOffDurationInMins\",\"0.0.94.91.16.255\",\"0\",\"2\"\n" +
            "\"y\",\"2\",\"CT\",\"BlockPowerOffDurationInMins\",\"0.0.94.91.16.255\",\"0\",\"2\"\n"));

        try
        {
            HesDataModel model = LoadFrom(dir);

            Assert.True(model.TryGetAttribute(2, "3P", "BlockPowerOffDurationInMins", out AttributeMapping m));
            Assert.Equal("0.0.94.91.16.255", m.ObisCode);
            Assert.Equal(2, m.AttributeIndex);

            // Category is part of the key -- 1P and 3P genuinely differ.
            Assert.False(model.TryGetAttribute(2, "1P", "BlockPowerOffDurationInMins", out _));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    /// <summary>
    /// Loads the REAL exports if they are present and reports what came back. Skipped otherwise,
    /// since the CSVs are gitignored — this is a local "test and find out", not a CI gate.
    /// </summary>
    [Fact]
    public void RealExports_LoadAndJoinUp()
    {
        string folder = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..",
            "ManyMeterSimulator", "KimbalSpecifics", "DataModel"));

        if (!File.Exists(Path.Combine(folder, "MeterTemplate.csv")))
        {
            _output.WriteLine($"skipped: no exports at {folder}");
            return;
        }

        HesDataModel model = LoadFrom(folder);

        _output.WriteLine($"magic numbers : {model.MagicNumberCount}");
        _output.WriteLine($"templates     : {model.TemplateCount}");
        _output.WriteLine($"profile layouts: {model.FieldListCount}");
        _output.WriteLine($"attributes    : {model.AttributeCount}");

        Assert.True(model.TemplateCount > 0);
        Assert.True(model.AttributeCount > 0);

        // Walk one real custom-pull layout end to end: every field should resolve to an OBIS.
        var sample = (ProfileTemplateId: 35, ProfileType: "BLOCK_CUSTOM_PULL_3P");
        IReadOnlyList<TemplateField> fields = model.GetFields(sample.ProfileTemplateId, sample.ProfileType);
        _output.WriteLine($"\n{sample.ProfileType} on template {sample.ProfileTemplateId}: {fields.Count} fields");

        int resolved = 0;
        foreach (TemplateField f in fields.Take(15))
        {
            bool ok = model.TryGetAttribute(f.Profile, f.MeterCategory, f.ParameterName, out AttributeMapping m);
            if (ok)
            {
                resolved++;
            }

            _output.WriteLine($"  {f.SerialNumber,4}  {f.ParameterName,-45} {f.DataType,-10} sc={f.Scalar,-3} -> {(ok ? m.ObisCode : "UNRESOLVED")}");
        }

        _output.WriteLine($"\nresolved {resolved} of {Math.Min(15, fields.Count)} sampled");
    }
}
