namespace ManyMeterSimulator.Provisioning;

/// <summary>Where meter DLMS templates (XML) live. Bound from the "Templates" config section.</summary>
public sealed class TemplateOptions
{
    public const string SectionName = "Templates";

    /// <summary>
    /// Folder holding template .xml files. Relative paths resolve against the app content root.
    /// On the Linux box this is the folder deployed alongside the app; operators can drop XML
    /// files here directly, and browser uploads are saved here too.
    /// </summary>
    public string Folder { get; set; } = "Templates";
}
