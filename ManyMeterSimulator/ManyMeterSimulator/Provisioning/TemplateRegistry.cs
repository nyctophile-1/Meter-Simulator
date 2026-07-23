using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Lists the meter DLMS templates (XML files) available on disk and resolves a template name to
/// its full path. A batch references a template by name (see <see cref="MeterBatch"/>); the
/// session factory turns that name into a path here. Also accepts browser uploads, saving them
/// into the same folder so an uploaded template immediately becomes "available".
///
/// Available templates = "whatever .xml is in the folder" — so both built-in (repo-seeded,
/// deployed with the app) and operator-provided (dropped on the server, or uploaded) show up the
/// same way, with no separate list to maintain.
/// </summary>
public sealed class TemplateRegistry
{
    private readonly ILogger<TemplateRegistry> _logger;

    public TemplateRegistry(IOptions<TemplateOptions> options, IHostEnvironment env, ILogger<TemplateRegistry> logger)
    {
        _logger = logger;
        string configured = options.Value.Folder;
        Folder = Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(env.ContentRootPath, configured);
        Directory.CreateDirectory(Folder);
        _logger.LogInformation("Template folder: {Folder}", Folder);
    }

    /// <summary>Absolute path of the templates folder.</summary>
    public string Folder { get; }

    /// <summary>Template names (bare file names, e.g. "Values_SZ0000014HP.xml"), sorted.</summary>
    public IReadOnlyList<string> List() =>
        Directory.EnumerateFiles(Folder, "*.xml", SearchOption.TopDirectoryOnly)
            .Select(p => Path.GetFileName(p)!)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public bool Exists(string? templateName) => TryResolve(templateName, out _);

    /// <summary>
    /// Resolves a template name to its full path. Rejects anything that isn't a bare ".xml" file
    /// name inside the folder (guards against path traversal from user/UI input).
    /// </summary>
    public bool TryResolve(string? templateName, out string fullPath)
    {
        fullPath = string.Empty;
        if (string.IsNullOrWhiteSpace(templateName))
            return false;

        // Only a bare file name is allowed — no directory components / traversal.
        string name = Path.GetFileName(templateName);
        if (!string.Equals(name, templateName, StringComparison.Ordinal))
            return false;
        if (!name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            return false;

        string candidate = Path.Combine(Folder, name);
        if (!File.Exists(candidate))
            return false;

        fullPath = candidate;
        return true;
    }

    public string ResolveOrThrow(string? templateName)
    {
        if (!TryResolve(templateName, out string path))
            throw new FileNotFoundException($"Template '{templateName}' not found in {Folder}.");
        return path;
    }

    /// <summary>
    /// Saves an uploaded template stream as <paramref name="fileName"/> into the folder and
    /// returns the stored (bare) template name. Overwrites an existing same-named template.
    /// </summary>
    public async Task<string> SaveUploadAsync(string fileName, Stream content, CancellationToken cancellationToken = default)
    {
        string name = Path.GetFileName(fileName);
        if (string.IsNullOrWhiteSpace(name) || !name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Template must be a .xml file.", nameof(fileName));

        string dest = Path.Combine(Folder, name);
        await using (var fs = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            await content.CopyToAsync(fs, cancellationToken);
        }

        _logger.LogInformation("Saved uploaded template {Name} to {Path}", name, dest);
        return name;
    }
}
