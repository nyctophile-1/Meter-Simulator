using System.Text;
using System.Text.Json;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Appends every captured broker message to <c>data/captures/&lt;nic&gt;-&lt;date&gt;.jsonl</c> —
/// one JSON object per line, so a capture can be tailed live, diffed, and replayed.
///
/// This is the ground truth the Phase E/F/G codecs are written against (virtual_nics.md §9): the
/// HES source tells us what the framing SHOULD be, and these files tell us what it actually is.
/// Where they disagree, these win.
///
/// Lands in the persistent <c>data/</c> folder (sibling of the deployment), so captures survive a
/// redeploy like the batch store does.
/// </summary>
public sealed class NicCaptureWriter
{
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };

    private readonly string _folder;
    private readonly ILogger<NicCaptureWriter> _logger;
    private readonly object _writeLock = new();

    public NicCaptureWriter(IOptions<PersistenceOptions> persistence, IHostEnvironment env, ILogger<NicCaptureWriter> logger)
    {
        string configured = persistence.Value.Folder;
        string dataFolder = Path.IsPathRooted(configured)
            ? configured
            : Path.Combine(env.ContentRootPath, configured);

        _folder = Path.GetFullPath(Path.Combine(dataFolder, "captures"));
        _logger = logger;
    }

    public string Folder => _folder;

    /// <summary>
    /// Records one message. Synchronous under a lock: capture is a diagnostic mode, not the steady
    /// state, and losing interleaving would make a multi-fragment exchange unreadable — which is
    /// the exact thing captures exist to explain.
    /// </summary>
    public void Write(NicType nic, NicEnvelope envelope, string? nodeId) =>
        Write(nic, "in", envelope.Topic, nodeId, envelope.Payload, envelope.ReceivedAtUtc);

    /// <summary>
    /// Records one message in either direction. Capturing what we SEND is what makes a capture file
    /// diagnosable on its own: without it, a stalled exchange can only be explained by replaying
    /// requests offline and inferring the reply, which is slow and easy to get wrong.
    /// </summary>
    public void Write(NicType nic, string direction, string topic, string? nodeId, byte[] payload, DateTimeOffset? at = null)
    {
        var record = new CaptureRecord(
            at ?? DateTimeOffset.UtcNow,
            nic.ToString(),
            direction,
            topic,
            nodeId,
            payload.Length,
            Convert.ToHexString(payload));

        try
        {
            lock (_writeLock)
            {
                Directory.CreateDirectory(_folder);
                string path = Path.Combine(_folder, $"{nic}-{DateTime.UtcNow:yyyy-MM-dd}.jsonl");
                File.AppendAllText(path, JsonSerializer.Serialize(record, Json) + Environment.NewLine, Encoding.UTF8);
            }
        }
        catch (Exception ex)
        {
            // Never let a capture failure (full disk, permissions) affect the traffic being captured.
            _logger.LogError(ex, "Failed to write capture for {Nic} on {Topic}", nic, topic);
        }
    }

    private sealed record CaptureRecord(
        DateTimeOffset Ts,
        string Nic,
        /// <summary>"in" = HES → meter, "out" = meter → HES.</summary>
        string Dir,
        string Topic,
        string? NodeId,
        int Length,
        string PayloadHex);
}
