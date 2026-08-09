using System.Net;
using System.Text;
using ManyMeterSimulator.Networking;
using ManyMeterSimulator.Networking.Nic;
using MeterSimulator.Models;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Provisioning;

/// <summary>
/// Download endpoint for a batch's meter registration list (index, node id, serial, IPv6, port) —
/// the same shape the HES is registered with. Node id is present for every NIC; the IPv6 and port
/// columns are blank for the MQTT NICs, which have no per-meter address. Streamed rather than built
/// in memory so a large batch (millions of meters) downloads without materialising the whole file.
/// Any authenticated user may download.
/// </summary>
public static class BatchEndpoints
{
    public static void MapBatchEndpoints(this WebApplication app)
    {
        app.MapGet("/batches/{id:int}/meters.csv",
            (int id, MeterRegistry registry, IOptions<TcpOptions> tcp) =>
            {
                MeterBatch? batch = registry.Batches.FirstOrDefault(b => b.Id == id);
                if (batch is null)
                {
                    return Results.NotFound();
                }

                string prefix = tcp.Value.AddressPrefix;
                bool isTcp = batch.NicType == NicType.Tcp4G;
                string port = isTcp ? tcp.Value.ListenPort.ToString() : string.Empty;
                string templateName = batch.TemplateName;
                string nic = batch.NicType.ToString();
                string fileName = $"batch-{SanitizeFileName(batch.Name)}-meters.csv";

                return Results.Stream(async stream =>
                {
                    // UTF-8 BOM + quoted fields to match the existing registration CSV format.
                    await using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
                    await writer.WriteLineAsync("\"index\",\"nodeid\",\"serial\",\"nic\",\"ipv6\",\"port\",\"template\"");
                    foreach ((long index, IPAddress address, string serial) in registry.GetMeters(batch, prefix))
                    {
                        string ip = isTcp ? address.ToString() : string.Empty;
                        await writer.WriteLineAsync(
                            $"\"{index}\",\"{MeterIdentity.NodeId(index)}\",\"{serial}\",\"{nic}\",\"{ip}\",\"{port}\",\"{templateName}\"");
                    }
                }, "text/csv", fileName);
            })
            .RequireAuthorization();

        // Every meter in every batch, one file. Registering a whole fleet with the HES otherwise
        // means downloading each batch and concatenating by hand, which is exactly where a
        // duplicated or skipped batch creeps in. Same columns and row format as the per-batch
        // file, plus a "batch" column so any row can still be traced back to where it came from.
        app.MapGet("/batches/meters.csv",
            (MeterRegistry registry, IOptions<TcpOptions> tcp) =>
            {
                string prefix = tcp.Value.AddressPrefix;
                string tcpPort = tcp.Value.ListenPort.ToString();

                // Snapshot up front: the stream callback runs after this handler returns, so a
                // batch added or deleted midway would otherwise change what we iterate.
                List<MeterBatch> batches = registry.Batches.OrderBy(b => b.StartIndex).ToList();

                return Results.Stream(async stream =>
                {
                    await using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
                    await writer.WriteLineAsync("\"index\",\"nodeid\",\"serial\",\"nic\",\"ipv6\",\"port\",\"template\",\"batch\"");

                    foreach (MeterBatch batch in batches)
                    {
                        bool isTcp = batch.NicType == NicType.Tcp4G;
                        string port = isTcp ? tcpPort : string.Empty;
                        string nic = batch.NicType.ToString();
                        string batchName = EscapeCsv(batch.Name);
                        string templateName = EscapeCsv(batch.TemplateName);

                        foreach ((long index, IPAddress address, string serial) in registry.GetMeters(batch, prefix))
                        {
                            string ip = isTcp ? address.ToString() : string.Empty;
                            await writer.WriteLineAsync(
                                $"\"{index}\",\"{MeterIdentity.NodeId(index)}\",\"{serial}\",\"{nic}\",\"{ip}\",\"{port}\",\"{templateName}\",\"{batchName}\"");
                        }
                    }
                }, "text/csv", "all-meters.csv");
            })
            .RequireAuthorization();
    }

    /// <summary>
    /// Doubles embedded quotes, per RFC 4180. Batch names are operator-entered free text, so one
    /// containing a quote would otherwise break every column after it on that row.
    /// </summary>
    private static string EscapeCsv(string value) => value.Replace("\"", "\"\"");

    private static string SanitizeFileName(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-');
        }

        string cleaned = sb.ToString().Trim('-');
        return string.IsNullOrEmpty(cleaned) ? "batch" : cleaned;
    }
}
