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
    }

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
