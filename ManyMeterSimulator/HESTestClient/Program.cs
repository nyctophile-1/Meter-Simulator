using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ManyMeterSimulator.Framing;
using ManyMeterSimulator.Provisioning;

// Simple stand-in for HES, for local testing of nic_sim (NOT the real staging HES).
// Opens one connection per meter, all concurrently, does N request/response exchanges per
// connection using the same DLMS WPDU framing nic_sim speaks, then closes.
//
// Usage: dotnet run -- [meterCount] [addressPrefix] [port] [exchangesPerSession]
// Defaults simulate 100 meters against the reserved prefix. Pass "::" as the prefix with
// meterCount=1 to point at ::1 (loopback) for a quick sanity check without needing the
// Windows loopback multi-address route set up.

const int ConnectTimeoutMs = 10_000;
const int ExchangeTimeoutMs = 10_000;

int meterCount = args.Length > 0 ? int.Parse(args[0]) : 100;
string addressPrefix = args.Length > 1 ? args[1] : "fd00:6d65:7472::";
int port = args.Length > 2 ? int.Parse(args[2]) : 4059;
int exchangesPerSession = args.Length > 3 ? int.Parse(args[3]) : 10;

List<IPAddress> meterAddresses = Enumerable.Range(1, meterCount)
    .Select(i => MeterAddressing.ComputeAddress(addressPrefix, i))
    .ToList();

Console.WriteLine($"HES test client: {meterCount} meters, {exchangesPerSession} exchanges each, port {port}");
Console.WriteLine($"First address: {meterAddresses[0]}, last address: {meterAddresses[^1]}");
Console.WriteLine();

var results = new ConcurrentBag<MeterResult>();
var stopwatch = Stopwatch.StartNew();

await Task.WhenAll(meterAddresses.Select(addr => RunMeterSessionAsync(addr, meterCount, port, exchangesPerSession, results)));

stopwatch.Stop();

int succeeded = results.Count(r => r.Success);
int failed = results.Count(r => !r.Success);

Console.WriteLine();
Console.WriteLine($"Done in {stopwatch.Elapsed.TotalSeconds:F1}s - {succeeded}/{meterCount} succeeded, {failed} failed");

if (failed > 0)
{
    Console.WriteLine();
    Console.WriteLine("Failures:");
    foreach (MeterResult r in results.Where(r => !r.Success).OrderBy(r => r.MeterId))
    {
        Console.WriteLine($"  {r.MeterId}: {r.Error}");
    }
}

// Double-clicking this exe opens a console window that Windows closes the instant the process
// exits, which would otherwise hide the summary above. Skip the pause when input is redirected
// (e.g. run from a script/CI) so automated runs don't hang waiting for a keypress.
if (!Console.IsInputRedirected)
{
    Console.WriteLine();
    Console.WriteLine("Press any key to exit...");
    Console.ReadKey();
}

static async Task RunMeterSessionAsync(IPAddress meterId, int meterCount, int port, int exchangesPerSession, ConcurrentBag<MeterResult> results)
{
    try
    {
        using var client = new TcpClient(AddressFamily.InterNetworkV6);
        using (var connectCts = new CancellationTokenSource(ConnectTimeoutMs))
        {
            await client.ConnectAsync(meterId, port, connectCts.Token);
        }

        await using NetworkStream stream = client.GetStream();
        PipeReader reader = PipeReader.Create(stream);
        PipeWriter writer = PipeWriter.Create(stream);

        for (int exchange = 1; exchange <= exchangesPerSession; exchange++)
        {
            byte[] requestPayload = Encoding.ASCII.GetBytes($"req-{exchange}");
            byte[] requestFrame = DlmsWpduFramer.BuildFrame(sourceWPort: 1, destinationWPort: 1, requestPayload);

            using var exchangeCts = new CancellationTokenSource(ExchangeTimeoutMs);
            await writer.WriteAsync(requestFrame, exchangeCts.Token);

            WpduFrame? response = await DlmsWpduFramer.ReadFrameAsync(reader, exchangeCts.Token);
            if (response is null)
            {
                throw new IOException($"nic_sim closed the connection unexpectedly after exchange {exchange - 1}");
            }

            if (meterCount <= 5)
            {
                Console.WriteLine($"  [{meterId}] exchange {exchange}/{exchangesPerSession} ok ({response.Payload.Length} bytes)");
            }
        }

        results.Add(new MeterResult(meterId.ToString(), true, null));
    }
    catch (Exception ex)
    {
        results.Add(new MeterResult(meterId.ToString(), false, ex.Message));
    }
}

record MeterResult(string MeterId, bool Success, string? Error);
