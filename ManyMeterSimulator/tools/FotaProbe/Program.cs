using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using ManyMeterSimulator.Fota;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

if (args.Length != 4)
{
    Console.Error.WriteLine("Usage: FotaProbe begin|complete|verify HOST PORT EXPECTED_VERSION\n" +
        "Offline provisioning (service must be stopped): FotaProbe prepare|stop DATA_ROOT TEMPLATE_ROOT PROBE_NAME");
    return 2;
}

try
{
    if (args[0] is "prepare" or "stop")
    {
        var registry = new MeterRegistry(new JsonBatchStore(Path.Combine(args[1], "batches.json")));
        string name = "FOTA verification " + args[3];
        MeterBatch? batch = registry.Batches.SingleOrDefault(candidate => candidate.Name == name);
        if (args[0] == "stop")
        {
            if (batch is null || batch.Count != 2 || batch.EnvironmentKey is not null)
            {
                throw new InvalidOperationException("Dedicated unbound probe batch not found.");
            }

            registry.TryStop(batch.Id);
            Console.WriteLine(JsonSerializer.Serialize(new { batch.Id, batch.StartIndex, Status = "Stopped" }));
            return 0;
        }

        if (batch is not null)
        {
            throw new InvalidOperationException("Probe already exists; use its recorded index instead of reprovisioning.");
        }

        var templates = new TemplateRegistry(Options.Create(new TemplateOptions { Folder = Path.GetFullPath(args[2]) }),
            new ProbeEnvironment(), NullLogger<TemplateRegistry>.Instance);
        const string template = "SA1231166HP_values.xml";
        templates.ResolveOrThrow(template);
        batch = registry.AddBatch(name, template, 2);
        var fota = new FotaService(templates, Path.GetFullPath(args[1]), new());
        fota.SaveSettings(batch, batch.StartIndex, new() { Enabled = true, BlockSize = 200, TargetVersion = args[3] });
        registry.TryStart(batch.Id);
        Console.WriteLine(JsonSerializer.Serialize(new { batch.Id, batch.StartIndex, batch.Count, TargetVersion = args[3] }));
        return 0;
    }

    if (args[0] is not ("begin" or "complete" or "verify"))
    {
        throw new ArgumentException("Unknown probe mode.");
    }

    using var socket = new TcpClient(AddressFamily.InterNetworkV6);
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    await socket.ConnectAsync(IPAddress.Parse(args[1]), int.Parse(args[2]), timeout.Token);
    socket.ReceiveTimeout = 15000;
    socket.SendTimeout = 15000;
    using NetworkStream stream = socket.GetStream();
    var client = new GXDLMSSecureClient(true, 0x30, 1, Authentication.High, "AAAAAAAAAAAAAAAA", InterfaceType.WRAPPER);
    client.Ciphering.Security = Security.AuthenticationEncryption;
    client.Ciphering.BlockCipherKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
    client.Ciphering.AuthenticationKey = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
    client.Ciphering.SystemTitle = Encoding.ASCII.GetBytes("FOTAPROB");

    GXReplyData Send(byte[] request)
    {
        stream.Write(request);
        byte[] header = new byte[8];
        stream.ReadExactly(header);
        int length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(6));
        byte[] response = new byte[8 + length];
        header.CopyTo(response, 0);
        stream.ReadExactly(response.AsSpan(8));
        var reply = new GXReplyData();
        if (!client.GetData(new GXByteBuffer(response), reply, new GXReplyData()) || reply.Error != 0)
        {
            throw new IOException($"DLMS exchange failed: {reply.Error}.");
        }

        return reply;
    }

    object Read(GXDLMSObject target, int attribute) => Send(client.Read(target, attribute)[0]).Value;
    void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    client.ParseAAREResponse(Send(client.AARQRequest()[0]).Data);
    client.ParseApplicationAssociationResponse(Send(client.GetApplicationAssociationRequest()[0]).Data);
    var image = new GXDLMSImageTransfer(DLMSServerSession.ImageTransferObis);
    image.ImageBlockSize = Convert.ToUInt32(Read(image, 2));
    Require(image.ImageBlockSize is >= 32 and <= 4096, "Unexpected block size.");
    byte[] payload = new byte[image.ImageBlockSize * 2 + 1];
    byte[][] blocks = image.ImageBlockTransfer(client, payload, out _);

    if (args[0] == "begin")
    {
        Require(Convert.ToBoolean(Read(image, 5)), "FOTA is disabled.");
        Send(image.ImageTransferInitiate(client, Encoding.ASCII.GetBytes("MAYA-FOTA-PROBE"), payload.Length)[0]);
        Send(blocks[2]);
        Send(blocks[0]);
        Require(Convert.ToUInt32(Read(image, 4)) == 1, "Expected missing block 1.");
        Require(Read(image, 3).ToString() == "101", "Expected bitmap 101.");
    }
    else
    {
        if (args[0] == "complete")
        {
            Require(Convert.ToUInt32(Read(image, 4)) == 1, "Persisted resume position was lost.");
            Send(blocks[1]);
            Send(image.ImageVerify(client)[0]);
            Require(Read(image, 7) is GXArray { Count: 1 }, "Missing activation information.");
            Send(image.ImageActivate(client)[0]);
        }

        Require(Convert.ToByte(Read(image, 6)) == 6, "Expected activation successful.");
        object version = Read(new GXDLMSData(DLMSServerSession.FirmwareVersionObis), 2);
        string actual = version is byte[] bytes ? Encoding.UTF8.GetString(bytes) : version.ToString()!;
        Require(actual == args[3], $"Version mismatch: {actual}.");
    }

    Console.WriteLine(JsonSerializer.Serialize(new
    {
        Result = "PASS", Mode = args[0], Host = args[1], BlockSize = image.ImageBlockSize,
        Bitmap = Read(image, 3).ToString(), FirstMissing = Read(image, 4), Status = Read(image, 6)
    }));
    Send(client.ReleaseRequest()[0]);
    return 0;
}
catch (Exception exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}

internal sealed class ProbeEnvironment : IHostEnvironment
{
    public string EnvironmentName { get; set; } = "Verification";
    public string ApplicationName { get; set; } = "FotaProbe";
    public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
}
