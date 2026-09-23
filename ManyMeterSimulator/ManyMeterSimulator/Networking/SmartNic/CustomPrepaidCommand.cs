using System.Globalization;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.Options;
using MeterSimulator.DLMS;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// Handles HES command 70. The custom NIC owns one isolated DLMS association, reads RTC plus the
/// five prepaid objects, and returns one packed response; HES never sees the intermediate DLMS.
/// </summary>
public sealed class CustomPrepaidCommand(
    MeterSessionManager sessions,
    HesDataModel model,
    IOptions<CustomPullOptions> options)
{
    private readonly CustomPullOptions _options = options.Value;

    private static readonly (string Parameter, bool IsTime)[] Fields =
    {
        ("GetLastRechargeAmount", false),
        ("GetLastRechargeTime", true),
        ("GetTotalAmountAtLastRecharge", false),
        ("GetPrepaidBalance", false),
        ("GetCurrentBalanceTime", true),
    };

    public byte[] Execute(CustomPullInbound inbound, CancellationToken cancellationToken)
    {
        if (inbound.Intent.Command != CustomCommandType.GetAllPrepaidParameters ||
            inbound.Intent.Selector != CustomDataSelector.GetWithoutData)
            throw new NotSupportedException("Only custom GetAllPrepaidParameters is implemented here.");
        if (inbound.Batch.Status != BatchStatus.Running || inbound.Meter.Nic != NicType.MqttWirepas)
            throw new InvalidOperationException("Custom prepaid requires a running Wirepas batch.");
        if (!model.TryGetTemplate(inbound.Protocol.HesTemplateId, out MeterTemplateRow template))
            throw new InvalidOperationException("HES template is unavailable.");
        if (!_options.MeterCategories.TryGetValue(template.Id, out string? category) || category is not ("1P" or "3P" or "CT"))
            throw new InvalidOperationException($"Configure CustomPull:MeterCategories:{template.Id} as 1P, 3P or CT.");
        (inbound.Protocol with { MeterProfileHeaderTemplateId = template.MeterProfileHeaderTemplateId }).ValidateResponseHeader();

        AttributeMapping rtcMapping = RequiredMapping(category, "GetRTC");
        AttributeMapping[] fieldMappings = Fields.Select(field => RequiredMapping(category, field.Parameter)).ToArray();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.ReadTimeoutSeconds, 1, 120)));
        DLMSServerSession association = sessions.GetOrCreate(inbound.Meter).CreateReadAssociation();
        try
        {
            using var reader = new Reader(association, _options, timeout.Token);
            GXDateTime rtc = DateValue(reader.Read(new GXDLMSClock(rtcMapping.ObisCode), rtcMapping.AttributeIndex), "RTC");
            object[] values = new object[Fields.Length];
            for (int index = 0; index < Fields.Length; index++)
            {
                object? raw = reader.Read(new GXDLMSData(fieldMappings[index].ObisCode), fieldMappings[index].AttributeIndex);
                values[index] = Fields[index].IsTime
                    ? DateValue(raw, Fields[index].Parameter)
                    : IntValue(raw, Fields[index].Parameter);
            }
            return Encode(inbound, rtc, (int)values[0], (GXDateTime)values[1], (int)values[2],
                (int)values[3], (GXDateTime)values[4]);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Custom prepaid DLMS read timed out.");
        }
        finally
        {
            association.Reset();
        }
    }

    private AttributeMapping RequiredMapping(string category, string parameter) =>
        model.TryGetUniqueAttribute(category, parameter, out AttributeMapping mapping)
            ? mapping
            : throw new InvalidOperationException($"Expected one HES OBIS mapping for {category}/{parameter}.");

    public static byte[] Encode(
        CustomPullInbound inbound,
        GXDateTime rtc,
        int lastRechargeAmount,
        GXDateTime lastRechargeTime,
        int totalAmountAtLastRecharge,
        int currentBalanceAmount,
        GXDateTime currentBalanceTime)
    {
        inbound.Protocol.ValidateResponseHeader();
        byte[] header = CustomProfileCommand.Header(inbound, inbound.Intent.RawCommandType, 1);
        using var body = new MemoryStream();
        body.Write(header);
        using var writer = new BinaryWriter(body);
        uint rtcEpoch = Epoch(rtc, "RTC");
        writer.Write(rtcEpoch);
        writer.Write((byte)4); // HES NonDLMSDataParser: four-byte RTC payload
        writer.Write((byte)6); // HES custom UInt32 epoch type
        writer.Write(lastRechargeAmount);
        writer.Write(Epoch(lastRechargeTime, "last recharge time"));
        writer.Write(totalAmountAtLastRecharge);
        writer.Write(currentBalanceAmount);
        writer.Write(Epoch(currentBalanceTime, "current balance time"));
        IReadOnlyList<byte[]> packets = CustomProfileCommand.Frame(inbound, body.ToArray());
        if (packets.Count != 1) throw new InvalidOperationException("A prepaid response must fit in one custom packet.");
        return packets[0];
    }

    private static int IntValue(object? raw, string parameter)
    {
        try { return Convert.ToInt32(raw, CultureInfo.InvariantCulture); }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        { throw new InvalidDataException($"Meter returned an invalid {parameter} value.", ex); }
    }

    private static GXDateTime DateValue(object? raw, string parameter) => raw switch
    {
        GXDateTime value => RequireConcrete(value, parameter),
        DateTime value => new GXDateTime(DateTime.SpecifyKind(value, DateTimeKind.Utc)),
        DateTimeOffset value => new GXDateTime(value.UtcDateTime),
        byte[] value => RequireConcrete((GXDateTime)GXDLMSClient.ChangeType(value, DataType.DateTime), parameter),
        _ => throw new InvalidDataException($"Meter returned an invalid {parameter} value."),
    };

    private static GXDateTime RequireConcrete(GXDateTime value, string parameter)
    {
        DateTimeSkips required = DateTimeSkips.Year | DateTimeSkips.Month | DateTimeSkips.Day |
                                 DateTimeSkips.Hour | DateTimeSkips.Minute | DateTimeSkips.Second;
        if ((value.Skip & required) != 0)
            throw new InvalidDataException($"Meter returned a wildcard {parameter} value.");
        return value;
    }

    private static uint Epoch(GXDateTime value, string parameter)
    {
        RequireConcrete(value, parameter);
        DateTime wallClock = DateTime.SpecifyKind(value.Value.DateTime, DateTimeKind.Utc);
        return checked((uint)new DateTimeOffset(wallClock).ToUnixTimeSeconds());
    }

    private sealed class Reader : IDisposable
    {
        private readonly DLMSServerSession _server;
        private readonly CustomPullOptions _options;
        private readonly CancellationToken _token;
        private readonly GXDLMSClient _client = new(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        private int _blocks;
        private int _bytes;

        public Reader(DLMSServerSession server, CustomPullOptions options, CancellationToken token)
        {
            _server = server;
            _options = options;
            _token = token;
            _client.ParseAAREResponse(Exchange(_client.AARQRequest()).Data);
        }

        public object? Read(GXDLMSObject target, int attribute) => Exchange(_client.Read(target, attribute)).Value;

        private GXReplyData Exchange(byte[][] requests)
        {
            var reply = new GXReplyData();
            foreach (byte[] request in requests)
            {
                Receive(request, reply);
                while (reply.IsMoreData) Receive(_client.ReceiverReady(reply), reply);
            }
            return reply;
        }

        private void Receive(byte[] request, GXReplyData reply)
        {
            _token.ThrowIfCancellationRequested();
            if (++_blocks > _options.MaxDlmsBlocks) throw new InvalidOperationException("DLMS block limit exceeded.");
            byte[] response = _server.HandleRequest(request) ?? [];
            _bytes = checked(_bytes + response.Length);
            if (_bytes > _options.MaxResponseBytes) throw new InvalidOperationException("DLMS response byte limit exceeded.");
            if (response.Length == 0 || !_client.GetData(response, reply) || reply.Error != 0)
                throw new InvalidOperationException($"Custom prepaid DLMS read failed ({reply.Error}).");
        }

        public void Dispose()
        {
            if (!_token.IsCancellationRequested)
                foreach (byte[] request in _client.ReleaseRequest() ?? []) _server.HandleRequest(request);
        }
    }
}
