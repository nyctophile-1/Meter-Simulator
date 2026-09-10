using System.Collections;
using System.Buffers.Binary;
using System.Globalization;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using ManyMeterSimulator.Brain;
using ManyMeterSimulator.Networking.CustomPush;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using MeterSimulator.DLMS;
using Microsoft.Extensions.Options;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>Reads the simulated meter and packs fields in HES's exported custom-pull order.</summary>
public sealed class CustomProfileCommand(MeterSessionManager sessions, HesDataModel model, IOptions<CustomPullOptions> options)
{
    private readonly CustomPullOptions _options = options.Value;

    public static bool Supports(CustomCommandType command) => (int)command is 3 or 4 or 5 or 6 or 21 or >= 41 and <= 47 or 50 or 83;

    public IReadOnlyList<byte[]> Execute(CustomPullInbound inbound, CancellationToken cancellationToken)
    {
        if (!Supports(inbound.Intent.Command)) throw new NotSupportedException("Not a custom profile read.");
        if (inbound.Batch.Status != BatchStatus.Running || inbound.Meter.Nic != NicType.MqttWirepas)
            throw new InvalidOperationException("Custom profiles require a running Wirepas batch.");
        if (!model.TryGetTemplate(inbound.Protocol.HesTemplateId, out var template))
            throw new InvalidOperationException("HES template is unavailable.");
        if (!_options.MeterCategories.TryGetValue(template.Id, out var category) || category is not ("1P" or "3P" or "CT"))
            throw new InvalidOperationException($"Configure CustomPull:MeterCategories:{template.Id} as 1P, 3P or CT.");
        bool modern = inbound.Protocol.WireProfile == CustomPullWireProfile.NewHeader;
        if (template.MeterProfileHeaderTemplateId is null || (template.MeterProfileHeaderTemplateId == 3) != modern)
            throw new NotSupportedException("Exported meter profile header does not match the custom framing.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_options.ReadTimeoutSeconds, 1, 120)));
        if (_options.ProfileDataSource == "DataModel" || inbound.Intent.Command == CustomCommandType.GRBlockLoadProfile)
        {
            try { return GenerateAndEncode(inbound, template, category, timeout.Token); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            { throw new TimeoutException("Custom profile generation timed out."); }
        }
        if (_options.ProfileDataSource != "Meter") throw new InvalidOperationException("ProfileDataSource must be DataModel or Meter.");
        var association = sessions.GetOrCreate(inbound.Meter).CreateReadAssociation();
        try { return ReadAndEncode(association, inbound, template, category, timeout.Token); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new TimeoutException("Custom profile read timed out."); }
        finally { association.Reset(); }
    }

    private IReadOnlyList<byte[]> GenerateAndEncode(CustomPullInbound inbound, MeterTemplateRow template, string category, CancellationToken token)
    {
        var (_, kind, templateId, responseType) = Describe(inbound.Intent.Command, template);
        var fields = Fields(templateId, kind, category);
        if (inbound.Intent.Command == CustomCommandType.GRBlockLoadProfile)
            return GenerateGapAndEncode(inbound, fields, token);
        int eventId = CustomProfileDataGenerator.EventId(inbound.Intent.Command);
        if (kind == "EVENT")
        {
            if (_options.EventsWithPowerProfile is null) throw new InvalidOperationException("Configure EventsWithPowerProfile from HES.");
            if (!_options.EventsWithPowerProfile.Contains(eventId)) fields = Fields(template.EventNonProfileTemplateId, "EVENTNONPROFILE", category);
        }
        var timestamps = CustomProfileDataGenerator.SelectTimestamps(inbound.Intent, DateTimeOffset.UtcNow, _options);
        var packets = new List<byte[]>();
        int bytes = 0;
        if (timestamps.Count == 0) return Frame(inbound, Header(inbound, 100, 0));
        foreach (var timestamp in timestamps)
        {
            token.ThrowIfCancellationRequested();
            using var body = new MemoryStream();
            body.Write(Header(inbound, responseType, 1));
            foreach (var field in fields)
            {
                // The data model determines layout and scale; this mode intentionally generates
                // engineering values rather than borrowing unrelated/missing XML capture rows.
                object value = CustomProfileDataGenerator.Value(field, inbound.Meter.Index, timestamp, kind, eventId);
                body.Write(EncodeField(field, value, new GXDLMSData(), _options.ResponseTimestampOffsetMinutes));
            }
            foreach (var packet in Frame(inbound, body.ToArray()))
            {
                bytes = checked(bytes + packet.Length);
                if (bytes > _options.MaxResponseBytes) throw new InvalidOperationException("Custom response limit exceeded; request a smaller range.");
                packets.Add(packet);
            }
        }
        return packets;
    }

    private IReadOnlyList<byte[]> GenerateGapAndEncode(CustomPullInbound inbound,
        IReadOnlyList<TemplateField> fields, CancellationToken token)
    {
        var selection = GapBlockSelection.Create(inbound, _options);
        token.ThrowIfCancellationRequested();
        if (selection.Mask == 0) return Frame(inbound, Header(inbound, 100, 0));
        if (!fields.Any(f => f.DataType == "DateTime"))
            throw new NotSupportedException("A gap-reading layout must contain a timestamp to identify each selected block.");
        var selected = new List<byte[]>();
        // Generate the complete logical window, then retain only the slots whose bits are set.
        // No DLMS association is opened: these are synthetic, metadata-defined rows.
        for (int bit = 0; bit < 32; bit++)
        {
            token.ThrowIfCancellationRequested();
            var timestamp = selection.Timestamp(bit);
            var values = fields.Select(field => CustomProfileDataGenerator.Value(field, inbound.Meter.Index,
                timestamp, "BLOCK", 0, selection.PeriodMinutes)).ToArray();
            if (!selection.Includes(bit)) continue;
            using var row = new MemoryStream();
            for (int column = 0; column < fields.Count; column++)
                row.Write(EncodeField(fields[column], values[column], new GXDLMSData(), _options.ResponseTimestampOffsetMinutes));
            selected.Add(row.ToArray());
        }
        using var body = new MemoryStream();
        body.Write(Header(inbound, 19, checked((byte)selected.Count)));
        // Generic HES ParseBlock counts frames down, so reverse wire rows for chronological consumption.
        foreach (byte[] row in selected.AsEnumerable().Reverse()) body.Write(row);
        var packets = Frame(inbound, body.ToArray());
        if (packets.Sum(p => p.Length) > _options.MaxResponseBytes) throw new InvalidOperationException("GR response byte limit exceeded.");
        return packets;
    }

    private IReadOnlyList<byte[]> ReadAndEncode(DLMSServerSession association, CustomPullInbound inbound,
        MeterTemplateRow template, string category, CancellationToken token)
    {
        var (obis, kind, templateId, responseType) = Describe(inbound.Intent.Command, template);
        var source = association.Items.OfType<GXDLMSProfileGeneric>().SingleOrDefault(p => p.LogicalName == obis)
            ?? throw new NotSupportedException($"Meter XML has no {kind} profile {obis}.");
        using var reader = new ProfileReader(association, _options, token);
        // Client operations clear their target buffer. Never pass a shared server object to them.
        var profile = new GXDLMSProfileGeneric(obis);
        foreach (var capture in source.CaptureObjects) profile.CaptureObjects.Add(capture);
        var rows = inbound.Intent.Command == CustomCommandType.GetInstantaneousProfile
            ? new List<object?[]> { source.CaptureObjects.Select(c => reader.Read(c.Key, c.Value.AttributeIndex)).ToArray() }
            : reader.ReadRows(profile, inbound.Intent);
        if (rows.Count > _options.MaxProfileRows) throw new InvalidOperationException("Custom profile row limit exceeded; request a smaller range.");
        var packets = new List<byte[]>();
        int bytes = 0;
        if (rows.Count == 0) packets.AddRange(Frame(inbound, Header(inbound, 100, 0)));
        // HES's daily/billing/instant parsers read one row; event layouts can vary by event ID.
        // A complete body per row also avoids overflowing the new header's 4-bit row count.
        foreach (var row in rows)
        {
            token.ThrowIfCancellationRequested();
            if (row.Length != source.CaptureObjects.Count) throw new InvalidOperationException("DLMS row and capture-object counts differ.");
            var fields = Fields(templateId, kind, category);
            if (kind == "EVENT")
            {
                if (_options.EventsWithPowerProfile is null)
                    throw new InvalidOperationException("Configure EventsWithPowerProfile from the HES setting.");
                var eventField = fields.Single(f => f.ParameterName == "EventId");
                var eventValue = Resolve(eventField, category, source, row);
                if (!_options.EventsWithPowerProfile.Contains(Convert.ToInt32(eventValue.Value, CultureInfo.InvariantCulture)))
                    fields = Fields(template.EventNonProfileTemplateId, "EVENTNONPROFILE", category);
            }
            using var body = new MemoryStream();
            body.Write(Header(inbound, responseType, 1));
            foreach (var field in fields)
            {
                var value = Resolve(field, category, source, row);
                try { body.Write(EncodeField(field, value.Value, value.Object, _options.ResponseTimestampOffsetMinutes)); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                { throw new InvalidOperationException($"{kind} field {field.ParameterName} ({field.DataType}, scalar {field.Scalar}): {ex.Message}", ex); }
            }
            foreach (var packet in Frame(inbound, body.ToArray()))
            {
                bytes = checked(bytes + packet.Length);
                if (bytes > _options.MaxResponseBytes) throw new InvalidOperationException("Custom response byte limit exceeded; request a smaller range.");
                packets.Add(packet);
            }
        }
        // Finish validation before the caller publishes anything: no partially encoded success.
        return packets;
    }

    private IReadOnlyList<TemplateField> Fields(int? id, string kind, string category)
    {
        var fields = model.GetFields(id ?? -1, $"{kind}_CUSTOM_PULL_{category}");
        if (fields.Count == 0) throw new NotSupportedException($"Missing HES {kind} layout {id}/{category}.");
        if (fields.Select(f => f.SerialNumber).Distinct().Count() != fields.Count || fields.Any(f => f.MeterCategory != category))
            throw new InvalidOperationException($"Ambiguous HES {kind} layout {id}/{category}.");
        return fields;
    }

    private (object? Value, GXDLMSObject Object) Resolve(TemplateField field, string category, GXDLMSProfileGeneric profile, object?[] row)
    {
        if (!model.TryGetAttribute(field.Profile, category, field.ParameterName, out var mapping) || mapping.AttributeIndex < 1)
            throw new NotSupportedException($"No OBIS mapping for {category}/{field.Profile}/{field.ParameterName}.");
        string obis = mapping.ObisCode;
        if (profile.LogicalName.StartsWith("0.0.99.98.", StringComparison.Ordinal))
        {
            string group = profile.LogicalName.Split('.')[4];
            if (field.ParameterName == "EventId") obis = $"0.0.96.11.{group}.255";
            obis = obis.Replace(".e.", $".{group}.", StringComparison.Ordinal);
        }
        var matches = profile.CaptureObjects.Select((c, i) => (Capture: c, Index: i))
            .Where(x => x.Capture.Key.LogicalName == obis && x.Capture.Value.AttributeIndex == mapping.AttributeIndex && x.Capture.Value.DataIndex == 0).ToArray();
        if (matches.Length != 1)
            throw new NotSupportedException($"{profile.LogicalName}: expected one capture for {field.ParameterName} ({obis}/{mapping.AttributeIndex}), found {matches.Length}.");
        return (row[matches[0].Index], matches[0].Capture.Key);
    }

    public static (string Obis, string Kind, int? TemplateId, byte ResponseType) Describe(CustomCommandType command, MeterTemplateRow t) => command switch
    {
        CustomCommandType.GetInstantaneousProfile or CustomCommandType.GetStoredInstantaneousProfile => ("1.0.94.91.0.255", "INSTANT", t.InstantTemplateId, 22),
        CustomCommandType.GetBlockLoadProfile or CustomCommandType.GRBlockLoadProfile => ("1.0.99.1.0.255", "BLOCK", t.BlockTemplateId, 19),
        CustomCommandType.GetDailyLoadProfile => ("1.0.99.2.0.255", "DAILY", t.DailyTemplateId, 20),
        CustomCommandType.GetBillingProfile => ("1.0.98.1.0.255", "BILL", t.BillTemplateId, 21),
        >= CustomCommandType.GetVoltageEventProfile and <= CustomCommandType.GetControlEventProfile =>
            ($"0.0.99.98.{(int)command - 41}.255", "EVENT", t.EventTemplateId, checked((byte)((int)command - 18))),
        CustomCommandType.GetDiData => ("0.0.94.91.128.255", "EVENT", t.EventTemplateId, 83),
        _ => throw new NotSupportedException($"Unsupported profile {command}."),
    };

    public static byte[] EncodeField(TemplateField field, object? value, GXDLMSObject source, int offsetMinutes)
    {
        if (value is null) throw new InvalidOperationException("The meter returned no value.");
        if (field.DataType == "DateTime")
        {
            var clock = value switch
            {
                GXDateTime gx => gx,
                DateTime dt => new GXDateTime(dt),
                byte[] raw => (GXDateTime)GXDLMSClient.ChangeType(raw, DataType.DateTime),
                _ => throw new NotSupportedException("Expected a DLMS date/time."),
            };
            long epoch = new DateTimeOffset(DateTime.SpecifyKind(clock.Value.DateTime, DateTimeKind.Utc)).ToUnixTimeSeconds();
            byte[] result = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(result, checked((uint)(epoch + offsetMinutes * 60L)));
            return result;
        }
        decimal number = Convert.ToDecimal(value, CultureInfo.InvariantCulture);
        if (source is GXDLMSRegister register && field.DataType != "DateTime")
        {
            number *= (decimal)register.Scaler;
            bool kilo = field.ParameterName.Contains("Kw", StringComparison.OrdinalIgnoreCase) || field.ParameterName.Contains("Kva", StringComparison.OrdinalIgnoreCase);
            if (kilo && register.Unit is Unit.ActiveEnergy or Unit.ApparentEnergy or Unit.ReactiveEnergy or Unit.ActivePower or Unit.ApparentPower or Unit.ReactivePower)
                number /= 1000m;
            if (register.Unit == Unit.Second && field.ParameterName.EndsWith("Mins", StringComparison.Ordinal)) number /= 60m;
        }
        if (field.Scalar is < -12 or > 12) throw new NotSupportedException("Scalar exceeds the supported decimal range.");
        number /= (decimal)Math.Pow(10, field.Scalar);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        if (field.DataType == "Float32")
        {
            float f = (float)number;
            if (!float.IsFinite(f)) throw new OverflowException("Non-finite Float32.");
            writer.Write(f);
        }
        else
        {
            number = decimal.Round(number, 0, MidpointRounding.AwayFromZero);
            switch (field.DataType)
            {
                case "UInt8": writer.Write(checked((byte)number)); break;
                case "Int8": writer.Write(checked((sbyte)number)); break;
                case "UInt16": writer.Write(checked((ushort)number)); break;
                case "Int16": writer.Write(checked((short)number)); break;
                case "UInt24":
                    uint u = checked((uint)number);
                    if (u > 0xFFFFFF) throw new OverflowException("UInt24 overflow.");
                    writer.Write((byte)u); writer.Write((byte)(u >> 8)); writer.Write((byte)(u >> 16)); break;
                // HES's current generic parser returns signed Int32 even for UInt32.
                case "UInt32":
                    if (number > int.MaxValue) throw new OverflowException("Value exceeds HES UInt32 parser range.");
                    writer.Write(checked((uint)number)); break;
                case "Int32": writer.Write(checked((int)number)); break;
                default: throw new NotSupportedException($"Unverified HES data type {field.DataType}.");
            }
        }
        return stream.ToArray();
    }

    public static byte[] Header(CustomPullInbound inbound, byte profile, byte rows)
    {
        bool modern = inbound.Protocol.WireProfile == CustomPullWireProfile.NewHeader;
        uint node = checked((uint)inbound.Meter.Index);
        if (!modern && node > 0xFFFFFF) throw new NotSupportedException("Legacy profile header has a 24-bit node ID.");
        if (modern && rows > 15) throw new ArgumentOutOfRangeException(nameof(rows));
        byte[] body = new byte[modern ? 11 : 12];
        body[0] = profile;
        if (modern)
        {
            body[1] = rows; body[2] = (byte)'M'; body[3] = (byte)'Y';
            BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(4), node);
        }
        else
        {
            body[1] = (byte)node; body[2] = (byte)(node >> 8); body[3] = (byte)(node >> 16);
            body[4] = (byte)'M'; body[5] = (byte)'Y';
            BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(6), node); body[11] = rows;
        }
        return body;
    }

    public static IReadOnlyList<byte[]> Frame(CustomPullInbound inbound, byte[] body)
    {
        bool modern = inbound.Protocol.WireProfile == CustomPullWireProfile.NewHeader;
        // Full MQTT payloads are accepted by HES. Fragment only at the wire length limit.
        int size = modern ? 65523 : 245;
        int count = (body.Length + size - 1) / size;
        if (count is < 1 or > 255) throw new InvalidOperationException("Response exceeds custom fragment limit.");
        var result = new List<byte[]>(count);
        for (int i = 0; i < count; i++)
        {
            var packet = CustomPushFramer.Frame(body.AsSpan(i * size, Math.Min(size, body.Length - i * size)),
                modern ? CustomPushHeaderKind.New : CustomPushHeaderKind.Old, inbound.Request.FrameId, inbound.Protocol.ResponseMagicNumber);
            packet[modern ? 6 : 1] = checked((byte)count);
            packet[modern ? 7 : 2] = checked((byte)(i + 1));
            result.Add(packet);
        }
        return result;
    }

    private sealed class ProfileReader : IDisposable
    {
        private readonly DLMSServerSession _server;
        private readonly CustomPullOptions _options;
        private readonly CancellationToken _token;
        private readonly GXDLMSClient _client = new(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER);
        private int _blocks, _bytes;
        public ProfileReader(DLMSServerSession server, CustomPullOptions options, CancellationToken token)
        {
            _server = server; _options = options; _token = token;
            _client.ParseAAREResponse(Exchange(_client.AARQRequest()).Data);
        }
        public object? Read(GXDLMSObject obj, int attribute) => Exchange(_client.Read(obj, attribute)).Value;
        private GXReplyData Exchange(byte[][] requests)
        {
            var reply = new GXReplyData();
            void Receive(byte[] request)
            {
                _token.ThrowIfCancellationRequested();
                if (++_blocks > _options.MaxDlmsBlocks) throw new InvalidOperationException("DLMS block limit exceeded.");
                byte[] response = _server.HandleRequest(request) ?? [];
                _bytes = checked(_bytes + response.Length);
                if (_bytes > _options.MaxResponseBytes) throw new InvalidOperationException("DLMS response byte limit exceeded.");
                if (response.Length == 0 || !_client.GetData(response, reply) || reply.Error != 0)
                    throw new InvalidOperationException($"Custom profile DLMS read failed ({reply.Error}).");
            }
            foreach (var request in requests)
            {
                Receive(request);
                while (reply.IsMoreData) Receive(_client.ReceiverReady(reply));
            }
            return reply;
        }
        public List<object?[]> ReadRows(GXDLMSProfileGeneric profile, CommandIntent intent)
        {
            uint total = Convert.ToUInt32(Read(profile, 7), CultureInfo.InvariantCulture);
            if (total == 0) return [];
            byte[][] request;
            if (intent.Selector == CustomDataSelector.GetWithDateRange)
            {
                if (intent.ValueFrom > intent.ValueTo) throw new ArgumentException("Date range is reversed.");
                int offset = intent.Command == CustomCommandType.GetBlockLoadProfile ? _options.BlockRequestOffsetMinutes : 0;
                var from = DateTimeOffset.FromUnixTimeSeconds(intent.ValueFrom).AddMinutes(-offset).UtcDateTime;
                var to = DateTimeOffset.FromUnixTimeSeconds(intent.ValueTo).AddMinutes(-offset).UtcDateTime;
                request = _client.ReadRowsByRange(profile, from, to);
            }
            else
            {
                var (start, count) = SelectEntries(total, intent.Selector, intent.ValueFrom, intent.ValueTo);
                if (count == 0) return [];
                if (count > _options.MaxProfileRows) throw new InvalidOperationException("Too many profile rows; request a smaller entry range.");
                request = _client.ReadRowsByEntry(profile, start, count);
            }
            object? raw = Exchange(request).Value;
            if (raw is not IEnumerable sequence) throw new InvalidOperationException("DLMS profile did not return an array.");
            var result = new List<object?[]>();
            foreach (var row in sequence)
            {
                if (row is not IEnumerable cells || row is string or byte[]) throw new InvalidOperationException("DLMS profile row is not a structure.");
                result.Add(cells.Cast<object?>().ToArray());
                if (result.Count > _options.MaxProfileRows) throw new InvalidOperationException("Too many profile rows; narrow the date range.");
            }
            return result;
        }
        public void Dispose()
        {
            if (!_token.IsCancellationRequested)
                foreach (var request in _client.ReleaseRequest() ?? []) _server.HandleRequest(request);
        }
    }

    /// <summary>HES entry endpoints are inclusive and one-based; latest entries count from the tail.</summary>
    public static (uint Start, uint Count) SelectEntries(uint total, CustomDataSelector selector, uint from, uint to)
    {
        if (selector == CustomDataSelector.GetWithoutData) return (1, total);
        if (selector is not (CustomDataSelector.GetWithEntryRange or CustomDataSelector.GetLatestEntriesRange))
            throw new NotSupportedException("Unsupported profile selector.");
        from = from == 0 ? 1 : from;
        to = to == 0 ? total : to;
        if (from > to) throw new ArgumentException("Entry range is reversed.");
        if (from > total) return (1, 0);
        to = Math.Min(to, total);
        return (selector == CustomDataSelector.GetLatestEntriesRange ? total - to + 1 : from, to - from + 1);
    }
}
