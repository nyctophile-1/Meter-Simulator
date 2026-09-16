using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.Models;

namespace ManyMeterSimulator.Networking.SmartNic;

public sealed partial class CustomProfileCommand
{
    private IReadOnlyList<byte[]> ReadEventStatusWord(CustomPullInbound inbound, CancellationToken token)
    {
        if (inbound.Intent.Selector != CustomDataSelector.GetWithoutData)
            throw new NotSupportedException("GetESWF requires a read without data.");
        var association = sessions.GetOrCreate(inbound.Meter).CreateReadAssociation();
        try
        {
            using var reader = new ProfileReader(association, _options, token);
            var clock = reader.Read(new GXDLMSClock("0.0.1.0.0.255"), 2) switch
            {
                GXDateTime time => time,
                byte[] bytes => (GXDateTime)GXDLMSClient.ChangeType(bytes, DataType.DateTime),
                _ => throw new InvalidDataException("The meter did not return its clock.")
            };
            // HES GetESWF currently maps to ESW-1; the XML's separate ESWF object is preserved.
            var value = reader.Read(new GXDLMSData(EventStatusWord.LogicalName), 2);
            string bits = value is GXBitString bitString ? bitString.ToString() : value as string
                ?? throw new InvalidDataException("The meter did not return an ESW bit string.");
            EventStatusWord.Validate(bits);
            using var body = new MemoryStream();
            body.Write(Header(inbound, 5, 1));
            using var writer = new BinaryWriter(body);
            long seconds = new DateTimeOffset(DateTime.SpecifyKind(clock.Value.DateTime, DateTimeKind.Utc)).ToUnixTimeSeconds();
            writer.Write(checked((uint)(seconds + _options.ResponseTimestampOffsetMinutes * 60L)));
            writer.Write((byte)4);
            writer.Write((byte)128);
            for (int bit = 0; bit < 128; bit += 8)
                writer.Write(Convert.ToByte(bits.Substring(bit, 8), 2));
            return Frame(inbound, body.ToArray());
        }
        finally { association.Reset(); }
    }
}
