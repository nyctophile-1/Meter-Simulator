using Gurux.DLMS;
using Gurux.DLMS.Enums;

namespace MeterSimulator.DLMS;

public partial class DLMSServerSession
{
    private long _successfulCommands;
    private bool _successfulResponse;
    private bool _associationAction;
    private bool _pendingBlockSuccess;

    public long SuccessfulCommands => Interlocked.Read(ref _successfulCommands);

    public override void HandleRequest(GXServerReply reply)
    {
        _successfulResponse = false;
        base.HandleRequest(reply);

        if (_successfulResponse && reply.Reply is { Length: > 0 })
        {
            Interlocked.Increment(ref _successfulCommands);
        }
    }

    private void ObserveCommandResponse(byte[]? pdu, bool finalBlock)
    {
        if (pdu is not null)
        {
            try
            {
                _pendingBlockSuccess = IsSuccessfulResponse(pdu);
            }
            catch (Exception)
            {
                // A partial or unsupported list must not interrupt the meter response.
                _pendingBlockSuccess = false;
            }
        }

        if (finalBlock)
        {
            _successfulResponse |= _pendingBlockSuccess;
            _pendingBlockSuccess = false;
        }
    }

    private bool IsSuccessfulResponse(byte[] pdu)
    {
        if (pdu.Length < 4)
        {
            return false;
        }

        return (Command)pdu[0] switch
        {
            Command.GetResponse => pdu[1] switch
            {
                1 => pdu[3] == 0,
                2 => pdu.Length >= 10 && pdu[3] == 1 && pdu[8] == 0,
                3 => SuccessfulList(pdu, containsValues: true),
                _ => false,
            },
            Command.SetResponse => pdu[1] switch
            {
                1 => pdu[3] == 0,
                3 => pdu.Length >= 8 && pdu[3] == 0,
                5 => SuccessfulList(pdu, containsValues: false),
                _ => false,
            },
            Command.MethodResponse when !_associationAction => pdu[1] switch
            {
                1 => pdu.Length >= 5 && pdu[3] == 0 &&
                    (pdu[4] == 0 || (pdu.Length >= 6 && pdu[4] == 1 && pdu[5] == 0)),
                2 => pdu.Length >= 9 && pdu[3] == 1,
                _ => false,
            },
            _ => false,
        };
    }

    private static bool SuccessfulList(byte[] pdu, bool containsValues)
    {
        var data = new GXByteBuffer(pdu) { Position = 3 };
        int count = data.GetUInt8();

        if ((count & 0x80) != 0)
        {
            int length = count & 0x7f;
            count = 0;

            if (length is < 1 or > 4 || data.Available < length)
            {
                return false;
            }

            for (int i = 0; i < length; i++)
            {
                count = (count << 8) | data.GetUInt8();
            }
        }

        if (count <= 0 || count > data.Available)
        {
            return false;
        }

        for (int i = 0; i < count; i++)
        {
            if (data.Available == 0 || data.GetUInt8() != 0)
            {
                return false;
            }

            if (containsValues)
            {
                GXDLMSClient.GetValue(data);
            }
        }

        return data.Available == 0;
    }
}
