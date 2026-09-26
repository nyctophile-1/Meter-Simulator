using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using MeterSimulator.Fota;

namespace MeterSimulator.DLMS;

public partial class DLMSServerSession
{
    public IFotaMeter? Fota { get; set; }
    public const string FirmwareVersionObis = "1.0.0.2.0.255";
    public const string ImageTransferObis = "0.0.44.0.0.255";
    private const string FirmwareScheduleObis = "0.0.15.0.2.255";

    private bool ReadFota(ValueEventArgs arg)
    {
        bool image = arg.Target is GXDLMSImageTransfer;
        bool version = arg.Target.LogicalName == FirmwareVersionObis && arg.Index == 2;
        if (!image && !version)
        {
            return false;
        }

        if (image && arg.Index == 1)
        {
            return false;
        }

        try
        {
            if (version)
            {
                string? active = Fota?.ActiveVersion;
                if (active is null)
                {
                    return false;
                }

                arg.Value = arg.Target.GetDataType(2) == DataType.OctetString
                    ? System.Text.Encoding.UTF8.GetBytes(active)
                    : active;
            }
            else if (Fota is not null && arg.Target.LogicalName == ImageTransferObis)
            {
                arg.Value = Fota.Read(arg.Index);
            }
            else
            {
                arg.Value = arg.Index switch
                {
                    2 => ((GXDLMSImageTransfer)arg.Target).ImageBlockSize,
                    3 => "",
                    4 => 0U,
                    5 => false,
                    6 => (byte)0,
                    7 => new GXArray(),
                    _ => null
                };
                if (arg.Value is null)
                {
                    arg.Error = ErrorCode.ReadWriteDenied;
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            arg.Error = ErrorCode.TemporaryFailure;
        }
        catch (ArgumentOutOfRangeException)
        {
            arg.Error = ErrorCode.ReadWriteDenied;
        }

        arg.Handled = true;
        return true;
    }

    private bool ActionFota(ValueEventArgs arg)
    {
        if (arg.Target is not GXDLMSImageTransfer)
        {
            return false;
        }

        arg.Handled = true;
        arg.Error = Fota is null || arg.Target.LogicalName != ImageTransferObis || Settings.Authentication < Authentication.High ||
            AssignedAssociation is not GXDLMSAssociationLogicalName { AssociationStatus: Gurux.DLMS.Objects.Enums.AssociationStatus.Associated }
            ? ErrorCode.ReadWriteDenied
            : Fota.Invoke(arg.Index, arg.Parameters);
        return true;
    }

    private static bool DenyFotaWrite(ValueEventArgs arg)
    {
        if (arg.Target is not GXDLMSImageTransfer && arg.Target.LogicalName != FirmwareScheduleObis)
        {
            return false;
        }

        arg.Handled = true;
        arg.Error = ErrorCode.ReadWriteDenied;
        return true;
    }
}
