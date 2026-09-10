using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.SmartNic;

/// <summary>
/// Converts HES's endpoint-13 command byte and selector into a semantic request without relying on
/// either enum's declaration order. The source sender intentionally aliases two command bytes, so
/// the raw byte remains on <see cref="CommandIntent"/> for diagnostics and response correlation.
/// </summary>
public static class CustomPullCommandDecoder
{
    public static bool TryDecode(
        MeterRef meter,
        CustomPullRequest request,
        out CommandIntent intent,
        out string error)
    {
        intent = default!;
        error = string.Empty;

        if (!TryMapCommand(request.RawCommandType, out CustomCommandType command))
        {
            error = $"custom command {request.RawCommandType} is not enabled by the simulator capability catalogue";
            return false;
        }

        CustomDataSelector selector = (CustomDataSelector)(byte)request.Selector;
        if (!IsSelectorAllowed(command, selector))
        {
            error = $"custom command {request.RawCommandType} ({command}) does not support selector {request.Selector}";
            return false;
        }

        intent = new CommandIntent(
            meter,
            command,
            selector,
            request.RawCommandType,
            request.ValueFromBits,
            request.ValueToBits)
        {
            FrameId = request.FrameId,
        };
        return true;
    }

    private static bool TryMapCommand(byte rawCommand, out CustomCommandType command)
    {
        command = rawCommand switch
        {
            3 => CustomCommandType.GetInstantaneousProfile,
            4 or 72 => CustomCommandType.GetBlockLoadProfile, // GetBlockLoadProfileInternal
            5 => CustomCommandType.GetDailyLoadProfile,
            6 => CustomCommandType.GetBillingProfile,
            24 => CustomCommandType.GetNamePlate,
            25 => CustomCommandType.GetSingleActionSchedule,
            >= 41 and <= 47 => (CustomCommandType)rawCommand,
            48 => CustomCommandType.GetRealtimeClock,
            50 => CustomCommandType.GetStoredInstantaneousProfile,
            83 or 90 => CustomCommandType.GetDiData, // GetDIEventProfile is sent as GetDIData
            _ => CustomCommandType.Unknown,
        };

        return command != CustomCommandType.Unknown;
    }

    private static bool IsSelectorAllowed(CustomCommandType command, CustomDataSelector selector) => command switch
    {
        CustomCommandType.GetInstantaneousProfile
            or CustomCommandType.GetNamePlate
            or CustomCommandType.GetSingleActionSchedule
            or CustomCommandType.GetRealtimeClock => selector == CustomDataSelector.GetWithoutData,

        CustomCommandType.GetBlockLoadProfile
            or CustomCommandType.GetDailyLoadProfile
            or CustomCommandType.GetBillingProfile
            or CustomCommandType.GetStoredInstantaneousProfile
            or CustomCommandType.GetVoltageEventProfile
            or CustomCommandType.GetCurrentEventProfile
            or CustomCommandType.GetPowerEventProfile
            or CustomCommandType.GetTransactionEventProfile
            or CustomCommandType.GetOtherEventProfile
            or CustomCommandType.GetNonRollOverEventProfile
            or CustomCommandType.GetControlEventProfile
            or CustomCommandType.GetDiData => selector is
                CustomDataSelector.GetWithoutData or
                CustomDataSelector.GetWithEntryRange or
                CustomDataSelector.GetWithDateRange or
                CustomDataSelector.GetLatestEntriesRange,

        _ => false,
    };
}
