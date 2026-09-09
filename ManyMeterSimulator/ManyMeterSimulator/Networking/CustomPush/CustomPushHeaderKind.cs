namespace ManyMeterSimulator.Networking.CustomPush;

/// <summary>
/// The HES custom scheduled-push header selected for a Wirepas batch.  This is deliberately
/// batch configuration: a Wirepas radio can carry either custom header family.
/// </summary>
public enum CustomPushHeaderKind
{
    Old = 10,
    New = 12,
}
