namespace ManyMeterSimulator.Provisioning;

public static class BatchGatewayAssignment
{
    public const int MetersPerGateway = 1000;

    public static (string Gateway, uint Sink) ForKmesh(int batchId, long startIndex, long meterIndex)
    {
        var route = For(batchId, startIndex, meterIndex);

        return (route.Gateway, (uint)((meterIndex - 1) % 4));
    }

    public static (string Gateway, string Sink) For(int batchId, long startIndex, long meterIndex)
    {
        if (batchId < 1 || startIndex < 1 || meterIndex < startIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(meterIndex));
        }

        long ordinal = meterIndex - startIndex;

        return ($"gate_{batchId}_{ordinal / MetersPerGateway + 1}", $"sink{(meterIndex - 1) % 4}");
    }
}
