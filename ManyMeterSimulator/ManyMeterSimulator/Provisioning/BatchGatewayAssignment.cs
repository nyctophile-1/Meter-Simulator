namespace ManyMeterSimulator.Provisioning;

public static class BatchGatewayAssignment
{
    public static string GatewayFor(string module, long meterIndex)
    {
        string prefix = module switch
        {
            "TCP" => "direct_tcp",
            "MQTT4G" => "direct_4g",
            "RF" => "gw",
            "KMesh" => "kgw",
            _ => throw new ArgumentOutOfRangeException(nameof(module))
        };

        return prefix + "_" + MeterNodeIds.Format(meterIndex)[^4..];
    }

    public static (string Gateway, uint Sink) ForKmesh(int batchId, long startIndex, long meterIndex)
    {
        ValidateRange(batchId, startIndex, meterIndex);

        return (GatewayFor("KMesh", meterIndex), (uint)((meterIndex - 1) % 4));
    }

    public static (string Gateway, string Sink) For(int batchId, long startIndex, long meterIndex)
    {
        ValidateRange(batchId, startIndex, meterIndex);

        return (GatewayFor("RF", meterIndex), $"sink{(meterIndex - 1) % 4}");
    }

    private static void ValidateRange(int batchId, long startIndex, long meterIndex)
    {
        if (batchId < 1 || startIndex < 1 || meterIndex < startIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(meterIndex));
        }
    }
}
