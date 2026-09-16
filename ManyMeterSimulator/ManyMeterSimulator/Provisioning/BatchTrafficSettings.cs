namespace ManyMeterSimulator.Provisioning;

public enum BatchTrafficKind { Routing, Instantaneous, BlockLoad, Daily }

public sealed record BatchTrafficSettings
{
    public bool Routing { get; init; } = true;
    public bool Instantaneous { get; init; }
    public bool BlockLoad { get; init; }
    public bool Daily { get; init; }

    public bool Enabled(BatchTrafficKind kind) => kind switch
    {
        BatchTrafficKind.Routing => Routing,
        BatchTrafficKind.Instantaneous => Instantaneous,
        BatchTrafficKind.BlockLoad => BlockLoad,
        BatchTrafficKind.Daily => Daily,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public BatchTrafficSettings With(BatchTrafficKind kind, bool enabled) => kind switch
    {
        BatchTrafficKind.Routing => this with { Routing = enabled },
        BatchTrafficKind.Instantaneous => this with { Instantaneous = enabled },
        BatchTrafficKind.BlockLoad => this with { BlockLoad = enabled },
        BatchTrafficKind.Daily => this with { Daily = enabled },
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}
