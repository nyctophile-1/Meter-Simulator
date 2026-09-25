namespace ManyMeterSimulator.Provisioning;

public enum BatchTrafficKind { Routing, Instantaneous, BlockLoad, Daily, Events, Esw, Billing, Rtc }

public sealed record BatchTrafficSettings
{
    public bool Routing { get; init; } = true;
    public bool Instantaneous { get; init; }
    public bool BlockLoad { get; init; }
    public bool Daily { get; init; }
    public bool Events { get; init; }
    public bool Esw { get; init; }
    public bool Billing { get; init; }
    public bool Rtc { get; init; }

    public bool Enabled(BatchTrafficKind kind) => kind switch
    {
        BatchTrafficKind.Routing => Routing,
        BatchTrafficKind.Instantaneous => Instantaneous,
        BatchTrafficKind.BlockLoad => BlockLoad,
        BatchTrafficKind.Daily => Daily,
        BatchTrafficKind.Events => Events,
        BatchTrafficKind.Esw => Esw,
        BatchTrafficKind.Billing => Billing,
        BatchTrafficKind.Rtc => Rtc,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    public BatchTrafficSettings With(BatchTrafficKind kind, bool enabled) => kind switch
    {
        BatchTrafficKind.Routing => this with { Routing = enabled },
        BatchTrafficKind.Instantaneous => this with { Instantaneous = enabled },
        BatchTrafficKind.BlockLoad => this with { BlockLoad = enabled },
        BatchTrafficKind.Daily => this with { Daily = enabled },
        BatchTrafficKind.Events => this with { Events = enabled },
        BatchTrafficKind.Esw => this with { Esw = enabled },
        BatchTrafficKind.Billing => this with { Billing = enabled },
        BatchTrafficKind.Rtc => this with { Rtc = enabled },
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };
}
