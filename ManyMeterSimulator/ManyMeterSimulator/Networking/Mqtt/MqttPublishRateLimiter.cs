namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>One shared message budget per run, with at most 10 ms of accumulated credit.</summary>
public sealed class MqttPublishRateLimiter
{
    public const int MinimumRate = 100;
    public const int MaximumRate = 300_000;
    private readonly object _sync = new();
    private readonly TimeProvider _clock;
    private int _rate;
    private double _credit;
    private long _updatedAt;

    public MqttPublishRateLimiter(int rate, TimeProvider? clock = null)
    {
        _clock = clock ?? TimeProvider.System;
        SetRate(rate);
    }

    public int Rate { get { lock (_sync) return _rate; } }

    public static void Validate(int rate)
    {
        if (rate is < MinimumRate or > MaximumRate)
            throw new ArgumentOutOfRangeException(nameof(rate), "Publish rate must be 100 to 300,000 messages per second.");
    }

    public void SetRate(int rate)
    {
        Validate(rate);
        lock (_sync)
        {
            if (_rate == rate) return;
            _rate = rate;
            _credit = 0;
            _updatedAt = _clock.GetTimestamp();
        }
    }

    internal bool TryAcquire(out TimeSpan delay)
    {
        lock (_sync)
        {
            long now = _clock.GetTimestamp();
            double frequency = _clock.TimestampFrequency;
            _credit = Math.Min(frequency * _rate / 100, _credit + (now - _updatedAt) * (double)_rate);
            _updatedAt = now;
            if (_credit >= frequency)
            {
                _credit -= frequency;
                delay = TimeSpan.Zero;
                return true;
            }
            // Bound both timer churn and how long an in-progress wait can miss a rate change.
            delay = TimeSpan.FromMilliseconds(Math.Clamp((frequency - _credit) * 1000 / (_rate * frequency), 1, 10));
            return false;
        }
    }

    public async ValueTask WaitAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (TryAcquire(out var delay)) return;
            await Task.Delay(delay, _clock, cancellationToken);
        }
    }
}
