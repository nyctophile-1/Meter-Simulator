namespace ManyMeterSimulator.Networking.Push;

internal sealed class PushCanceledException(int sent, int failed, CancellationToken token)
    : OperationCanceledException("Push stopped; remaining delivery is unconfirmed.", token)
{
    public int Sent { get; } = sent;
    public int Failed { get; } = failed;
}
