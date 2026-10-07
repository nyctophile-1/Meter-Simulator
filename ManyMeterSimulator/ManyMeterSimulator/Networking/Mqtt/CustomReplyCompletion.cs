using ManyMeterSimulator.Diagnostics;

namespace ManyMeterSimulator.Networking.Mqtt;

internal static class CustomReplyCompletion
{
    internal static async Task<bool> PublishAsync(IReadOnlyList<byte[]> responses,
        Func<byte[], Task<bool>> publish, ConnectionState session, SessionRegistry sessions,
        SimulatorMetrics metrics)
    {
        if (responses.Count == 0)
        {
            return false;
        }

        foreach (byte[] response in responses)
        {
            session.Touch();
            if (!await publish(response))
            {
                return false;
            }
        }

        session.Touch();
        session.RecordExchange();
        metrics.RecordCommandSucceeded(session.Meter.Nic);

        if (session.IsVirtual && session.IsCustomCommand)
        {
            sessions.Unregister(session.Meter, session);
            session.SessionCts.Cancel();
        }

        return true;
    }
}
