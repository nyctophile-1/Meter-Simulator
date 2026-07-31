using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Provisioning;

namespace ManyMeterSimulator.Networking.Nic;

/// <summary>
/// Decides whether a meter may open a session, and registers it if so. Every NIC asks the same
/// questions in the same order — is this meter provisioned, is its batch running, does its template
/// resolve, are we at capacity, is a session already live — so the policy lives here once rather
/// than being reimplemented per transport.
///
/// What differs per NIC is how a refusal is EXPRESSED, not how it is decided: TCP closes the socket,
/// the MQTT NICs simply drop the message (which is also what a powered-off meter looks like to the
/// HES). So this returns an outcome and lets the caller act, while owning the counters itself.
///
/// Registration is done here rather than by the caller because "is a session already live" and
/// "claim the session" must be one atomic step — checking first and registering after is a race.
/// </summary>
public sealed class MeterAdmission
{
    private readonly MeterRegistry _meterRegistry;
    private readonly TemplateRegistry _templates;
    private readonly SessionRegistry _sessions;
    private readonly SimulatorMetrics _metrics;

    public MeterAdmission(
        MeterRegistry meterRegistry,
        TemplateRegistry templates,
        SessionRegistry sessions,
        SimulatorMetrics metrics)
    {
        _meterRegistry = meterRegistry;
        _templates = templates;
        _sessions = sessions;
        _metrics = metrics;
    }

    /// <summary>
    /// Runs every gate and, on success, claims the session for this meter. The caller must
    /// <see cref="SessionRegistry.Unregister"/> when the session ends.
    /// </summary>
    /// <param name="maxConcurrentSessions">
    /// The calling NIC's own concurrency ceiling — TCP is bounded by sockets, the MQTT NICs by
    /// in-flight work, so the limit belongs to the caller rather than to this shared policy.
    /// </param>
    public AdmissionResult TryAdmit(MeterRef meter, ConnectionState state, int maxConcurrentSessions)
    {
        // A meter must belong to a batch AND that batch must have a resolvable template — a meter
        // with no template can't be simulated.
        MeterBatch? batch = _meterRegistry.GetBatchForIndex(meter.Index);
        if (batch is null)
        {
            _metrics.RecordRejectedNoTemplate(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.NotProvisioned, null);
        }

        // The meter must actually be provisioned for the NIC it is being polled over. A TCP meter
        // answering over MQTT (or vice versa) is a provisioning mistake, and silently serving it
        // would make the simulator disagree with how the HES has the fleet registered.
        if (!NicTypes.CanServe(meter.Nic, batch.NicType))
        {
            _metrics.RecordRejectedNoTemplate(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.WrongNic, batch);
        }

        if (batch.Status is BatchStatus.NotStarted or BatchStatus.Stopped)
        {
            _metrics.RecordRejectedBatchNotRunning(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.BatchNotRunning, batch);
        }

        if (!_templates.TryResolve(batch.TemplateName, out _))
        {
            _metrics.RecordRejectedNoTemplate(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.TemplateMissing, batch);
        }

        if (_sessions.ActiveCount >= maxConcurrentSessions)
        {
            _metrics.RecordRejectedMaxConnections(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.AtCapacity, batch);
        }

        if (!_sessions.TryRegister(meter, state))
        {
            _metrics.RecordRejectedCollision(meter.Nic);
            return new AdmissionResult(AdmissionOutcome.AlreadyActive, batch);
        }

        _metrics.RecordAccepted(meter.Nic);
        return new AdmissionResult(AdmissionOutcome.Admitted, batch);
    }
}

public enum AdmissionOutcome
{
    Admitted,

    /// <summary>The meter belongs to no batch, so there is no template to build it from.</summary>
    NotProvisioned,

    /// <summary>The meter's batch exists but is NotStarted or Stopped.</summary>
    BatchNotRunning,

    /// <summary>The meter is provisioned for a different NIC than the one it arrived on.</summary>
    WrongNic,

    /// <summary>The batch names a template that is no longer on disk.</summary>
    TemplateMissing,

    /// <summary>The calling NIC is already at its concurrent-session ceiling.</summary>
    AtCapacity,

    /// <summary>A session for this meter is already live — real meter firmware accepts only one.</summary>
    AlreadyActive,
}

public readonly record struct AdmissionResult(AdmissionOutcome Outcome, MeterBatch? Batch)
{
    public bool IsAdmitted => Outcome == AdmissionOutcome.Admitted;

    /// <summary>Reason text for the caller's rejection log line.</summary>
    public string Reason => Outcome switch
    {
        AdmissionOutcome.Admitted => "admitted",
        AdmissionOutcome.NotProvisioned => "not part of any batch (no template)",
        AdmissionOutcome.BatchNotRunning => $"batch is {Batch?.Status}",
        AdmissionOutcome.WrongNic => $"meter is provisioned for {Batch?.NicType}, not this NIC",
        AdmissionOutcome.TemplateMissing => $"batch template '{Batch?.TemplateName}' not found",
        AdmissionOutcome.AtCapacity => "max concurrent sessions reached",
        AdmissionOutcome.AlreadyActive => "a session is already active for this meter",
        _ => Outcome.ToString(),
    };
}
