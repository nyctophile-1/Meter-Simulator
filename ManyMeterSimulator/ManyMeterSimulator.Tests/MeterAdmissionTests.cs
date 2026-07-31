using ManyMeterSimulator.Diagnostics;
using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Provisioning;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace ManyMeterSimulator.Tests;

/// <summary>
/// Admission policy is shared by every NIC, so it is tested independently of any transport. What
/// each NIC does with a refusal differs (TCP closes the socket, MQTT drops the message); what gets
/// decided, and in what order, must not.
/// </summary>
public class MeterAdmissionTests
{
    private const string Template = "SA1231166HP_values.xml";

    private static (MeterAdmission Admission, MeterRegistry Registry, SessionRegistry Sessions, SimulatorMetrics Metrics) Build(
        Action<MeterRegistry>? arrange = null)
    {
        var registry = new MeterRegistry();
        arrange?.Invoke(registry);

        var templates = new TemplateRegistry(
            Options.Create(new TemplateOptions { Folder = Path.Combine(AppContext.BaseDirectory, "Templates") }),
            new TestHostEnvironment(),
            NullLogger<TemplateRegistry>.Instance);

        var sessions = new SessionRegistry();
        var metrics = new SimulatorMetrics();
        return (new MeterAdmission(registry, templates, sessions, metrics), registry, sessions, metrics);
    }

    private static ConnectionState StateFor(MeterRef meter) =>
        new() { Meter = meter, SessionCts = new CancellationTokenSource() };

    [Fact]
    public void AdmitsAProvisionedRunningMeter_AndClaimsTheSession()
    {
        var (admission, _, sessions, metrics) = Build(r => r.TryStart(r.AddBatch("b", Template, 10, NicType.Mqtt4G).Id));
        var meter = new MeterRef(1, NicType.Mqtt4G);

        AdmissionResult result = admission.TryAdmit(meter, StateFor(meter), maxConcurrentSessions: 10);

        Assert.True(result.IsAdmitted);
        Assert.Equal(1, sessions.ActiveCount);
        Assert.Equal(1, metrics.Snapshot(NicType.Mqtt4G, 0).TotalAccepted);
    }

    [Fact]
    public void RejectsAMeterInNoBatch()
    {
        var (admission, _, sessions, _) = Build();   // no batches at all
        var meter = new MeterRef(1, NicType.Mqtt4G);

        AdmissionResult result = admission.TryAdmit(meter, StateFor(meter), 10);

        Assert.Equal(AdmissionOutcome.NotProvisioned, result.Outcome);
        Assert.Equal(0, sessions.ActiveCount);   // a refused meter must not hold a session slot
    }

    [Theory]
    [InlineData(BatchStatus.NotStarted)]
    [InlineData(BatchStatus.Stopped)]
    public void RejectsAMeterWhoseBatchIsNotRunning(BatchStatus status)
    {
        var (admission, _, sessions, metrics) = Build(r =>
        {
            MeterBatch b = r.AddBatch("b", Template, 10);
            if (status == BatchStatus.Stopped)
            {
                r.TryStop(b.Id);
            }
        });

        var meter = new MeterRef(1, NicType.Tcp4G);
        AdmissionResult result = admission.TryAdmit(meter, StateFor(meter), 10);

        Assert.Equal(AdmissionOutcome.BatchNotRunning, result.Outcome);
        Assert.Equal(0, sessions.ActiveCount);
        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalRejectedBatchNotRunning);
    }

    [Fact]
    public void RejectsAMeterWhoseTemplateIsMissing()
    {
        var (admission, _, _, metrics) = Build(r => r.TryStart(r.AddBatch("b", "no-such-template.xml", 10).Id));
        var meter = new MeterRef(1, NicType.Tcp4G);

        AdmissionResult result = admission.TryAdmit(meter, StateFor(meter), 10);

        Assert.Equal(AdmissionOutcome.TemplateMissing, result.Outcome);
        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalRejectedNoTemplate);
    }

    [Fact]
    public void RejectsASecondSessionForTheSameMeter()
    {
        var (admission, _, sessions, metrics) = Build(r => r.TryStart(r.AddBatch("b", Template, 10).Id));
        var meter = new MeterRef(1, NicType.Tcp4G);

        Assert.True(admission.TryAdmit(meter, StateFor(meter), 10).IsAdmitted);
        AdmissionResult second = admission.TryAdmit(meter, StateFor(meter), 10);

        Assert.Equal(AdmissionOutcome.AlreadyActive, second.Outcome);
        Assert.Equal(1, sessions.ActiveCount);   // the first session still owns the meter
        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalRejectedCollision);
    }

    [Fact]
    public void RejectsOnceTheCallersCeilingIsReached()
    {
        var (admission, _, _, metrics) = Build(r => r.TryStart(r.AddBatch("b", Template, 10).Id));

        var first = new MeterRef(1, NicType.Tcp4G);
        Assert.True(admission.TryAdmit(first, StateFor(first), maxConcurrentSessions: 1).IsAdmitted);

        var second = new MeterRef(2, NicType.Tcp4G);
        AdmissionResult result = admission.TryAdmit(second, StateFor(second), maxConcurrentSessions: 1);

        Assert.Equal(AdmissionOutcome.AtCapacity, result.Outcome);
        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalRejectedMaxConnections);
    }

    /// <summary>
    /// A meter must be polled over the NIC it was provisioned for. Serving a TCP meter over MQTT
    /// would make the simulator disagree with how HES has the fleet registered — better to drop it
    /// and have the misconfiguration show up as a counter.
    /// </summary>
    [Fact]
    public void RejectsAMeterPolledOverTheWrongNic()
    {
        var (admission, _, sessions, _) = Build(r => r.TryStart(r.AddBatch("tcp", Template, 10).Id));

        // Provisioned as Tcp4G, but the request arrived on the 4G MQTT transport.
        var meter = new MeterRef(1, NicType.Mqtt4G);
        AdmissionResult result = admission.TryAdmit(meter, StateFor(meter), 10);

        Assert.Equal(AdmissionOutcome.WrongNic, result.Outcome);
        Assert.Equal(0, sessions.ActiveCount);
    }

    /// <summary>IMG meters legitimately arrive on the direct-4G transport — that pair must pass.</summary>
    [Fact]
    public void AcceptsAnImgMeterOnTheDirect4GTransport()
    {
        var (admission, _, _, _) = Build(r => r.TryStart(r.AddBatch("img", Template, 10, NicType.Mqtt4GImg).Id));

        var meter = new MeterRef(1, NicType.Mqtt4G);
        Assert.True(admission.TryAdmit(meter, StateFor(meter), 10).IsAdmitted);
    }

    /// <summary>
    /// The point of the NIC dimension: one NIC's failures must not be hidden inside a fleet total.
    /// </summary>
    [Fact]
    public void CountersAreRecordedAgainstTheMetersOwnNic()
    {
        var (admission, _, _, metrics) = Build(r =>
        {
            r.TryStart(r.AddBatch("tcp", Template, 5).Id);                        // indices 1..5
            r.AddBatch("wirepas", Template, 5, NicType.MqttWirepas);              // indices 6..10, not started
        });

        var tcp = new MeterRef(1, NicType.Tcp4G);
        var wirepas = new MeterRef(6, NicType.MqttWirepas);

        Assert.True(admission.TryAdmit(tcp, StateFor(tcp), 10).IsAdmitted);
        Assert.Equal(AdmissionOutcome.BatchNotRunning, admission.TryAdmit(wirepas, StateFor(wirepas), 10).Outcome);

        Assert.Equal(1, metrics.Snapshot(NicType.Tcp4G, 0).TotalAccepted);
        Assert.Equal(0, metrics.Snapshot(NicType.Tcp4G, 0).TotalRejectedBatchNotRunning);

        Assert.Equal(0, metrics.Snapshot(NicType.MqttWirepas, 0).TotalAccepted);
        Assert.Equal(1, metrics.Snapshot(NicType.MqttWirepas, 0).TotalRejectedBatchNotRunning);

        // ...and the fleet total is still the sum.
        SimulatorMetricsSnapshot all = metrics.Snapshot(0);
        Assert.Equal(1, all.TotalAccepted);
        Assert.Equal(1, all.TotalRejectedBatchNotRunning);
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
