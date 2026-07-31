using ManyMeterSimulator.Networking.Nic;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Configuration for the MQTT NICs. One broker serves all four variants in the field (see
/// virtual_nics.md §14.5), so the connection lives under <see cref="Shared"/> and each variant
/// carries only its own tuning — but a variant may override the broker if a deployment ever splits
/// them.
/// </summary>
public sealed class NicsOptions
{
    public const string SectionName = "Nics";

    public SharedNicOptions Shared { get; set; } = new();

    /// <summary>
    /// The direct-4G transport. Serves BOTH <see cref="NicType.Mqtt4G"/> and
    /// <see cref="NicType.Mqtt4GImg"/> — there is deliberately no separate IMG section, because the
    /// two share a broker, a topic pair and a framing format. A meter's batch still records which
    /// of the two it is (that is real hardware), but on the wire they are indistinguishable, so
    /// giving them separate clients would just subscribe to <c>PollRequest/#</c> twice and receive
    /// every message twice.
    /// </summary>
    public MqttNicOptions Mqtt4G { get; set; } = new();

    public MqttNicOptions MqttWirepas { get; set; } = new();

    public MqttNicOptions MqttKmesh { get; set; } = new();

    /// <summary>See <see cref="NicTypes.TransportFor"/> — IMG folds into the direct-4G transport.</summary>
    public static NicType TransportFor(NicType nic) => NicTypes.TransportFor(nic);

    public MqttNicOptions For(NicType nic) => NicTypes.TransportFor(nic) switch
    {
        NicType.Mqtt4G => Mqtt4G,
        NicType.MqttWirepas => MqttWirepas,
        NicType.MqttKmesh => MqttKmesh,
        _ => throw new ArgumentOutOfRangeException(nameof(nic), nic, "Not an MQTT NIC."),
    };

    /// <summary>The broker a variant should dial: its own if it declares one, otherwise the shared one.</summary>
    public MqttBrokerOptions BrokerFor(NicType nic)
    {
        MqttNicOptions variant = For(nic);
        return variant.Broker is { Host.Length: > 0 } own ? own : Shared.Broker;
    }

    /// <summary>
    /// Every MQTT transport that is switched on — one broker client each. Note these are
    /// transports, not NIC types: there is no separate IMG entry.
    /// </summary>
    public IEnumerable<NicType> EnabledTransports()
    {
        foreach (NicType nic in new[] { NicType.Mqtt4G, NicType.MqttWirepas, NicType.MqttKmesh })
        {
            if (For(nic).Enabled)
            {
                yield return nic;
            }
        }
    }
}

public sealed class SharedNicOptions
{
    public MqttBrokerOptions Broker { get; set; } = new();

    /// <summary>
    /// Messages that may queue for ONE meter before further ones are dropped. Small on purpose:
    /// a real meter under a request storm drops too, and a deep queue would just serve HES stale
    /// answers to requests it has already given up on.
    /// </summary>
    public int MailboxCapacity { get; set; } = 32;

    /// <summary>
    /// How many meters may be inside the brain at once, across every MQTT NIC. Bounds CPU under a
    /// poll storm so the work queues instead of starving the thread pool.
    /// </summary>
    public int MaxConcurrentBrainCalls { get; set; } = Environment.ProcessorCount * 4;

    /// <summary>On shutdown, how long queued messages get to finish before being abandoned.</summary>
    public int ShutdownDrainSeconds { get; set; } = 10;
}

public sealed class MqttNicOptions
{
    public bool Enabled { get; set; }

    /// <summary>Per-variant broker override. Left empty, the variant uses the shared broker.</summary>
    public MqttBrokerOptions? Broker { get; set; }

    /// <summary>
    /// Largest DLMS payload put in one outbound fragment. 0 means never fragment — which is what
    /// HES itself does on the 4G request path (virtual_nics.md §14.1). RF NICs use 90.
    /// </summary>
    public int MaxFragmentPayload { get; set; }

    /// <summary>Pause between publishing consecutive fragments, for NICs that cannot absorb a burst.</summary>
    public int InterFragmentDelayMs { get; set; }

    /// <summary>QoS used when publishing responses. HES clamps its own setting to 2.</summary>
    public int PublishQos { get; set; } = 2;

    /// <summary>QoS requested when subscribing to the request topics.</summary>
    public int SubscribeQos { get; set; } = 2;

    /// <summary>Incomplete fragment sets are abandoned after this long.</summary>
    public int FragmentTimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Capture every inbound message to <c>data/captures/</c> as JSONL. This is how the codecs get
    /// their golden vectors (virtual_nics.md §9) — leave it off in a steady-state run, since it
    /// writes one line per message.
    /// </summary>
    public bool CaptureRawMessages { get; set; }
}

public sealed class MqttBrokerOptions
{
    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 1883;

    /// <summary>The EQA broker is plaintext (<c>CrystalHES.SecureBroker = false</c>).</summary>
    public bool UseTls { get; set; }

    /// <summary>
    /// Client ids are disposable — HES itself uses a fresh GUID per connection with CleanSession,
    /// so there is no format to match and no duplicate-eviction hazard. A suffix is appended.
    /// </summary>
    public string ClientIdPrefix { get; set; } = "nicsim";

    public int ReconnectDelaySeconds { get; set; } = 5;

    public int ConnectTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Candidate credentials, tried in order until one authenticates.
    ///
    /// This exists because the HES settings carry the SAME username with two different passwords,
    /// belonging to opposite ends of the link: one is what HES presents when it connects, the other
    /// is what HES *writes into a meter* via the SetMQTTBrokerDetails DLMS command. Nothing in the
    /// source disambiguates them, so rather than guess we try the meter-side one first (we are
    /// impersonating a meter) and fall back. The client logs which one worked.
    /// </summary>
    public List<MqttCredential> Credentials { get; set; } = new();
}

public sealed class MqttCredential
{
    /// <summary>Label for logs, e.g. "meter-side" / "hes-side". Never the password.</summary>
    public string Name { get; set; } = "unnamed";

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}
