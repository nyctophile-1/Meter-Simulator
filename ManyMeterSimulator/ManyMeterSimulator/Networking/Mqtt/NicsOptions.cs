using ManyMeterSimulator.Networking.Nic;
using ManyMeterSimulator.Networking.Registry;

namespace ManyMeterSimulator.Networking.Mqtt;

/// <summary>
/// Tuning for the MQTT NICs.
///
/// <para>
/// WHERE a NIC connects is no longer here. Brokers are named rows in the network registry and a
/// batch binds to one, because a real fleet is served by several — different gateways, regions and
/// HES instances — which a single config section cannot express (network_registry.md §3). What is
/// left here is per-variant wire tuning plus the connection knobs that are the same whichever
/// broker is dialled.
/// </para>
///
/// <para>
/// The per-variant <c>Enabled</c> flags are gone too. A client now exists when a RUNNING batch
/// references an ENABLED broker, so there is one gate instead of two, both of them visible on the
/// Network page. <see cref="SharedNicOptions.Broker"/> survives only to seed the registry's
/// <c>default</c> entry on first run, and to carry the connection tuning below
/// (network_registry.md §5.6).
/// </para>
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

    /// <summary>
    /// The dial-able connection for a registry endpoint: identity and credentials from the
    /// endpoint (operator-managed, per broker), timing and client-id prefix from config (deployment
    /// tuning, the same whichever broker is dialled).
    /// </summary>
    public MqttBrokerOptions ConnectionFor(BrokerEndpoint endpoint) => new()
    {
        Host = endpoint.Host,
        Port = endpoint.Port,
        UseTls = endpoint.UseTls,
        ClientIdPrefix = Shared.Broker.ClientIdPrefix,
        ReconnectDelaySeconds = Shared.Broker.ReconnectDelaySeconds,
        ConnectTimeoutSeconds = Shared.Broker.ConnectTimeoutSeconds,
        Credentials = CredentialsFor(endpoint),
    };

    /// <summary>
    /// The endpoint's own credential, plus any configured fallbacks for the SAME host.
    ///
    /// <para>
    /// A registry endpoint carries exactly one username/password — that is what the operator typed
    /// and what the Network page verified. But the configured broker may carry several: the HES
    /// settings hold the same username with two different passwords, belonging to opposite ends of
    /// the link, and nothing disambiguates them (see <see cref="MqttBrokerOptions.Credentials"/>).
    /// Dropping that list when the config broker is seeded into the registry would turn a working
    /// deployment into a <c>BadUserNameOrPassword</c> on first start.
    /// </para>
    ///
    /// <para>
    /// So the fallbacks are kept, but only for an endpoint pointing at the configured host: they are
    /// that host's credentials and mean nothing anywhere else. The client logs which one worked, so
    /// the operator can settle it and edit the endpoint.
    /// </para>
    /// </summary>
    private List<MqttCredential> CredentialsFor(BrokerEndpoint endpoint)
    {
        var credentials = new List<MqttCredential>();

        if (!string.IsNullOrEmpty(endpoint.Username))
        {
            credentials.Add(new MqttCredential
            {
                Name = endpoint.Key,
                Username = endpoint.Username,
                Password = endpoint.Password,
            });
        }

        bool sameAsConfigured =
            string.Equals(endpoint.Host, Shared.Broker.Host, StringComparison.OrdinalIgnoreCase)
            && endpoint.Port == Shared.Broker.Port;

        if (!sameAsConfigured)
        {
            return credentials;
        }

        foreach (MqttCredential configured in Shared.Broker.Credentials)
        {
            bool alreadyListed = credentials.Any(c =>
                c.Username == configured.Username && c.Password == configured.Password);

            if (!alreadyListed)
            {
                credentials.Add(configured);
            }
        }

        return credentials;
    }
}

public sealed class SharedNicOptions
{
    /// <summary>
    /// Connection tuning, plus the seed for the registry's <c>default</c> broker on first run. It is
    /// NOT where a running NIC gets its host from any more — see <see cref="NicsOptions"/>.
    /// </summary>
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

    /// <summary>
    /// Safety net for the reconcile pass. Registry and batch changes signal it immediately, so this
    /// only matters if a signal is ever missed — a slow sweep that costs nothing when the desired
    /// and actual client sets already agree.
    /// </summary>
    public int ReconcileIntervalSeconds { get; set; } = 30;
}

public sealed class MqttNicOptions
{
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
    /// A registry-backed connection supplies exactly one (the endpoint's own). Several remain
    /// possible because the seeded config broker may still carry the historical pair: the HES
    /// settings hold the SAME username with two different passwords, belonging to opposite ends of
    /// the link — one HES presents when it connects, the other it WRITES INTO a meter via the
    /// SetMQTTBrokerDetails DLMS command. Nothing disambiguates them, so the meter-side one is
    /// tried first (we are impersonating a meter) and the client logs which one worked.
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
