namespace ManyMeterSimulator.Networking.Nic;

public static class NicTypes
{
    /// <summary>
    /// The transport that physically carries a NIC's traffic.
    ///
    /// Identity for every NIC except IMG, which folds into the direct-4G transport: c and d share a
    /// broker, a topic pair and a framing format, so they are one connection. A batch still records
    /// which of the two a meter is (that is real hardware), but nothing on the wire distinguishes
    /// them.
    /// </summary>
    public static NicType TransportFor(NicType nic) => nic == NicType.Mqtt4GImg ? NicType.Mqtt4G : nic;

    /// <summary>
    /// True if traffic arriving on <paramref name="transport"/> may legitimately be served for a
    /// meter provisioned as <paramref name="provisioned"/>. Guards against a meter being polled
    /// over a NIC it was never provisioned for — a TCP meter answering over MQTT would be a
    /// provisioning error, not a meter.
    /// </summary>
    public static bool CanServe(NicType transport, NicType provisioned) =>
        TransportFor(provisioned) == TransportFor(transport);

    /// <summary>
    /// True for the NICs reached through an MQTT broker — the ones that bind to a broker in the
    /// network registry. Written as "not TCP" rather than a list of four so a NIC added later is
    /// MQTT by default, which is the safer way to be wrong: a new MQTT NIC that is missed here
    /// would silently bind to nothing.
    /// </summary>
    public static bool IsMqtt(NicType nic) => nic != NicType.Tcp4G;
}
