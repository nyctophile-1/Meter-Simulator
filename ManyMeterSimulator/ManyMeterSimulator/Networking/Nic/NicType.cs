namespace ManyMeterSimulator.Networking.Nic;

/// <summary>
/// The network interface card a simulated meter presents to the HES. Every meter has exactly one,
/// fixed per batch — a real meter's NIC is hardware.
///
/// The DLMS brain below is identical for all of them: each variant differs only in how the HES
/// reaches it (transport + topics) and how the DLMS wrapper frame is packaged on the wire. See
/// virtual_nics.md §14 for the byte-level format of each.
/// </summary>
public enum NicType
{
    /// <summary>4G TCP — one IPv6 address per meter, DLMS wrapper frames straight over the socket.</summary>
    Tcp4G,

    /// <summary>4G MQTT — node id in the topic, 6-byte framing header (virtual_nics.md §14.1).</summary>
    Mqtt4G,

    /// <summary>
    /// 4G IMG MQTT — the gateway-meter variant. Wire-identical to <see cref="Mqtt4G"/> (same broker,
    /// topics and framing); the difference is meter hardware, so it shares the same codec.
    /// </summary>
    Mqtt4GImg,

    /// <summary>
    /// RF MQTT Wirepas — protobuf envelope, node id in the payload (virtual_nics.md §14.2).
    ///
    /// <para>
    /// ONE physical NIC with TWO channels, not two NIC types. It is transparent on one and smart on
    /// the other:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// <b>endpoint 3 — DLMS</b>: passthrough, exactly like every other NIC. The DLMS conversation
    /// is between HES and the brain; the NIC just carries bytes.
    /// </item>
    /// <item>
    /// <b>endpoint 13 — custom</b> (informally "RF2"): HES asks for an OUTCOME ("block load profile
    /// from T1 to T2") and the NIC firmware runs the whole DLMS conversation with the meter itself,
    /// returning a manufacturer-specific binary result. Simulating that needs a DLMS *client*
    /// inside the NIC — see <c>Networking/SmartNic</c>.
    /// </item>
    /// </list>
    ///
    /// The custom channel still reads through the same brain, so a custom profile read and a plain
    /// DLMS read of the same meter can never disagree. Which channel a request belongs to is
    /// decided by the protobuf's destination_endpoint, not by the topic or the batch.
    /// </summary>
    MqttWirepas,

    /// <summary>RF MQTT Kmesh — protobuf envelope, fragmentation inside the message (virtual_nics.md §14.3).</summary>
    MqttKmesh,
}
