namespace MeterSimulator.Config
{
    /// <summary>
    /// Periodic push (DataNotification) settings, bound from appsettings.json
    /// under MeterConfig:Push.  The meter's push DESTINATION (IP) and transport
    /// come from the PushSetup DLMS object (loaded from XML); this config only
    /// carries what the object model can't express for an outbound socket:
    /// whether push is on, how often, the fallback port, and ciphering.
    /// </summary>
    public class PushConfig
    {
        /// <summary>Master on/off switch for periodic push.</summary>
        public bool Enabled { get; set; } = false;

        /// <summary>
        /// Overrides the PushSetup Destination loaded from XML.  Empty = keep the
        /// XML value.  Set this to redirect push away from whatever address the XML
        /// template baked in (e.g. a public head-end IP) to one you control, such
        /// as "127.0.0.1" for a local Wireshark test.  Bare IP → the Port below is
        /// used; include ":port" (IPv4) or "[addr]:port" (IPv6) to set it inline.
        /// </summary>
        public string Destination { get; set; } = "";

        /// <summary>Seconds between pushes.</summary>
        public int IntervalSeconds { get; set; } = 30;

        /// <summary>
        /// TCP port to connect to when the PushSetup Destination is a bare IP
        /// with no ":port".  Ignored if the Destination already carries a port.
        /// </summary>
        public int Port { get; set; } = 7000;

        /// <summary>
        /// false → send plaintext DataNotification (readable in Wireshark).
        /// true  → general-glo-ciphering using the meter's keys.
        /// </summary>
        public bool UseCiphering { get; set; } = false;
    }
}
