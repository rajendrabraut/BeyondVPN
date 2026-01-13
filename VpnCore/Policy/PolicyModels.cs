using System.Collections.Generic;

namespace VpnCore.Policy
{
    public sealed class VpnPolicy
    {
        public List<string> AllowedCidrs { get; set; } = new List<string>();
        public List<string> AllowedPorts { get; set; } = new List<string>();
        public bool FullTunnel { get; set; }
        public List<string> DnsServers { get; set; } = new List<string>();
        public string Signature { get; set; } = string.Empty;
    }
}
