using System.Diagnostics;
using VpnCore.Policy;

namespace VpnApp.WinForms
{
    public sealed class PolicyEnforcer
    {
        public void ApplyPolicy(VpnPolicy policy)
        {
            // Lightweight fallback using netsh firewall rules.
            // Prefer WFP in a full implementation for per-interface rules.
            foreach (var cidr in policy.AllowedCidrs)
            {
                var ruleName = $"BeyondVPN-Allow-{cidr}";
                var args = $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=allow remoteip={cidr}";
                RunNetsh(args);
            }
        }

        private static void RunNetsh(string arguments)
        {
            using (var process = new Process())
            {
                process.StartInfo.FileName = "netsh";
                process.StartInfo.Arguments = arguments;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.Start();
                process.WaitForExit();
            }
        }
    }
}
