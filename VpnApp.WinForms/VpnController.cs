using System;
using System.IO;
using VpnCore.Logging;

namespace VpnApp.WinForms
{
    public sealed class VpnController
    {
        private readonly FileLogger _clientLogger;
        private readonly FileLogger _serverLogger;

        // Single controller used by both Client and Server modes in the same UI.
        public VpnController()
        {
            var logDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            _clientLogger = new FileLogger(logDir, "client");
            _serverLogger = new FileLogger(logDir, "server");
        }

        public void StartClient(string endpoint)
        {
            // Placeholder: will create WSS connection and start VPN session.
            _clientLogger.Info($"Starting client to {endpoint}.");
        }

        public void StopClient()
        {
            _clientLogger.Info("Stopping client.");
        }

        public void StartServer(string relayEndpoint)
        {
            // Placeholder: will reverse-connect to relay and host VPN sessions.
            _serverLogger.Info($"Starting server with relay {relayEndpoint}.");
        }

        public void StopServer()
        {
            _serverLogger.Info("Stopping server.");
        }
    }
}
