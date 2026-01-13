using System.Net.WebSockets;
using System.Text;
using VpnCore.Logging;

var logger = new FileLogger(Path.Combine(AppContext.BaseDirectory, "logs"), "server");
var relayUri = Environment.GetEnvironmentVariable("VPN_RELAY") ?? "wss://relay.example.com:443";

logger.Info($"Starting Linux server agent. Relay: {relayUri}");

using var socket = new ClientWebSocket();
try
{
    await socket.ConnectAsync(new Uri(relayUri), CancellationToken.None);
    logger.Info("Connected to relay (stub).");
    var payload = Encoding.UTF8.GetBytes("SERVER_HELLO");
    await socket.SendAsync(payload, WebSocketMessageType.Text, true, CancellationToken.None);
}
catch (Exception ex)
{
    logger.Error(ex, "Failed to connect to relay.");
}
