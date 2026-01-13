using System.Collections.Concurrent;
using System.Net.WebSockets;
using VpnCore.Logging;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var logger = new FileLogger(Path.Combine(AppContext.BaseDirectory, "logs"), "relay");

app.UseWebSockets();

var sessions = new ConcurrentDictionary<string, RelaySession>();

app.Map("/relay", async context =>
{
    // The relay is a blind forwarder. It does not decrypt payloads.
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = 400;
        return;
    }

    var role = context.Request.Query["role"].ToString();
    var sessionId = context.Request.Query["session"].ToString();
    if (string.IsNullOrWhiteSpace(role) || string.IsNullOrWhiteSpace(sessionId))
    {
        context.Response.StatusCode = 400;
        return;
    }

    var socket = await context.WebSockets.AcceptWebSocketAsync();
    var session = sessions.GetOrAdd(sessionId, _ => new RelaySession());
    logger.Info($"Relay connection: {role} session {sessionId}");

    if (role == "server")
    {
        session.Server = socket;
    }
    else
    {
        session.Client = socket;
    }

    await session.TryBridgeAsync(logger, sessionId);
});

app.Run();

sealed class RelaySession
{
    public WebSocket? Server { get; set; }
    public WebSocket? Client { get; set; }

    public async Task TryBridgeAsync(FileLogger logger, string sessionId)
    {
        // Only bridge when both sides are connected.
        if (Server == null || Client == null)
        {
            return;
        }

        var server = Server;
        var client = Client;

        logger.Info($"Bridging session {sessionId}.");

        var serverToClient = PumpAsync(server, client, logger, sessionId, "server->client");
        var clientToServer = PumpAsync(client, server, logger, sessionId, "client->server");

        await Task.WhenAny(serverToClient, clientToServer);

        try
        {
            await server.CloseAsync(WebSocketCloseStatus.NormalClosure, "Relay closing", CancellationToken.None);
            await client.CloseAsync(WebSocketCloseStatus.NormalClosure, "Relay closing", CancellationToken.None);
        }
        catch
        {
        }
    }

    private static async Task PumpAsync(WebSocket from, WebSocket to, FileLogger logger, string sessionId, string label)
    {
        var buffer = new byte[64 * 1024];
        while (from.State == WebSocketState.Open && to.State == WebSocketState.Open)
        {
            var result = await from.ReceiveAsync(buffer, CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                logger.Info($"Relay closing {sessionId} {label}.");
                return;
            }

            await to.SendAsync(new ArraySegment<byte>(buffer, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
        }
    }
}
