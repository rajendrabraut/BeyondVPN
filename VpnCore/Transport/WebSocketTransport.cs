using System;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using VpnCore.Protocol;

namespace VpnCore.Transport
{
    public sealed class WebSocketTransport
    {
        private readonly WebSocket _socket;

        public WebSocketTransport(WebSocket socket)
        {
            _socket = socket;
        }

        // Sends a binary frame over WSS.
        public async Task SendFrameAsync(Frame frame, CancellationToken cancellationToken)
        {
            var bytes = frame.ToBytes();
            await _socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Binary, true, cancellationToken)
                .ConfigureAwait(false);
        }

        // Receives a full frame and validates the length prefix.
        public async Task<Frame?> ReceiveFrameAsync(CancellationToken cancellationToken)
        {
            var buffer = new byte[64 * 1024];
            using (var ms = new MemoryStream())
            {
                WebSocketReceiveResult result;
                do
                {
                    result = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken)
                        .ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        return null;
                    }
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                var data = ms.ToArray();
                if (data.Length < 4)
                {
                    return null;
                }

                var length = BitConverter.ToInt32(data, 0);
                if (length + 4 != data.Length)
                {
                    throw new InvalidDataException("Invalid frame length.");
                }

                return Frame.FromBytes(data);
            }
        }
    }
}
