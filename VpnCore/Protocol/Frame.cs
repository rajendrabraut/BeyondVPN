using System;

namespace VpnCore.Protocol
{
    public sealed class Frame
    {
        public MessageType Type { get; }
        public byte[] Payload { get; }

        // Frame format: [length:4][type:1][payload:N]
        public Frame(MessageType type, byte[] payload)
        {
            Type = type;
            Payload = payload ?? Array.Empty<byte>();
        }

        public byte[] ToBytes()
        {
            var length = 1 + Payload.Length;
            var buffer = new byte[4 + length];
            var lenBytes = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Copy(lenBytes, 0, buffer, 0, 4);
            }
            else
            {
                Array.Reverse(lenBytes);
                Array.Copy(lenBytes, 0, buffer, 0, 4);
            }
            buffer[4] = (byte)Type;
            Array.Copy(Payload, 0, buffer, 5, Payload.Length);
            return buffer;
        }

        // Expects the caller to supply a full frame (length already checked).
        public static Frame FromBytes(byte[] buffer)
        {
            if (buffer.Length < 5)
            {
                throw new ArgumentException("Frame too small.", nameof(buffer));
            }

            var type = (MessageType)buffer[4];
            var payload = new byte[buffer.Length - 5];
            Array.Copy(buffer, 5, payload, 0, payload.Length);
            return new Frame(type, payload);
        }
    }
}
