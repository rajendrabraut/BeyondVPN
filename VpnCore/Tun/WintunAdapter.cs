using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace VpnCore.Tun
{
    public sealed class WintunAdapter : ITunDevice
    {
        private readonly string _name;
        private IntPtr _adapterHandle;
        private IntPtr _sessionHandle;

        public WintunAdapter(string name)
        {
            _name = name;
            _adapterHandle = WintunCreateAdapter(name, "BeyondVPN", Guid.NewGuid());
            if (_adapterHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to create Wintun adapter.");
            }
            _sessionHandle = WintunStartSession(_adapterHandle, 0x400000);
        }

        public string Name => _name;

        public Task<int> ReadAsync(byte[] buffer, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                var size = 0u;
                var packet = WintunReceivePacket(_sessionHandle, ref size);
                if (packet == IntPtr.Zero)
                {
                    return 0;
                }
                Marshal.Copy(packet, buffer, 0, (int)size);
                WintunReleaseReceivePacket(_sessionHandle, packet);
                return (int)size;
            }, cancellationToken);
        }

        public Task WriteAsync(byte[] buffer, int length, CancellationToken cancellationToken)
        {
            return Task.Run(() =>
            {
                var packet = WintunAllocateSendPacket(_sessionHandle, (uint)length);
                if (packet == IntPtr.Zero)
                {
                    throw new InvalidOperationException("Failed to allocate send packet.");
                }
                Marshal.Copy(buffer, 0, packet, length);
                WintunSendPacket(_sessionHandle, packet);
            }, cancellationToken);
        }

        public void Dispose()
        {
            if (_sessionHandle != IntPtr.Zero)
            {
                WintunEndSession(_sessionHandle);
                _sessionHandle = IntPtr.Zero;
            }
            if (_adapterHandle != IntPtr.Zero)
            {
                WintunCloseAdapter(_adapterHandle);
                _adapterHandle = IntPtr.Zero;
            }
        }

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private static extern IntPtr WintunCreateAdapter(string name, string tunnelType, Guid requestedGuid);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void WintunCloseAdapter(IntPtr adapter);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr WintunStartSession(IntPtr adapter, uint capacity);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void WintunEndSession(IntPtr session);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr WintunReceivePacket(IntPtr session, ref uint packetSize);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void WintunReleaseReceivePacket(IntPtr session, IntPtr packet);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr WintunAllocateSendPacket(IntPtr session, uint packetSize);

        [DllImport("wintun.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern void WintunSendPacket(IntPtr session, IntPtr packet);
    }
}
