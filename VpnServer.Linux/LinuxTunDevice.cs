using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using VpnCore.Tun;

namespace VpnServer.Linux;

public sealed class LinuxTunDevice : ITunDevice
{
    private const int O_RDWR = 2;
    private const short IFF_TUN = 0x0001;
    private const short IFF_NO_PI = 0x1000;
    private const uint TUNSETIFF = 0x400454ca;

    private readonly SafeFileHandle _handle;
    private readonly FileStream _stream;

    public LinuxTunDevice(string name)
    {
        Name = name;
        _handle = new SafeFileHandle(open("/dev/net/tun", O_RDWR), ownsHandle: true);
        if (_handle.IsInvalid)
        {
            throw new InvalidOperationException("Failed to open /dev/net/tun");
        }

        var ifr = new byte[40];
        var nameBytes = Encoding.ASCII.GetBytes(name);
        Array.Copy(nameBytes, ifr, Math.Min(nameBytes.Length, 16));
        var flags = (short)(IFF_TUN | IFF_NO_PI);
        BitConverter.GetBytes(flags).CopyTo(ifr, 16);

        if (ioctl(_handle.DangerousGetHandle(), TUNSETIFF, ifr) < 0)
        {
            throw new InvalidOperationException("ioctl TUNSETIFF failed");
        }

        _stream = new FileStream(_handle, FileAccess.ReadWrite, 64 * 1024, isAsync: true);
    }

    public string Name { get; }

    public async Task<int> ReadAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        return await _stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
    }

    public async Task WriteAsync(byte[] buffer, int length, CancellationToken cancellationToken)
    {
        await _stream.WriteAsync(buffer, 0, length, cancellationToken);
    }

    public void Dispose()
    {
        _stream.Dispose();
        _handle.Dispose();
    }

    [DllImport("libc", SetLastError = true)]
    private static extern int open(string pathname, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern int ioctl(IntPtr fd, uint request, byte[] data);
}
