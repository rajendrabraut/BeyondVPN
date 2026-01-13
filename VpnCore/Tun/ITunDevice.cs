using System;
using System.Threading;
using System.Threading.Tasks;

namespace VpnCore.Tun
{
    public interface ITunDevice : IDisposable
    {
        string Name { get; }
        Task<int> ReadAsync(byte[] buffer, CancellationToken cancellationToken);
        Task WriteAsync(byte[] buffer, int length, CancellationToken cancellationToken);
    }
}
