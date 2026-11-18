using Grpc.Core;
using VpnServer;
using VpnServer.Data;

namespace VpnServer.Services;

public class VpnServiceImpl : VpnService.VpnServiceBase
{
    private readonly ServerRepository _repo;
    private readonly UserRepository _users;
    private readonly ILogger<VpnServiceImpl> _logger;

    public VpnServiceImpl(ServerRepository repo, UserRepository users, ILogger<VpnServiceImpl> logger)
    {
        _repo = repo;
        _users = users;
        _logger = logger;
    }

    public override async Task<AuthResponse> Authenticate(AuthRequest request, ServerCallContext context)
    {
        var user = await _users.Authenticate(request.Username, request.Password);
        var ok = user is not null;

        return new AuthResponse {
            Success = ok,
            Token = ok ? Guid.NewGuid().ToString() : "",
            Message = ok ? "OK" : "Invalid credentials"
        };
    }

    public override Task<ServerList> GetServers(Empty request, ServerCallContext context)
    {
        var list = new ServerList();
        list.Servers.AddRange(_repo.GetAll().Select(s => new Server {
            Id = s.Id,
            Name = s.Name,
            Country = s.Country,
            Type = s.Type,
            LatencyMs = s.LatencyMs,
            IsFree = s.IsFree
        }));
        return Task.FromResult(list);
    }

    public override Task<ConfigResponse> GetConfig(ConfigRequest request, ServerCallContext context)
    {
        var cfg = _repo.GetConfig(request.ServerId);
        var type = _repo.GetById(request.ServerId)?.Type ?? "wireguard";
        return Task.FromResult(new ConfigResponse { Config = cfg, Type = type });
    }

    public override Task<Empty> ReportStatus(StatusReport request, ServerCallContext context)
    {
        _logger.LogInformation("Client {ip} {status} on {server}", request.ClientIp, request.Status, request.ServerId);
        return Task.FromResult(new Empty());
    }
}
