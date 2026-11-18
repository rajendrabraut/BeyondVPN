using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Tokens;
using VpnServer;
using VpnServer.Data;
using VpnServer.Security;
using VpnServer.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5001, o => o.Protocols = HttpProtocols.Http2);
    options.ListenLocalhost(5000, o => o.Protocols = HttpProtocols.Http1);
});

builder.Services.AddDataProtection();
builder.Services.AddGrpc();
builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
    p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));
builder.Services.AddSingleton<ServerRepository>();
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<AuthTokenService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var jwtKey = builder.Configuration["Jwt:Key"] ?? "FortiCloneVPN-Development-Key-Please-Change";
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "FortiCloneVPN";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "FortiCloneClients";

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
            ClockSkew = TimeSpan.FromMinutes(2),
        };
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var repo = scope.ServiceProvider.GetRequiredService<UserRepository>();
    await repo.EnsureSchemaAsync();
    await repo.SeedDefaultUsers();
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseGrpcWeb(new GrpcWebOptions { DefaultEnabled = true });

app.MapGrpcService<VpnServiceImpl>().EnableGrpcWeb();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapGet("/api/health", () => Results.Ok(new { status = "ok", rest = 5000, grpc = 5001 }));

app.MapGet("/api/vpn/capabilities", (ServerRepository repo, IConfiguration configuration) => Results.Ok(new
{
    protocols = new[]
    {
        new { id = "openvpn", name = "OpenVPN", backend = ".NET + Python collector", configurable = true },
        new { id = "wireguard", name = "WireGuard", backend = ".NET + Python collector", configurable = true },
    },
    sourceManifest = repo.GetSourceManifest(),
    environmentImports = new
    {
        openVpnUrls = "FORTICLONE_OPENVPN_URLS",
        wireGuardUrls = "FORTICLONE_WIREGUARD_URLS",
        vpnGate = "FORTICLONE_ENABLE_VPNGATE=1",
    },
    userStore = new
    {
        type = "encrypted-file",
        path = configuration["UserStore:Path"] ?? "App_Data/users.enc",
    },
}));

app.MapGet("/api/oauth/providers", (IConfiguration configuration) =>
{
    var googleClientId = configuration["OAuth:Google:ClientId"] ?? string.Empty;
    return Results.Ok(new
    {
        providers = new[]
        {
            new
            {
                id = "google",
                name = "Google",
                enabled = !string.IsNullOrWhiteSpace(googleClientId),
                clientId = googleClientId,
                note = string.IsNullOrWhiteSpace(googleClientId)
                    ? "Set OAuth:Google:ClientId to enable Google sign-in."
                    : "Ready for frontend Google sign-in.",
            }
        }
    });
});

app.MapGet("/api/servers", (ServerRepository repo) => Results.Ok(repo.GetAll()));

app.MapPost("/api/servers/refresh", async (ServerRepository repo) =>
{
    await repo.RefreshSources();
    return Results.Ok(new { success = true, count = repo.GetAll().Count() });
}).RequireAuthorization("AdminOnly");

app.MapGet("/api/vpn/sources", (ServerRepository repo) =>
    Results.Ok(repo.GetSourceManifest())).RequireAuthorization("AdminOnly");

app.MapPost("/api/vpn/sources", async (VpnSourceRequest req, ServerRepository repo) =>
{
    var result = await repo.UpsertSource(new VpnSourceDefinition(
        req.Id,
        req.Name,
        req.Country,
        req.Protocol,
        req.LatencyMs ?? 999,
        req.Source ?? "Admin",
        req.IsFree ?? true,
        req.Path,
        req.Url));

    if (!result.Success)
    {
        return Results.BadRequest(new { error = result.Error });
    }

    await repo.RefreshSources();
    return Results.Ok(new { success = true, count = repo.GetAll().Count(), sourceManifest = repo.GetSourceManifest() });
}).RequireAuthorization("AdminOnly");

app.MapDelete("/api/vpn/sources/{id}", async (string id, ServerRepository repo) =>
{
    var removed = await repo.DeleteSource(id);
    if (!removed)
    {
        return Results.NotFound(new { error = "VPN source not found." });
    }

    await repo.RefreshSources();
    return Results.Ok(new { success = true, count = repo.GetAll().Count(), sourceManifest = repo.GetSourceManifest() });
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/auth", async (LoginRequest req, UserRepository repo, AuthTokenService tokens) =>
{
    var user = await repo.Authenticate(req.Username, req.Password);
    return user is null
        ? Results.Unauthorized()
        : Results.Ok(new
        {
            success = true,
            token = tokens.CreateToken(user),
            user = ToUserDto(user),
        });
});

app.MapPost("/api/register", async (RegistrationRequest req, UserRepository repo, AuthTokenService tokens) =>
{
    var result = await repo.Register(req.Username, req.Password, req.Email, req.DisplayName);

    return !result.Success || result.User is null
        ? Results.BadRequest(new { error = result.Error ?? "Unable to register user." })
        : Results.Ok(new
        {
            success = true,
            token = tokens.CreateToken(result.User),
            user = ToUserDto(result.User),
        });
});

app.MapGet("/api/me", async (ClaimsPrincipal principal, UserRepository repo) =>
{
    var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrWhiteSpace(userId))
    {
        return Results.Unauthorized();
    }

    var user = await repo.GetById(userId);
    return user is null ? Results.NotFound() : Results.Ok(ToUserDto(user));
}).RequireAuthorization();

app.MapGet("/api/users", async (UserRepository repo) =>
{
    var users = await repo.GetAllUsers();
    return Results.Ok(users.Select(ToUserDto));
}).RequireAuthorization("AdminOnly");

app.MapPost("/api/user/password", async (PasswordUpdateRequest req, UserRepository repo) =>
{
    var success = await repo.UpdatePassword(req.Username, req.NewPassword);
    return success ? Results.Ok(new { success = true }) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/api/users/{id}/role", async (string id, RoleUpdateRequest req, UserRepository repo) =>
{
    var success = await repo.UpdateRole(id, req.Role);
    return success ? Results.Ok(new { success = true }) : Results.NotFound();
}).RequireAuthorization("AdminOnly");

app.MapGet("/api/config/{id}", (string id, ServerRepository repo) =>
{
    var server = repo.GetById(id);
    return server is null
        ? Results.NotFound(new { error = "Server not found" })
        : Results.Ok(new { server.Id, server.Name, server.Country, server.Type, server.Source, server.Config });
});

app.MapGet("/api/config/{id}/raw", (string id, ServerRepository repo) =>
{
    var config = repo.GetConfig(id);
    return string.IsNullOrWhiteSpace(config)
        ? Results.NotFound(new { error = "Server config not found" })
        : Results.Text(config, "text/plain");
});

app.Run();

static object ToUserDto(UserEntity user) => new
{
    user.Id,
    user.Username,
    user.DisplayName,
    user.Email,
    user.Role,
    user.Provider,
    user.CreatedAt,
    user.LastLoginAt,
};

public record LoginRequest(string Username, string Password);
public record RegistrationRequest(string Username, string Password, string? Email, string? DisplayName);
public record PasswordUpdateRequest(string Username, string NewPassword);
public record RoleUpdateRequest(string Role);
public record VpnSourceRequest(
    string Id,
    string Name,
    string Country,
    string Protocol,
    int? LatencyMs,
    string? Source,
    bool? IsFree,
    string? Path,
    string? Url);
