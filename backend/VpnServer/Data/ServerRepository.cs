using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace VpnServer.Services;

public record VpnServerModel(
    string Id,
    string Name,
    string Country,
    string Type,
    int LatencyMs,
    bool IsFree,
    string Config,
    string Source
);

public record VpnSourceDefinition(
    string Id,
    string Name,
    string Country,
    string Protocol,
    int LatencyMs,
    string Source,
    bool IsFree,
    string? Path,
    string? Url
);

public sealed class VpnSourceManifest
{
    public List<VpnSourceDefinition> Sources { get; set; } = [];
}

public class ServerRepository
{
    private readonly List<VpnServerModel> _servers = new();
    private readonly object _lock = new();
    private readonly object _sourceLock = new();
    private readonly string _projectRoot;
    private readonly string _sourcesPath;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public ServerRepository(IWebHostEnvironment environment, IConfiguration configuration)
    {
        _projectRoot = ResolveProjectRoot(environment.ContentRootPath);
        _sourcesPath = ResolvePath(_projectRoot, configuration["VpnSources:ManifestPath"] ?? "vpn_sources.json");

        _servers.Add(new(
            "seed-openvpn",
            "OpenVPN Sample Node",
            "Custom",
            "openvpn",
            28,
            true,
            ReadSampleConfig("samples\\openvpn-sample.ovpn"),
            "Manifest"
        ));

        _servers.Add(new(
            "seed-wireguard",
            "WireGuard Sample Node",
            "Custom",
            "wireguard",
            35,
            true,
            ReadSampleConfig("samples\\wireguard-sample.conf"),
            "Manifest"
        ));

        _ = RefreshSources();
    }

    public VpnSourceManifest GetSourceManifest()
    {
        lock (_sourceLock)
        {
            var manifest = ReadSourceManifestUnlocked();
            return new VpnSourceManifest { Sources = manifest.Sources.ToList() };
        }
    }

    public Task<(bool Success, string? Error)> UpsertSource(VpnSourceDefinition source)
    {
        lock (_sourceLock)
        {
            var normalized = NormalizeSource(source);
            if (!ValidateSource(normalized, out var error))
            {
                return Task.FromResult((false, error));
            }

            var manifest = ReadSourceManifestUnlocked();
            var index = manifest.Sources.FindIndex(s => string.Equals(s.Id, normalized.Id, StringComparison.OrdinalIgnoreCase));
            if (index >= 0)
            {
                manifest.Sources[index] = normalized;
            }
            else
            {
                manifest.Sources.Add(normalized);
            }

            SaveSourceManifestUnlocked(manifest);
            return Task.FromResult<(bool Success, string? Error)>((true, null));
        }
    }

    public Task<bool> DeleteSource(string id)
    {
        lock (_sourceLock)
        {
            var manifest = ReadSourceManifestUnlocked();
            var removed = manifest.Sources.RemoveAll(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase)) > 0;
            if (removed)
            {
                SaveSourceManifestUnlocked(manifest);
            }

            return Task.FromResult(removed);
        }
    }

    public async Task RefreshSources()
    {
        try
        {
            var imported = await FetchFromPython();
            if (imported.Count == 0)
            {
                imported = await FetchFromVpnGateFallback();
            }

            if (imported.Count == 0)
            {
                return;
            }

            lock (_lock)
            {
                _servers.Clear();
                _servers.AddRange(imported);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to refresh VPN nodes: {ex.Message}");
        }
    }

    public IEnumerable<VpnServerModel> GetAll()
    {
        lock (_lock)
        {
            return _servers.ToList();
        }
    }

    public VpnServerModel? GetById(string id)
    {
        lock (_lock)
        {
            return _servers.FirstOrDefault(s => s.Id == id);
        }
    }

    public string GetConfig(string id) => GetById(id)?.Config ?? string.Empty;

    private async Task<List<VpnServerModel>> FetchFromPython()
    {
        var scriptPath = Path.Combine(_projectRoot, "fetch_servers.py");
        if (!File.Exists(scriptPath))
        {
            return [];
        }

        var (pythonFileName, pythonArgumentsPrefix) = ResolvePythonRunner();
        var start = new ProcessStartInfo
        {
            FileName = pythonFileName,
            Arguments = $"{pythonArgumentsPrefix}\"{scriptPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = _projectRoot,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        start.Environment["FORTICLONE_SOURCES_FILE"] = _sourcesPath;

        using var process = Process.Start(start);
        if (process is null)
        {
            return [];
        }

        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            Console.WriteLine($"Python source collector failed: {stderr}");
            return [];
        }

        var pyServers = JsonSerializer.Deserialize<List<PyServer>>(stdout,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

        return pyServers?
            .Where(s => !string.IsNullOrWhiteSpace(s.Id) && !string.IsNullOrWhiteSpace(s.Config))
            .Select(s => new VpnServerModel(
                s.Id,
                s.Name,
                s.Country,
                string.IsNullOrWhiteSpace(s.Type) ? DetectProtocol(s.Config) : s.Type,
                s.LatencyMs <= 0 ? 999 : s.LatencyMs,
                s.IsFree,
                s.Config,
                string.IsNullOrWhiteSpace(s.Source) ? "Python" : s.Source
            ))
            .ToList() ?? [];
    }

    private async Task<List<VpnServerModel>> FetchFromVpnGateFallback()
    {
        using var client = new HttpClient();
        var csvData = await client.GetStringAsync("https://www.vpngate.net/api/iphone/");
        var lines = csvData.Split('\n');

        var servers = new List<VpnServerModel>();

        for (var i = 2; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("*"))
            {
                continue;
            }

            var cols = line.Split(',');
            if (cols.Length < 15)
            {
                continue;
            }

            string config;
            try
            {
                config = Encoding.UTF8.GetString(Convert.FromBase64String(cols[14]));
            }
            catch
            {
                continue;
            }

            servers.Add(new VpnServerModel(
                $"vpngate-{cols[1]}",
                $"VPNGate {cols[5]} {cols[0]}",
                cols[5],
                "openvpn",
                int.TryParse(cols[3], out var ping) ? ping : 100,
                true,
                config,
                "VPNGate"
            ));

            if (servers.Count >= 10)
            {
                break;
            }
        }

        return servers;
    }

    private static string ResolveProjectRoot(string contentRoot)
    {
        var probe = new DirectoryInfo(contentRoot);

        while (probe is not null)
        {
            if (File.Exists(Path.Combine(probe.FullName, "fetch_servers.py")))
            {
                return probe.FullName;
            }

            probe = probe.Parent;
        }

        probe = new DirectoryInfo(AppContext.BaseDirectory);
        while (probe is not null)
        {
            if (File.Exists(Path.Combine(probe.FullName, "fetch_servers.py")))
            {
                return probe.FullName;
            }

            probe = probe.Parent;
        }

        return contentRoot;
    }

    private string ReadSampleConfig(string relativePath)
    {
        var target = Path.Combine(_projectRoot, relativePath);
        return File.Exists(target) ? File.ReadAllText(target) : string.Empty;
    }

    private static string DetectProtocol(string config)
    {
        var normalized = config.ToLowerInvariant();
        if (normalized.Contains("[interface]") || normalized.Contains("privatekey"))
        {
            return "wireguard";
        }

        return "openvpn";
    }

    private VpnSourceManifest ReadSourceManifestUnlocked()
    {
        if (!File.Exists(_sourcesPath))
        {
            return new VpnSourceManifest();
        }

        try
        {
            return JsonSerializer.Deserialize<VpnSourceManifest>(
                File.ReadAllText(_sourcesPath, Encoding.UTF8),
                _jsonOptions) ?? new VpnSourceManifest();
        }
        catch
        {
            return new VpnSourceManifest();
        }
    }

    private void SaveSourceManifestUnlocked(VpnSourceManifest manifest)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_sourcesPath)!);
        var tempPath = $"{_sourcesPath}.{Guid.NewGuid():N}.tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(manifest, _jsonOptions), Encoding.UTF8);
        File.Move(tempPath, _sourcesPath, true);
    }

    private VpnSourceDefinition NormalizeSource(VpnSourceDefinition source)
    {
        var protocol = source.Protocol.Trim().ToLowerInvariant();
        var id = string.IsNullOrWhiteSpace(source.Id)
            ? $"{protocol}-{Guid.NewGuid():N}"[..24]
            : source.Id.Trim();

        return source with
        {
            Id = id,
            Name = string.IsNullOrWhiteSpace(source.Name) ? $"{protocol} node" : source.Name.Trim(),
            Country = string.IsNullOrWhiteSpace(source.Country) ? "Unknown" : source.Country.Trim(),
            Protocol = protocol,
            LatencyMs = source.LatencyMs <= 0 ? 999 : source.LatencyMs,
            Source = string.IsNullOrWhiteSpace(source.Source) ? "Admin" : source.Source.Trim(),
            IsFree = source.IsFree,
            Path = string.IsNullOrWhiteSpace(source.Path) ? null : source.Path.Trim(),
            Url = string.IsNullOrWhiteSpace(source.Url) ? null : source.Url.Trim(),
        };
    }

    private bool ValidateSource(VpnSourceDefinition source, out string? error)
    {
        error = null;

        if (string.IsNullOrWhiteSpace(source.Id))
        {
            error = "Source id is required.";
            return false;
        }

        if (source.Protocol is not ("openvpn" or "wireguard"))
        {
            error = "Protocol must be openvpn or wireguard.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(source.Path) && string.IsNullOrWhiteSpace(source.Url))
        {
            error = "Provide either a local config path or an HTTP(S) config URL.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(source.Url) &&
            (!Uri.TryCreate(source.Url, UriKind.Absolute, out var uri) ||
             uri.Scheme is not ("http" or "https")))
        {
            error = "Config URL must be an absolute HTTP(S) URL.";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(source.Path) && !File.Exists(ResolvePath(_projectRoot, source.Path)))
        {
            error = $"Config path was not found: {source.Path}";
            return false;
        }

        return true;
    }

    private static string ResolvePath(string root, string path) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(root, path));

    private static (string FileName, string ArgumentsPrefix) ResolvePythonRunner()
    {
        if (CommandExists("python"))
        {
            return ("python", string.Empty);
        }

        return CommandExists("py") ? ("py", "-3 ") : ("python", string.Empty);
    }

    private static bool CommandExists(string command)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = command,
                Arguments = "--version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });

            process?.WaitForExit(2000);
            return process?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private record PyServer(
        string Id,
        string Name,
        string Country,
        string Type,
        int LatencyMs,
        bool IsFree,
        string Config,
        string Source
    );
}
