using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;

namespace VpnServer.Data;

public record RegistrationResult(bool Success, UserEntity? User, string? Error);

public class UserRepository
{
    private const string CurrentPasswordScheme = "PBKDF2";
    private const int Pbkdf2Iterations = 210_000;
    private const int SaltSize = 16;
    private const int KeySize = 32;

    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _storePath;
    private readonly string _legacyDbPath;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    public UserRepository(
        IDataProtectionProvider protectionProvider,
        IWebHostEnvironment environment,
        IConfiguration configuration)
    {
        _protector = protectionProvider.CreateProtector("FortiClientCloneVPN.Users.FileStore.v1");

        var storePath = configuration["UserStore:Path"] ?? "App_Data/users.enc";
        _storePath = ResolvePath(environment.ContentRootPath, storePath);

        var legacyDbPath = configuration["UserStore:LegacySqlitePath"] ?? "vpn.db";
        _legacyDbPath = ResolvePath(environment.ContentRootPath, legacyDbPath);
    }

    public async Task EnsureSchemaAsync()
    {
        await _gate.WaitAsync();
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_storePath)!);

            if (!File.Exists(_storePath))
            {
                var document = new UserStoreDocument
                {
                    Users = await LoadLegacyUsersAsync(),
                };

                await SaveDocumentUnlockedAsync(document);
                return;
            }

            _ = await ReadDocumentUnlockedAsync();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SeedDefaultUsers()
    {
        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            var changed = false;

            changed |= EnsureUser(document, "admin", "admin", "Admin", "Administrator", "admin@local.test");
            changed |= EnsureUser(document, "demo", "demo", "User", "Demo User", "demo@local.test");

            if (changed)
            {
                await SaveDocumentUnlockedAsync(document);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<UserEntity?> Authenticate(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            var user = document.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));

            if (user is null || !VerifyPassword(user, password, out var shouldUpgrade))
            {
                return null;
            }

            user.LastLoginAt = DateTime.UtcNow;
            if (shouldUpgrade)
            {
                user.PasswordHash = HashPassword(password);
                user.Password = string.Empty;
            }

            await SaveDocumentUnlockedAsync(document);
            return Clone(user);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<RegistrationResult> Register(string username, string password, string? email, string? displayName)
    {
        username = username.Trim();

        if (string.IsNullOrWhiteSpace(username) || username.Length < 3)
        {
            return new RegistrationResult(false, null, "Username must be at least 3 characters.");
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            return new RegistrationResult(false, null, "Password must be at least 8 characters.");
        }

        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            if (document.Users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)))
            {
                return new RegistrationResult(false, null, "Username is already registered.");
            }

            var user = new UserEntity
            {
                Id = Guid.NewGuid().ToString("N"),
                Username = username,
                Password = string.Empty,
                PasswordHash = HashPassword(password),
                Email = email?.Trim() ?? string.Empty,
                DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(),
                Role = "User",
                Provider = "local",
                ProviderSubject = string.Empty,
                CreatedAt = DateTime.UtcNow,
            };

            document.Users.Add(user);
            await SaveDocumentUnlockedAsync(document);
            return new RegistrationResult(true, Clone(user), null);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<UserEntity>> GetAllUsers()
    {
        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            return document.Users
                .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
                .Select(Clone)
                .ToList();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<UserEntity?> GetById(string id)
    {
        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            var user = document.Users.FirstOrDefault(u => string.Equals(u.Id, id, StringComparison.Ordinal));
            return user is null ? null : Clone(user);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> UpdatePassword(string username, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(newPassword) || newPassword.Length < 8)
        {
            return false;
        }

        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            var user = document.Users.FirstOrDefault(u =>
                string.Equals(u.Username, username.Trim(), StringComparison.OrdinalIgnoreCase));

            if (user is null)
            {
                return false;
            }

            user.Password = string.Empty;
            user.PasswordHash = HashPassword(newPassword);
            await SaveDocumentUnlockedAsync(document);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> UpdateRole(string id, string role)
    {
        var normalizedRole = string.Equals(role, "Admin", StringComparison.OrdinalIgnoreCase) ? "Admin" : "User";

        await _gate.WaitAsync();
        try
        {
            var document = await ReadDocumentUnlockedAsync();
            var user = document.Users.FirstOrDefault(u => string.Equals(u.Id, id, StringComparison.Ordinal));

            if (user is null)
            {
                return false;
            }

            user.Role = normalizedRole;
            await SaveDocumentUnlockedAsync(document);
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<UserStoreDocument> ReadDocumentUnlockedAsync()
    {
        if (!File.Exists(_storePath))
        {
            return new UserStoreDocument();
        }

        var protectedJson = await File.ReadAllTextAsync(_storePath, Encoding.UTF8);
        if (string.IsNullOrWhiteSpace(protectedJson))
        {
            return new UserStoreDocument();
        }

        var json = _protector.Unprotect(protectedJson);
        return JsonSerializer.Deserialize<UserStoreDocument>(json, _jsonOptions) ?? new UserStoreDocument();
    }

    private async Task SaveDocumentUnlockedAsync(UserStoreDocument document)
    {
        document.Version = 1;
        var json = JsonSerializer.Serialize(document, _jsonOptions);
        var protectedJson = _protector.Protect(json);
        var tempPath = $"{_storePath}.{Guid.NewGuid():N}.tmp";

        await File.WriteAllTextAsync(tempPath, protectedJson, Encoding.UTF8);
        File.Move(tempPath, _storePath, true);
    }

    private async Task<List<UserEntity>> LoadLegacyUsersAsync()
    {
        var users = new List<UserEntity>();
        if (!File.Exists(_legacyDbPath))
        {
            return users;
        }

        try
        {
            await using var connection = new SqliteConnection($"Data Source={_legacyDbPath}");
            await connection.OpenAsync();

            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT * FROM Users";

            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                var username = ReadString(reader, "Username")?.Trim();
                if (string.IsNullOrWhiteSpace(username) ||
                    users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                users.Add(new UserEntity
                {
                    Id = ReadString(reader, "Id") ?? Guid.NewGuid().ToString("N"),
                    Username = username,
                    Password = ReadString(reader, "Password") ?? string.Empty,
                    PasswordHash = ReadString(reader, "PasswordHash") ?? string.Empty,
                    Email = ReadString(reader, "Email") ?? string.Empty,
                    DisplayName = ReadString(reader, "DisplayName") ?? username,
                    Role = string.Equals(ReadString(reader, "Role"), "Admin", StringComparison.OrdinalIgnoreCase)
                        ? "Admin"
                        : "User",
                    Provider = ReadString(reader, "Provider") ?? "local",
                    ProviderSubject = ReadString(reader, "ProviderSubject") ?? string.Empty,
                    CreatedAt = ReadDateTime(reader, "CreatedAt") ?? DateTime.UtcNow,
                    LastLoginAt = ReadDateTime(reader, "LastLoginAt"),
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Legacy user migration skipped: {ex.Message}");
        }

        return users;
    }

    private bool EnsureUser(UserStoreDocument document, string username, string password, string role, string displayName, string email)
    {
        if (document.Users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        document.Users.Add(new UserEntity
        {
            Id = Guid.NewGuid().ToString("N"),
            Username = username,
            Password = string.Empty,
            PasswordHash = HashPassword(password),
            Email = email,
            DisplayName = displayName,
            Role = role,
            Provider = "local",
            CreatedAt = DateTime.UtcNow,
        });

        return true;
    }

    private static bool VerifyPassword(UserEntity user, string password, out bool shouldUpgrade)
    {
        shouldUpgrade = false;

        if (VerifyPbkdf2(password, user.PasswordHash))
        {
            return true;
        }

        if (IsSha256Hex(user.PasswordHash) && string.Equals(user.PasswordHash, Sha256Hex(password), StringComparison.OrdinalIgnoreCase))
        {
            shouldUpgrade = true;
            return true;
        }

        if (!string.IsNullOrEmpty(user.Password) && string.Equals(user.Password, password, StringComparison.Ordinal))
        {
            shouldUpgrade = true;
            return true;
        }

        return false;
    }

    private static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            KeySize);

        return $"{CurrentPasswordScheme}${Pbkdf2Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(key)}";
    }

    private static bool VerifyPbkdf2(string password, string storedHash)
    {
        var parts = storedHash.Split('$');
        if (parts.Length != 4 ||
            !string.Equals(parts[0], CurrentPasswordScheme, StringComparison.Ordinal) ||
            !int.TryParse(parts[1], out var iterations))
        {
            return false;
        }

        try
        {
            var salt = Convert.FromBase64String(parts[2]);
            var expected = Convert.FromBase64String(parts[3]);
            var actual = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expected.Length);

            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSha256Hex(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);

    private static string Sha256Hex(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ResolvePath(string contentRoot, string path) =>
        Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(contentRoot, path));

    private static UserEntity Clone(UserEntity user) => new()
    {
        Id = user.Id,
        Username = user.Username,
        Password = string.Empty,
        PasswordHash = string.Empty,
        Email = user.Email,
        DisplayName = user.DisplayName,
        Role = user.Role,
        Provider = user.Provider,
        ProviderSubject = user.ProviderSubject,
        CreatedAt = user.CreatedAt,
        LastLoginAt = user.LastLoginAt,
    };

    private static string? ReadString(SqliteDataReader reader, string columnName)
    {
        for (var i = 0; i < reader.FieldCount; i++)
        {
            if (!string.Equals(reader.GetName(i), columnName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return reader.IsDBNull(i) ? null : Convert.ToString(reader.GetValue(i), CultureInfo.InvariantCulture);
        }

        return null;
    }

    private static DateTime? ReadDateTime(SqliteDataReader reader, string columnName)
    {
        var raw = ReadString(reader, columnName);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        if (DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            return parsed;
        }

        return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ticks)
            ? new DateTime(ticks, DateTimeKind.Utc)
            : null;
    }

    private sealed class UserStoreDocument
    {
        public int Version { get; set; } = 1;
        public List<UserEntity> Users { get; set; } = [];
    }
}
