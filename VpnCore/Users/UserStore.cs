using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VpnCore.Crypto;

namespace VpnCore.Users
{
    public sealed class UserStore
    {
        private readonly string _path;

        public UserStore(string path)
        {
            _path = path;
        }

        public UserDatabase Load(string masterPassword)
        {
            if (!File.Exists(_path))
            {
                return new UserDatabase();
            }

            var encrypted = File.ReadAllBytes(_path);
            var payload = DecryptPayload(encrypted, masterPassword);
            return JsonSerializer.Deserialize<UserDatabase>(payload) ?? new UserDatabase();
        }

        public void Save(UserDatabase database, string masterPassword)
        {
            var payload = JsonSerializer.Serialize(database, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            var encrypted = EncryptPayload(Encoding.UTF8.GetBytes(payload), masterPassword, database);
            Directory.CreateDirectory(Path.GetDirectoryName(_path) ?? ".");
            File.WriteAllBytes(_path, encrypted);
        }

        public UserRecord CreateUser(UserDatabase database, string username, string password, bool isAdmin)
        {
            if (database.Users.Any(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("User already exists.");
            }

            var salt = RandomBytes(16);
            var hash = HashPassword(password, salt, database.Iterations);
            var record = new UserRecord
            {
                Username = username,
                PasswordHash = Convert.ToBase64String(hash),
                Salt = Convert.ToBase64String(salt),
                IsAdmin = isAdmin
            };
            database.Users.Add(record);
            return record;
        }

        public bool ValidateUser(UserDatabase database, string username, string password)
        {
            var user = database.Users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
            if (user == null || !user.Enabled)
            {
                return false;
            }

            var salt = Convert.FromBase64String(user.Salt);
            var hash = HashPassword(password, salt, database.Iterations);
            var expected = Convert.FromBase64String(user.PasswordHash);
            return CryptographicOperations.FixedTimeEquals(hash, expected);
        }

        private static byte[] HashPassword(string password, byte[] salt, int iterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        private static byte[] EncryptPayload(byte[] payload, string masterPassword, UserDatabase database)
        {
            if (string.IsNullOrWhiteSpace(database.KdfSalt))
            {
                database.KdfSalt = Convert.ToBase64String(RandomBytes(16));
            }

            var salt = Convert.FromBase64String(database.KdfSalt);
            var key = DeriveKey(masterPassword, salt, database.Iterations);
            var aead = new Aead(key);
            var nonce = RandomNonce();
            var ciphertext = aead.Encrypt(nonce, payload, Array.Empty<byte>());
            var output = new byte[1 + 8 + salt.Length + ciphertext.Length];
            output[0] = 1;
            Array.Copy(BitConverter.GetBytes(nonce), 0, output, 1, 8);
            Array.Copy(salt, 0, output, 9, salt.Length);
            Array.Copy(ciphertext, 0, output, 9 + salt.Length, ciphertext.Length);
            return output;
        }

        private static byte[] DecryptPayload(byte[] encrypted, string masterPassword)
        {
            if (encrypted.Length < 1 + 8 + 16)
            {
                throw new InvalidOperationException("Corrupt user store.");
            }

            var version = encrypted[0];
            if (version != 1)
            {
                throw new InvalidOperationException("Unsupported user store version.");
            }

            var nonce = BitConverter.ToUInt64(encrypted, 1);
            var salt = new byte[16];
            Array.Copy(encrypted, 9, salt, 0, 16);
            var ciphertext = new byte[encrypted.Length - 25];
            Array.Copy(encrypted, 25, ciphertext, 0, ciphertext.Length);
            var key = DeriveKey(masterPassword, salt, 200_000);
            var aead = new Aead(key);
            var plaintext = aead.Decrypt(nonce, ciphertext, Array.Empty<byte>());
            return plaintext;
        }

        private static byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(32);
            }
        }

        private static byte[] RandomBytes(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        private static ulong RandomNonce()
        {
            var buffer = RandomBytes(8);
            return BitConverter.ToUInt64(buffer, 0);
        }
    }
}
