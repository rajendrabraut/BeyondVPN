using System;
using System.Collections.Generic;

namespace VpnCore.Users
{
    public sealed class UserRecord
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Salt { get; set; } = string.Empty;
        public bool IsAdmin { get; set; }
        public bool Enabled { get; set; } = true;
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    }

    public sealed class UserDatabase
    {
        public List<UserRecord> Users { get; set; } = new List<UserRecord>();
        public int Iterations { get; set; } = 200_000;
        public string KdfSalt { get; set; } = string.Empty;
    }
}
