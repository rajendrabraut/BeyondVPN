using System;
using System.Globalization;
using System.IO;
using System.Text;

namespace VpnCore.Logging
{
    public sealed class FileLogger
    {
        private readonly object _lock = new object();
        private readonly string _path;
        private readonly string _component;

        public FileLogger(string logDirectory, string component)
        {
            Directory.CreateDirectory(logDirectory);
            _component = component;
            var date = DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
            _path = Path.Combine(logDirectory, $"{component}-{date}.log");
        }

        public void Info(string message) => Write("INFO", message);
        public void Warn(string message) => Write("WARN", message);
        public void Error(string message) => Write("ERROR", message);
        public void Error(Exception ex, string message) => Write("ERROR", $"{message} :: {ex}");

        private void Write(string level, string message)
        {
            var line = $"{DateTime.UtcNow:O} [{_component}] {level} {message}";
            lock (_lock)
            {
                File.AppendAllText(_path, line + Environment.NewLine, Encoding.UTF8);
            }
        }
    }
}
