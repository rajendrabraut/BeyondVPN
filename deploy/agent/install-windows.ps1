# Installs beyond-agent as a native Windows service (run in an elevated PowerShell).
# Prerequisite: WireGuard for Windows (https://www.wireguard.com/install/) — provides WireGuard-NT.
#
# The service runs as LocalSystem. Its state lives in %ProgramData%\BeyondVPN and is locked down by
# the agent itself: SYSTEM + Administrators only, agent.token additionally readable by signed-in
# users (the desktop app needs it); the device key and API tokens are DPAPI-encrypted.
param(
    [string]$Binary = ".\beyond-agent.exe",
    [int]$Port = 47800
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
if (-not (Test-Path "$env:ProgramFiles\WireGuard\wireguard.exe")) {
    throw "WireGuard for Windows is not installed. Install it first."
}
$dest = "$env:ProgramFiles\BeyondVPN"
$exe = "$dest\beyond-agent.exe"
if (Get-Service BeyondVPNAgent -ErrorAction SilentlyContinue) { & $exe service uninstall }
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item $Binary $exe -Force
# Program Files is only writable by administrators, so users cannot swap the SYSTEM service binary.
& $exe service install --port $Port
if ($LASTEXITCODE -ne 0) { throw "service install failed" }
# Older installers set a machine-wide BEYOND_AGENT_DIR; the desktop app now finds the service's state itself.
[Environment]::SetEnvironmentVariable("BEYOND_AGENT_DIR", $null, "Machine")
Get-Service BeyondVPNAgent | Format-Table Name, Status, StartType -AutoSize
