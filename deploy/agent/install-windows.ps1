# Installs beyond-agent as a Windows service (run in an elevated PowerShell).
# Prerequisite: WireGuard for Windows (https://www.wireguard.com/install/) — provides WireGuard-NT.
param(
    [string]$Binary = ".\beyond-agent.exe",
    [string]$StateDir = "$env:ProgramData\BeyondVPN"
)
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
if (-not (Test-Path "$env:ProgramFiles\WireGuard\wireguard.exe")) {
    throw "WireGuard for Windows is not installed. Install it first."
}
$dest = "$env:ProgramFiles\BeyondVPN"
New-Item -ItemType Directory -Force $dest, $StateDir | Out-Null
Copy-Item $Binary "$dest\beyond-agent.exe" -Force

# State dir: SYSTEM + Administrators full, Users read (needed for the UI to read agent.token).
icacls $StateDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)R" | Out-Null

[Environment]::SetEnvironmentVariable("BEYOND_AGENT_DIR", $StateDir, "Machine")
if (Get-Service BeyondVPNAgent -ErrorAction SilentlyContinue) { sc.exe stop BeyondVPNAgent | Out-Null; sc.exe delete BeyondVPNAgent | Out-Null; Start-Sleep 2 }
# The agent binary is a console program; use a service wrapper such as WinSW or NSSM in production.
sc.exe create BeyondVPNAgent binPath= "`"$dest\beyond-agent.exe`" serve --port 47800" start= auto DisplayName= "Beyond VPN Agent" | Out-Null
sc.exe description BeyondVPNAgent "Beyond VPN tunnel manager (local API on 127.0.0.1:47800)" | Out-Null
sc.exe failure BeyondVPNAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Write-Host "Installed. Start with: sc.exe start BeyondVPNAgent (see REMAINING.md: native Windows service wrapper)."
