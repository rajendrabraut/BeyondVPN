const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const { execFile } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const axios = require('axios');

const API = 'http://localhost:5000';
const activeTunnels = new Map();

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#081018',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
    },
  });

  win.loadURL('http://localhost:5173');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

function guessProtocol(config) {
  const normalized = String(config || '').toLowerCase();
  if (normalized.includes('[interface]') || normalized.includes('privatekey')) {
    return 'wireguard';
  }

  if (
    normalized.includes('client') ||
    normalized.includes('<ca>') ||
    normalized.includes('proto ') ||
    normalized.includes('remote ')
  ) {
    return 'openvpn';
  }

  return 'unknown';
}

function findOpenVpnBinary() {
  const candidates = [
    'C:\\Program Files\\OpenVPN\\bin\\openvpn.exe',
  ];

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function findWireGuardBinary() {
  const candidates = [
    'C:\\Program Files\\WireGuard\\wireguard.exe',
  ];

  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function writeTempConfig(serverId, protocol, config) {
  const extension = protocol === 'wireguard' ? 'conf' : 'ovpn';
  const targetPath = path.join(os.tmpdir(), `${serverId}.${extension}`);
  fs.writeFileSync(targetPath, config, 'utf8');
  return targetPath;
}

function allocatePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

function waitForOpenVpnReady(logPath, child, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const interval = setInterval(() => {
      if (Date.now() - startedAt > timeoutMs) {
        clearInterval(interval);
        const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '';
        resolve({ ok: false, error: log.split(/\r?\n/).filter(Boolean).slice(-5).join(' | ') || 'OpenVPN timed out before the tunnel initialized.' });
        return;
      }

      if (child.exitCode !== null) {
        clearInterval(interval);
        const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, 'utf8') : '';
        resolve({ ok: false, error: log.split(/\r?\n/).filter(Boolean).slice(-5).join(' | ') || `OpenVPN exited early with code ${child.exitCode}.` });
        return;
      }

      if (fs.existsSync(logPath)) {
        const log = fs.readFileSync(logPath, 'utf8');
        if (log.includes('Initialization Sequence Completed')) {
          clearInterval(interval);
          resolve({ ok: true });
        }
      }
    }, 800);
  });
}

function sanitizeTunnelName(serverId) {
  return String(serverId || 'forticlone').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function runPowerShell(command) {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-Command', command],
      { windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr || error.message));
          return;
        }

        resolve(String(stdout || '').trim());
      }
    );
  });
}

async function readDnsServers() {
  try {
    const raw = await runPowerShell("(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notlike '*Loopback*' } | ForEach-Object { $_.ServerAddresses }) -join ','");
    return raw
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

async function readPublicNetwork() {
  try {
    const response = await axios.get('https://ipapi.co/json/', { timeout: 8000 });
    return {
      ip: response.data?.ip || 'Unknown',
      city: response.data?.city || '',
      region: response.data?.region || '',
      country: response.data?.country_name || '',
      org: response.data?.org || '',
    };
  } catch {
    return {
      ip: 'Unknown',
      city: '',
      region: '',
      country: '',
      org: '',
    };
  }
}

ipcMain.handle('vpn-connect', async (_event, serverId) => {
  try {
    const response = await axios.get(`${API}/api/config/${serverId}`);
    const payload = response.data;
    const protocol = payload.type || guessProtocol(payload.config);

    if (!payload?.config) {
      return { ok: false, error: 'Backend returned an empty VPN configuration.' };
    }

    const configPath = writeTempConfig(serverId, protocol, payload.config);

    if (protocol === 'openvpn') {
      const openVpnBinary = findOpenVpnBinary();
      if (!openVpnBinary) {
        return {
          ok: false,
          error: 'OpenVPN is required for these VPNGate profiles. Install OpenVPN on Windows and try again.',
          protocol,
          configPath,
        };
      }

      const logPath = path.join(os.tmpdir(), `${serverId}.openvpn.log`);
      const child = spawn(openVpnBinary, ['--config', configPath, '--log-append', logPath], {
        detached: false,
        stdio: 'ignore',
        windowsHide: true,
      });

      const ready = await waitForOpenVpnReady(logPath, child);
      if (!ready.ok) {
        try {
          child.kill();
        } catch {}

        return {
          ok: false,
          error: ready.error,
          protocol,
          configPath,
        };
      }

      activeTunnels.set(serverId, {
        child,
        protocol,
        configPath,
        logPath,
      });

      return { ok: true, protocol, configPath };
    }

    if (protocol === 'wireguard') {
      const wireGuardBinary = findWireGuardBinary();
      if (!wireGuardBinary) {
        return {
          ok: false,
          error: 'WireGuard is required for WireGuard profiles. Install WireGuard for Windows and try again.',
          protocol,
          configPath,
        };
      }

      const tunnelName = sanitizeTunnelName(serverId);
      const child = spawn(wireGuardBinary, ['/installtunnelservice', configPath], {
        detached: false,
        stdio: 'ignore',
        windowsHide: true,
      });

      activeTunnels.set(serverId, {
        child,
        protocol,
        configPath,
        tunnelName,
        binary: wireGuardBinary,
      });

      return { ok: true, protocol, configPath };
    }

    return {
      ok: false,
      error: 'Unsupported VPN profile returned by the backend.',
      protocol,
      configPath,
    };
  } catch (error) {
    return {
      ok: false,
      error: error?.response?.data?.error || error.message || 'Connection failed.',
    };
  }
});

ipcMain.handle('vpn-disconnect', async (_event, serverId) => {
  const tunnel = activeTunnels.get(serverId);

  if (!tunnel) {
    return { ok: false, error: 'No active VPN session found for this server.' };
  }

  try {
    if (tunnel.protocol === 'wireguard' && tunnel.binary && tunnel.tunnelName) {
      spawn(tunnel.binary, ['/uninstalltunnelservice', tunnel.tunnelName], {
        detached: false,
        stdio: 'ignore',
        windowsHide: true,
      });
    } else {
      tunnel.child.kill();
    }

    activeTunnels.delete(serverId);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message || 'Disconnect failed.' };
  }
});

ipcMain.handle('vpn-status', async () => {
  const publicNetwork = await readPublicNetwork();
  const dnsServers = await readDnsServers();
  const openVpnInstalled = Boolean(findOpenVpnBinary());
  const wireGuardInstalled = Boolean(findWireGuardBinary());

  return {
    publicNetwork,
    dnsServers,
    activeTunnels: [...activeTunnels.keys()],
    tunnelCount: activeTunnels.size,
    tunnelMode: activeTunnels.size > 0 ? 'native' : 'idle',
    capabilities: {
      openVpnInstalled,
      wireGuardInstalled,
    },
  };
});
