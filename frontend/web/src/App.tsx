import { FormEvent, useEffect, useMemo, useState } from 'react';
import axios from 'axios';

declare global {
  interface Window {
    vpn?: {
      connect: (serverId: string) => Promise<{ ok: boolean; error?: string; protocol?: string }>;
      disconnect: (serverId: string) => Promise<{ ok: boolean; error?: string }>;
      status: () => Promise<{
        publicNetwork: {
          ip: string;
          city: string;
          region: string;
          country: string;
          org: string;
        };
      dnsServers: string[];
      activeTunnels: string[];
      tunnelCount: number;
      tunnelMode: string;
      capabilities: {
        openVpnInstalled: boolean;
        wireGuardInstalled: boolean;
      };
      }>;
    };
  }
}

type Server = {
  id: string;
  name: string;
  country: string;
  type: string;
  latencyMs: number;
  isFree: boolean;
  source?: string;
};

type User = {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: string;
  provider: string;
  createdAt?: string;
  lastLoginAt?: string;
};

type Provider = {
  id: string;
  name: string;
  enabled: boolean;
  clientId: string;
  note: string;
};

type VpnSource = {
  id: string;
  name: string;
  country: string;
  protocol: 'openvpn' | 'wireguard';
  latencyMs: number;
  source: string;
  isFree: boolean;
  path?: string;
  url?: string;
};

type NetworkTelemetry = {
  publicNetwork: {
    ip: string;
    city: string;
    region: string;
    country: string;
    org: string;
  };
  dnsServers: string[];
  activeTunnels: string[];
  tunnelCount: number;
  tunnelMode: string;
  capabilities: {
    openVpnInstalled: boolean;
    wireGuardInstalled: boolean;
  };
};

const API = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5000/api';
const http = axios.create({ baseURL: API });

const DEFAULT_FORM = {
  username: 'demo',
  password: 'demo',
  email: '',
  displayName: '',
};

const DEFAULT_SOURCE_FORM: VpnSource = {
  id: '',
  name: '',
  country: 'Custom',
  protocol: 'wireguard',
  latencyMs: 40,
  source: 'Admin',
  isFree: true,
  path: '',
  url: '',
};

export default function App() {
  const [token, setToken] = useState('');
  const [providers, setProviders] = useState<Provider[]>([]);
  const [backendHealthy, setBackendHealthy] = useState(false);
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [form, setForm] = useState(DEFAULT_FORM);
  const [message, setMessage] = useState('Bring the control plane online.');
  const [user, setUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [selected, setSelected] = useState<Server | null>(null);
  const [status, setStatus] = useState('Idle');
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<'all' | 'openvpn' | 'wireguard'>('all');
  const [submitting, setSubmitting] = useState(false);
  const [busyServerId, setBusyServerId] = useState('');
  const [reloadingData, setReloadingData] = useState(false);
  const [networkTelemetry, setNetworkTelemetry] = useState<NetworkTelemetry | null>(null);
  const [baselineTelemetry, setBaselineTelemetry] = useState<NetworkTelemetry | null>(null);
  const [vpnSources, setVpnSources] = useState<VpnSource[]>([]);
  const [sourceForm, setSourceForm] = useState<VpnSource>(DEFAULT_SOURCE_FORM);
  const [sourceBusy, setSourceBusy] = useState(false);

  const authHeaders = useMemo(
    () => (token ? { Authorization: `Bearer ${token}` } : undefined),
    [token]
  );

  const isDesktopTunnelMode = Boolean(window.vpn);
  const isConnected = status.toLowerCase().startsWith('connected');
  const canConnect = Boolean(selected) && !busyServerId;
  const canDisconnect = Boolean(selected) && !busyServerId && isDesktopTunnelMode && isConnected;

  useEffect(() => {
    const boot = async () => {
      try {
        await http.get('/health');
        setBackendHealthy(true);
      } catch {
        setBackendHealthy(false);
        setMessage('Backend is offline. Start the .NET API on port 5000 first.');
      }

      try {
        const response = await http.get('/oauth/providers');
        setProviders(response.data.providers ?? []);
      } catch {
        setProviders([]);
      }
    };

    boot();
  }, []);

  useEffect(() => {
    if (!window.vpn?.status) {
      setNetworkTelemetry(null);
      return;
    }

    let alive = true;

    const refreshTelemetry = async () => {
      try {
        const nextTelemetry = await window.vpn.status();
        if (alive) {
          setNetworkTelemetry(nextTelemetry);
          if (!baselineTelemetry && nextTelemetry.tunnelCount === 0) {
            setBaselineTelemetry(nextTelemetry);
          }
        }
      } catch {
        if (alive) {
          setNetworkTelemetry(null);
        }
      }
    };

    refreshTelemetry();
    const interval = window.setInterval(refreshTelemetry, 15000);

    return () => {
      alive = false;
      window.clearInterval(interval);
    };
  }, [token, status, baselineTelemetry]);

  const ipChanged = Boolean(
    networkTelemetry &&
    baselineTelemetry &&
    networkTelemetry.publicNetwork.ip !== 'Unknown' &&
    baselineTelemetry.publicNetwork.ip !== 'Unknown' &&
    networkTelemetry.publicNetwork.ip !== baselineTelemetry.publicNetwork.ip
  );

  const dnsChanged = Boolean(
    networkTelemetry &&
    baselineTelemetry &&
    JSON.stringify(networkTelemetry.dnsServers) !== JSON.stringify(baselineTelemetry.dnsServers)
  );

  const loadDashboard = async (showReloadState = false) => {
    if (!token) {
      return;
    }

    if (showReloadState) {
      setReloadingData(true);
    }

    try {
      const [meResponse, serversResponse] = await Promise.all([
        http.get('/me', { headers: authHeaders }),
        http.get('/servers'),
      ]);

      const nextServers = serversResponse.data as Server[];
      setUser(meResponse.data);
      setServers(nextServers);
      setSelected((current) => {
        if (current) {
          return nextServers.find((entry) => entry.id === current.id) ?? nextServers[0] ?? null;
        }

        return nextServers[0] ?? null;
      });
      setMessage('User session synchronized with backend.');

      if (meResponse.data.role === 'Admin') {
        const [usersResponse, sourcesResponse] = await Promise.all([
          http.get('/users', { headers: authHeaders }),
          http.get('/vpn/sources', { headers: authHeaders }),
        ]);
        setUsers(usersResponse.data);
        setVpnSources(sourcesResponse.data.sources ?? []);
      } else {
        setUsers([]);
        setVpnSources([]);
      }
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Unable to load dashboard data.');
    } finally {
      setReloadingData(false);
    }
  };

  useEffect(() => {
    if (!token) {
      return;
    }

    loadDashboard();
  }, [token, authHeaders]);

  const filteredServers = servers.filter((server) => {
    const q = search.toLowerCase();
    const protocolMatch = protocolFilter === 'all' || server.type === protocolFilter;
    const searchMatch =
      server.name.toLowerCase().includes(q) ||
      server.country.toLowerCase().includes(q) ||
      server.type.toLowerCase().includes(q);

    return protocolMatch && searchMatch;
  });

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setMessage(mode === 'register' ? 'Creating user record...' : 'Authenticating session...');

    try {
      const endpoint = mode === 'register' ? '/register' : '/auth';
      const payload =
        mode === 'register'
          ? {
              username: form.username,
              password: form.password,
              email: form.email,
              displayName: form.displayName,
            }
          : {
              username: form.username,
              password: form.password,
            };

      const response = await http.post(endpoint, payload);
      setToken(response.data.token);
      setUser(response.data.user);
      setMode('login');
      setMessage(mode === 'register' ? 'Registration completed.' : 'Authentication successful.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Authentication failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleConnect = async () => {
    if (!selected) {
      return;
    }

    setBusyServerId(selected.id);
    setStatus('Preparing tunnel');

    try {
      if (window.vpn) {
        const result = await window.vpn.connect(selected.id);
        if (!result.ok) {
          throw new Error(result.error || 'Desktop tunnel failed.');
        }

        setStatus(`Connected via ${result.protocol || selected.type}`);
        setMessage('Desktop tunnel created through the Electron bridge. Verifying public IP and DNS state...');
      } else {
        await http.get(`/config/${selected.id}`);
        window.open(`${API}/config/${selected.id}/raw`, '_blank', 'noopener,noreferrer');
        setStatus(`Profile ready for ${selected.type}`);
        setMessage('Browser client opened the profile supplied by the backend. Browser mode cannot change your real machine IP or DNS.');
      }
    } catch (error: any) {
      setStatus('Connection failed');
      setMessage(error?.message || 'Unable to prepare tunnel.');
    } finally {
      setBusyServerId('');
    }
  };

  const handleDisconnect = async () => {
    if (!selected) {
      return;
    }

    if (!window.vpn) {
      setStatus('Browser mode');
      setMessage('Browser mode does not own the tunnel process, so disconnect is desktop-only.');
      return;
    }

    setBusyServerId(selected.id);
    try {
      const result = await window.vpn.disconnect(selected.id);
      if (!result.ok) {
        throw new Error(result.error || 'Disconnect failed.');
      }

      setStatus('Disconnected');
      setMessage('Desktop tunnel stopped.');
    } catch (error: any) {
      setMessage(error?.message || 'Disconnect failed.');
    } finally {
      setBusyServerId('');
    }
  };

  const updateRole = async (targetId: string, role: string) => {
    try {
      await http.post(`/users/${targetId}/role`, { role }, { headers: authHeaders });
      setUsers((current) => current.map((entry) => (entry.id === targetId ? { ...entry, role } : entry)));
      setMessage('User role updated.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Role update failed.');
    }
  };

  const saveVpnSource = async (event: FormEvent) => {
    event.preventDefault();
    setSourceBusy(true);
    setMessage('Saving VPN source in backend manifest...');

    try {
      const payload = {
        ...sourceForm,
        id: sourceForm.id || `${sourceForm.protocol}-${Date.now()}`,
        path: sourceForm.path?.trim() || null,
        url: sourceForm.url?.trim() || null,
      };

      const response = await http.post('/vpn/sources', payload, { headers: authHeaders });
      setVpnSources(response.data.sourceManifest?.sources ?? []);
      await loadDashboard(true);
      setSourceForm(DEFAULT_SOURCE_FORM);
      setMessage('VPN source saved and backend route inventory refreshed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source save failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  const removeVpnSource = async (id: string) => {
    setSourceBusy(true);
    setMessage(`Removing VPN source ${id}...`);

    try {
      const response = await http.delete(`/vpn/sources/${id}`, { headers: authHeaders });
      setVpnSources(response.data.sourceManifest?.sources ?? []);
      await loadDashboard(true);
      setMessage('VPN source removed and backend inventory refreshed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source removal failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  const refreshBackendSources = async () => {
    setSourceBusy(true);
    setMessage('Refreshing backend VPN sources through Python collector...');

    try {
      await http.post('/servers/refresh', {}, { headers: authHeaders });
      await loadDashboard(true);
      setMessage('Backend VPN sources refreshed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source refresh failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  const handleOAuthClick = (provider: Provider) => {
    if (!provider.enabled) {
      setMessage(`${provider.name} OAuth is not enabled yet. ${provider.note}`);
      return;
    }

    setMessage(`${provider.name} OAuth is configured on the backend. Frontend redirect flow is the next step once credentials are finalized.`);
  };

  const signOut = () => {
    setToken('');
    setUser(null);
    setUsers([]);
    setVpnSources([]);
    setServers([]);
    setSelected(null);
    setStatus('Idle');
    setMessage('Session ended.');
  };

  const clearSearch = () => {
    setSearch('');
    setProtocolFilter('all');
    setMessage('Server filters cleared.');
  };

  const pickFastestServer = () => {
    if (!filteredServers.length) {
      setMessage('No servers are available for the current filters.');
      return;
    }

    const fastest = [...filteredServers].sort((a, b) => a.latencyMs - b.latencyMs)[0];
    setSelected(fastest);
    setMessage(`Fastest route selected: ${fastest.name}.`);
  };

  const pickRecommendedServer = () => {
    if (!servers.length) {
      setMessage('Server inventory is still loading.');
      return;
    }

    const recommended =
      servers.find((server) => server.type === 'wireguard') ??
      [...servers].sort((a, b) => a.latencyMs - b.latencyMs)[0];

    setSelected(recommended);
    setMessage(`Recommended route selected: ${recommended.name}.`);
  };

  if (!token) {
    return (
      <main className="auth-shell">
        <section className="auth-panel">
          <div className="eyebrow">FortiClone Control Plane</div>
          <h1>Operate access, registration, and VPN delivery from one surface.</h1>
          <p className="lede">
            Backend health, registration, and OAuth capability are exposed directly from the API
            now, so the frontend is no longer running as a mock shell.
          </p>
          <div className="health-row">
            <span className={backendHealthy ? 'health-badge live' : 'health-badge down'}>
              {backendHealthy ? 'Backend online' : 'Backend offline'}
            </span>
            <span className="muted">REST `5000` / gRPC `5001`</span>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="mode-row">
              <button type="button" className={mode === 'login' ? 'mode active' : 'mode'} onClick={() => setMode('login')}>
                Login
              </button>
              <button type="button" className={mode === 'register' ? 'mode active' : 'mode'} onClick={() => setMode('register')}>
                Register
              </button>
            </div>

            <label>
              Username
              <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </label>
            <label>
              Password
              <input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </label>

            {mode === 'register' && (
              <>
                <label>
                  Display name
                  <input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
                </label>
                <label>
                  Email
                  <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
                </label>
              </>
            )}

            <button className="primary" disabled={submitting || !backendHealthy}>
              {submitting ? 'Working...' : mode === 'register' ? 'Create account' : 'Enter console'}
            </button>
          </form>

          <div className="oauth-block">
            <div className="section-kicker">OAuth</div>
            {providers.map((provider) => (
              <button key={provider.id} type="button" className="oauth-button" onClick={() => handleOAuthClick(provider)}>
                Continue with {provider.name}
                <span>{provider.enabled ? 'Client configured' : provider.note}</span>
              </button>
            ))}
          </div>

          <p className="status-copy">{message}</p>
        </section>
      </main>
    );
  }

  return (
    <main className="dashboard">
      <aside className="left-rail">
        <div className="session-card">
          <div className="eyebrow">Session</div>
          <h2>{user?.displayName || user?.username}</h2>
          <p className="muted">{user?.email || 'Local account'}</p>
          <div className="chip-row">
            <span className="chip">{user?.role}</span>
            <span className="chip subdued">{user?.provider}</span>
          </div>
          <button type="button" className="secondary rail-action" onClick={signOut}>
            Sign out
          </button>
        </div>

        <div className="search-card">
          <div className="section-kicker">Route Catalog</div>
          <label>
            Server search
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="country, name, protocol" />
          </label>
          <div className="filter-row">
            <button type="button" className={protocolFilter === 'all' ? 'mode active compact' : 'mode compact'} onClick={() => setProtocolFilter('all')}>
              All
            </button>
            <button type="button" className={protocolFilter === 'openvpn' ? 'mode active compact' : 'mode compact'} onClick={() => setProtocolFilter('openvpn')}>
              OpenVPN
            </button>
            <button type="button" className={protocolFilter === 'wireguard' ? 'mode active compact' : 'mode compact'} onClick={() => setProtocolFilter('wireguard')}>
              WireGuard
            </button>
          </div>
          <div className="search-actions">
            <button type="button" className="secondary compact-action" onClick={() => loadDashboard(true)} disabled={reloadingData}>
              {reloadingData ? 'Refreshing...' : 'Refresh data'}
            </button>
            <button type="button" className="secondary compact-action" onClick={clearSearch}>
              Clear
            </button>
          </div>
          <div className="search-actions">
            <button type="button" className="secondary compact-action" onClick={pickFastestServer}>
              Fastest route
            </button>
            <button type="button" className="secondary compact-action" onClick={pickRecommendedServer}>
              Recommended
            </button>
          </div>
        </div>

        <div className="server-list">
          {filteredServers.map((server) => (
            <button
              key={server.id}
              type="button"
              className={selected?.id === server.id ? 'server-card active' : 'server-card'}
              onClick={() => setSelected(server)}
            >
              <div>
                <strong>{server.name}</strong>
                <span>{server.country}</span>
              </div>
              <div className="server-meta">
                <span>{server.type}</span>
                <span>{server.latencyMs} ms</span>
              </div>
              <div className="server-submeta">{server.source || 'source unknown'}</div>
            </button>
          ))}
        </div>
      </aside>

      <section className="main-panel">
        <div className="status-banner">
          <div>
            <div className="section-kicker">Live Status</div>
            <strong>{status}</strong>
          </div>
          <p>{message}</p>
        </div>

        <div className="metrics-grid telemetry-grid">
          <article className="metric-card">
            <span className="section-kicker">Public IP</span>
            <strong>{networkTelemetry?.publicNetwork.ip || 'Browser-owned'}</strong>
            <p>
              {networkTelemetry
                ? [networkTelemetry.publicNetwork.city, networkTelemetry.publicNetwork.region, networkTelemetry.publicNetwork.country].filter(Boolean).join(', ') || 'Location unavailable'
                : 'The browser shell cannot change your actual public IP. Use the desktop or Android client for real tunneling.'}
            </p>
            {networkTelemetry && baselineTelemetry && (
              <div className={ipChanged ? 'proof-badge changed' : 'proof-badge unchanged'}>
                {ipChanged ? 'IP changed after tunnel' : 'IP unchanged from baseline'}
              </div>
            )}
          </article>
          <article className="metric-card">
            <span className="section-kicker">DNS</span>
            <strong>{networkTelemetry?.dnsServers[0] || 'Unchanged'}</strong>
            <p>
              {networkTelemetry
                ? `${networkTelemetry.dnsServers.length} configured resolver(s): ${networkTelemetry.dnsServers.join(', ')}`
                : 'Browser mode keeps the host machine DNS exactly as it is.'}
            </p>
            {networkTelemetry && baselineTelemetry && (
              <div className={dnsChanged ? 'proof-badge changed' : 'proof-badge unchanged'}>
                {dnsChanged ? 'DNS changed after tunnel' : 'DNS unchanged from baseline'}
              </div>
            )}
          </article>
          <article className="metric-card">
            <span className="section-kicker">Tunnel Reality</span>
            <strong>{networkTelemetry?.tunnelCount ? `${networkTelemetry.tunnelCount} active` : isDesktopTunnelMode ? 'No active tunnel' : 'Profile-only mode'}</strong>
            <p>
              {isDesktopTunnelMode
                ? 'Desktop mode can verify actual tunnel ownership and host networking state.'
                : 'Web mode can prepare a route profile, but it cannot alter system routing or DNS on its own.'}
            </p>
            {networkTelemetry?.capabilities && (
              <div className="capability-stack">
                <div className={networkTelemetry.capabilities.openVpnInstalled ? 'proof-badge changed' : 'proof-badge unchanged'}>
                  {networkTelemetry.capabilities.openVpnInstalled ? 'OpenVPN installed' : 'OpenVPN missing'}
                </div>
                <div className={networkTelemetry.capabilities.wireGuardInstalled ? 'proof-badge changed' : 'proof-badge unchanged'}>
                  {networkTelemetry.capabilities.wireGuardInstalled ? 'WireGuard installed' : 'WireGuard missing'}
                </div>
              </div>
            )}
          </article>
        </div>

        <div className="hero-card">
          <div className="hero-copy">
            <div className="section-kicker">Secure Routing</div>
            <h1>{selected?.name || 'Choose a server'}</h1>
            <p>{selected ? `${selected.country} / ${selected.type} / ${selected.latencyMs} ms` : 'Select an exit node from the left rail.'}</p>
            <div className="hero-meta">
              <span className="chip">{selected?.country || 'No region'}</span>
              <span className="chip subdued">{selected?.type || 'No protocol'}</span>
              <span className="chip subdued">{selected?.source || 'No source'}</span>
            </div>
            <div className="hero-grid">
              <div className="hero-mini-card">
                <span className="section-kicker">Protection</span>
                <strong>{isConnected ? 'Tunnel active' : 'Standby'}</strong>
                <p>{isDesktopTunnelMode ? 'Desktop shell can own tunnel state directly.' : 'Browser shell prepares secure profiles for the native client.'}</p>
              </div>
              <div className="hero-mini-card">
                <span className="section-kicker">Policy</span>
                <strong>{backendHealthy ? 'Compliant' : 'Awaiting backend'}</strong>
                <p>Unified agent posture, identity, and routing state are being surfaced in one console.</p>
              </div>
            </div>
          </div>

          <div className="hero-actions">
            <button className="primary" onClick={handleConnect} disabled={!canConnect}>
              {busyServerId ? 'Working...' : isDesktopTunnelMode ? 'Connect tunnel' : 'Download profile'}
            </button>
            <button className="secondary" onClick={handleDisconnect} disabled={!canDisconnect}>
              Disconnect
            </button>
            <button className="secondary" onClick={() => loadDashboard(true)} disabled={reloadingData}>
              Sync
            </button>
          </div>
        </div>

        <div className="metrics-grid">
          <article className="metric-card">
            <span className="section-kicker">Backend</span>
            <strong>{backendHealthy ? 'Healthy' : 'Offline'}</strong>
            <p>API health, auth, and user data are being read from the live .NET service.</p>
          </article>
          <article className="metric-card">
            <span className="section-kicker">Connection</span>
            <strong>{status}</strong>
            <p>{isDesktopTunnelMode ? 'Desktop mode can create and stop tunnel processes.' : 'Browser mode prepares profiles and opens the backend config.'}</p>
          </article>
          <article className="metric-card">
            <span className="section-kicker">Fleet</span>
            <strong>{servers.length} nodes</strong>
            <p>Filters, refresh, and selection now all drive real state changes.</p>
          </article>
        </div>

        <div className="management-card">
          <div className="management-head">
            <div>
              <div className="section-kicker">User Management</div>
              <h3>Identity records and roles</h3>
            </div>
          </div>

          {user?.role !== 'Admin' ? (
            <p className="muted">Admin access is required to manage other users.</p>
          ) : (
            <div className="user-table">
              {users.map((entry) => (
                <div key={entry.id} className="user-row">
                  <div>
                    <strong>{entry.displayName || entry.username}</strong>
                    <span>{entry.email || entry.username}</span>
                  </div>
                  <div className="user-row-meta">
                    <span>{entry.provider}</span>
                    <span>{entry.lastLoginAt ? new Date(entry.lastLoginAt).toLocaleString() : 'No login yet'}</span>
                  </div>
                  <select value={entry.role} onChange={(e) => updateRole(entry.id, e.target.value)}>
                    <option value="Admin">Admin</option>
                    <option value="User">User</option>
                  </select>
                </div>
              ))}
            </div>
          )}
        </div>

        {user?.role === 'Admin' && (
          <div className="management-card">
            <div className="management-head">
              <div>
                <div className="section-kicker">VPN Source Control</div>
                <h3>OpenVPN and WireGuard backend configuration</h3>
              </div>
              <button type="button" className="secondary" onClick={refreshBackendSources} disabled={sourceBusy}>
                {sourceBusy ? 'Working...' : 'Refresh collector'}
              </button>
            </div>

            <form className="source-form" onSubmit={saveVpnSource}>
              <label>
                Source id
                <input value={sourceForm.id} onChange={(e) => setSourceForm({ ...sourceForm, id: e.target.value })} placeholder="my-wireguard-node" />
              </label>
              <label>
                Display name
                <input value={sourceForm.name} onChange={(e) => setSourceForm({ ...sourceForm, name: e.target.value })} placeholder="WireGuard Singapore" />
              </label>
              <label>
                Country
                <input value={sourceForm.country} onChange={(e) => setSourceForm({ ...sourceForm, country: e.target.value })} />
              </label>
              <label>
                Protocol
                <select value={sourceForm.protocol} onChange={(e) => setSourceForm({ ...sourceForm, protocol: e.target.value as VpnSource['protocol'] })}>
                  <option value="wireguard">WireGuard</option>
                  <option value="openvpn">OpenVPN</option>
                </select>
              </label>
              <label>
                Latency estimate
                <input
                  type="number"
                  min="1"
                  value={sourceForm.latencyMs}
                  onChange={(e) => setSourceForm({ ...sourceForm, latencyMs: Number(e.target.value) || 999 })}
                />
              </label>
              <label>
                Local config path
                <input value={sourceForm.path ?? ''} onChange={(e) => setSourceForm({ ...sourceForm, path: e.target.value })} placeholder="samples/wireguard-sample.conf" />
              </label>
              <label>
                Remote config URL
                <input value={sourceForm.url ?? ''} onChange={(e) => setSourceForm({ ...sourceForm, url: e.target.value })} placeholder="https://example.com/profile.conf" />
              </label>
              <button type="submit" className="primary" disabled={sourceBusy}>
                Save VPN source
              </button>
            </form>

            <div className="source-grid">
              {vpnSources.map((source) => (
                <div key={source.id} className="source-row">
                  <div>
                    <strong>{source.name}</strong>
                    <span>{source.id}</span>
                  </div>
                  <div className="user-row-meta">
                    <span>{source.protocol} / {source.country}</span>
                    <span>{source.path || source.url || 'No config location'}</span>
                  </div>
                  <button type="button" className="secondary danger-action" onClick={() => removeVpnSource(source.id)} disabled={sourceBusy}>
                    Remove
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
