import { FormEvent, useEffect, useMemo, useState } from 'react';
import axios from 'axios';

declare global {
  interface Window {
    vpn?: {
      connect: (serverId: string) => Promise<{ ok: boolean; error?: string; protocol?: string }>;
      disconnect: (serverId: string) => Promise<{ ok: boolean; error?: string }>;
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

type AuthResponse = {
  token: string;
  user: User;
};

type CountryRow = {
  country: string;
  total: number;
  up: number;
  down: number;
  avgLatency: number;
  fastest: Server;
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

type VpnSourceKind = 'ovpn-file' | 'wireguard-config' | 'free-internet';

type AvailabilitySample = {
  time: string;
  up: number;
  down: number;
};

type Notice = {
  id: number;
  text: string;
  tone: 'info' | 'success' | 'danger';
};

const API = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:5000/api';
const http = axios.create({ baseURL: API });
const REMEMBER_KEY = 'beyondvpn-remembered-session';
const MAX_HISTORY_POINTS = 18;

const DEFAULT_LOGIN = {
  username: 'demo',
  password: 'demo',
};

const DEFAULT_REGISTRATION = {
  username: '',
  email: '',
  mobileNumber: '',
  firstName: '',
  middleName: '',
  lastName: '',
  gender: '',
  password: '',
  confirmPassword: '',
};

const DEFAULT_SOURCE_FORM: VpnSource = {
  id: '',
  name: '',
  country: '',
  protocol: 'openvpn',
  latencyMs: 80,
  source: 'Admin',
  isFree: true,
  path: '',
  url: '',
};

function BeyondLogo() {
  return (
    <div className="brand-lockup" aria-label="BeyondVPN">
      <div className="brand-mark">
        <span>B</span>
      </div>
      <strong>BeyondVPN</strong>
    </div>
  );
}

function makeOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function getInitialRoute() {
  return window.location.pathname === '/register' ? 'register' : 'login';
}

export default function App() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light');
  const [route, setRoute] = useState<'login' | 'register'>(getInitialRoute);
  const [token, setToken] = useState('');
  const [providers, setProviders] = useState<Provider[]>([]);
  const [backendHealthy, setBackendHealthy] = useState(false);
  const [loginForm, setLoginForm] = useState(DEFAULT_LOGIN);
  const [registerForm, setRegisterForm] = useState(DEFAULT_REGISTRATION);
  const [rememberMe, setRememberMe] = useState(true);
  const [pendingAuth, setPendingAuth] = useState<AuthResponse | null>(null);
  const [otpCode, setOtpCode] = useState('');
  const [otpInput, setOtpInput] = useState('');
  const [message, setMessage] = useState('Sign in to choose a VPN location.');
  const [notice, setNotice] = useState<Notice | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [vpnSources, setVpnSources] = useState<VpnSource[]>([]);
  const [sourceKind, setSourceKind] = useState<VpnSourceKind>('ovpn-file');
  const [sourceForm, setSourceForm] = useState<VpnSource>(DEFAULT_SOURCE_FORM);
  const [sourceBusy, setSourceBusy] = useState(false);
  const [selected, setSelected] = useState<Server | null>(null);
  const [status, setStatus] = useState('Not connected');
  const [countrySearch, setCountrySearch] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [busyServerId, setBusyServerId] = useState('');
  const [reloadingData, setReloadingData] = useState(false);
  const [availabilityHistory, setAvailabilityHistory] = useState<AvailabilitySample[]>([]);
  const [userSearch, setUserSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | 'Admin' | 'User'>('all');

  const authHeaders = useMemo(
    () => (token ? { Authorization: `Bearer ${token}` } : undefined),
    [token]
  );

  useEffect(() => {
    const handlePopState = () => setRoute(getInitialRoute());
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  useEffect(() => {
    const tone = /failed|offline|invalid|unable|error|not available/i.test(message)
      ? 'danger'
      : /verified|completed|restored|updated|saved|connected|disconnected|signed out/i.test(message)
        ? 'success'
        : 'info';
    const nextNotice = { id: Date.now(), text: message, tone } satisfies Notice;
    setNotice(nextNotice);
    const timeout = window.setTimeout(() => {
      setNotice((current) => (current?.id === nextNotice.id ? null : current));
    }, 5200);

    return () => window.clearTimeout(timeout);
  }, [message]);

  useEffect(() => {
    const savedTheme = localStorage.getItem('beyondvpn-theme');
    if (savedTheme === 'dark' || savedTheme === 'light') {
      setTheme(savedTheme);
    }

    const savedSession = localStorage.getItem(REMEMBER_KEY);
    if (savedSession) {
      try {
        const parsed = JSON.parse(savedSession) as AuthResponse;
        if (parsed.token && parsed.user) {
          setToken(parsed.token);
          setUser(parsed.user);
          setMessage('Remembered session restored.');
        }
      } catch {
        localStorage.removeItem(REMEMBER_KEY);
      }
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('beyondvpn-theme', theme);
  }, [theme]);

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

      const nextUser = meResponse.data as User;
      const nextServers = serversResponse.data as Server[];
      setUser(nextUser);
      setServers(nextServers);
      setSelected((current) => current ? nextServers.find((entry) => entry.id === current.id) ?? nextServers[0] ?? null : nextServers[0] ?? null);

      if (nextUser.role === 'Admin') {
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
    if (token) {
      loadDashboard();
    }
  }, [token, authHeaders]);

  useEffect(() => {
    if (!token) {
      return;
    }

    const interval = window.setInterval(() => {
      loadDashboard();
    }, 15000);

    return () => window.clearInterval(interval);
  }, [token, authHeaders]);

  const countryRows = useMemo<CountryRow[]>(() => {
    const grouped = new Map<string, Server[]>();
    servers.forEach((server) => {
      grouped.set(server.country, [...(grouped.get(server.country) ?? []), server]);
    });

    return [...grouped.entries()]
      .map(([country, items]) => {
        const sorted = [...items].sort((a, b) => a.latencyMs - b.latencyMs);
        const up = items.filter((server) => server.latencyMs < 800).length;
        const totalLatency = items.reduce((sum, server) => sum + server.latencyMs, 0);

        return {
          country,
          total: items.length,
          up,
          down: items.length - up,
          avgLatency: Math.round(totalLatency / items.length),
          fastest: sorted[0],
        };
      })
      .sort((a, b) => a.avgLatency - b.avgLatency);
  }, [servers]);

  const visibleCountries = countryRows.filter((entry) =>
    entry.country.toLowerCase().includes(countrySearch.trim().toLowerCase())
  );

  const availabilityTotals = useMemo(
    () => ({
      up: countryRows.reduce((sum, entry) => sum + entry.up, 0),
      down: countryRows.reduce((sum, entry) => sum + entry.down, 0),
    }),
    [countryRows]
  );
  const lineChartMax = Math.max(1, ...availabilityHistory.flatMap((entry) => [entry.up, entry.down]));
  const getLinePath = (key: 'up' | 'down') =>
    availabilityHistory
      .map((entry, index) => {
        const x = availabilityHistory.length <= 1 ? 0 : (index / (availabilityHistory.length - 1)) * 640;
        const y = 210 - (entry[key] / lineChartMax) * 170;
        return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
      })
      .join(' ');
  const isConnected = status.toLowerCase().startsWith('connected');
  const canConnect = Boolean(selected) && !busyServerId;
  const canDisconnect = Boolean(selected) && !busyServerId && Boolean(window.vpn) && isConnected;

  useEffect(() => {
    if (!token) {
      setAvailabilityHistory([]);
      return;
    }

    const addSample = () => {
      const nextSample = {
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        up: availabilityTotals.up,
        down: availabilityTotals.down,
      };
      setAvailabilityHistory((current) => [...current.slice(-(MAX_HISTORY_POINTS - 1)), nextSample]);
    };

    addSample();
    const interval = window.setInterval(addSample, 5000);
    return () => window.clearInterval(interval);
  }, [token, availabilityTotals.up, availabilityTotals.down]);

  const filteredUsers = users.filter((entry) => {
    const query = userSearch.trim().toLowerCase();
    const roleMatches = roleFilter === 'all' || entry.role === roleFilter;
    const textMatches =
      !query ||
      entry.username.toLowerCase().includes(query) ||
      entry.displayName.toLowerCase().includes(query) ||
      entry.email.toLowerCase().includes(query);

    return roleMatches && textMatches;
  });

  const completeLogin = (auth: AuthResponse) => {
    setToken(auth.token);
    setUser(auth.user);
    setPendingAuth(null);
    setOtpCode('');
    setOtpInput('');
    setStatus('Not connected');
    setMessage('Login verified. Choose a country and press Connect.');

    if (rememberMe) {
      localStorage.setItem(REMEMBER_KEY, JSON.stringify(auth));
    } else {
      localStorage.removeItem(REMEMBER_KEY);
    }
  };

  const handleLogin = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setMessage('Checking username and password...');

    try {
      const response = await http.post('/auth', loginForm);
      const nextOtp = makeOtp();
      setOtpCode(nextOtp);
      setOtpInput('');
      setPendingAuth(response.data);
      setMessage(`OTP sent to ${response.data.user.email || loginForm.username}. Demo OTP: ${nextOtp}`);
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Login failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const verifyOtp = (event: FormEvent) => {
    event.preventDefault();
    if (!pendingAuth) {
      return;
    }

    if (otpInput.trim() !== otpCode) {
      setMessage('Invalid OTP. Check the code and try again.');
      return;
    }

    completeLogin(pendingAuth);
  };

  const handleRegister = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setMessage('Creating account...');

    if (registerForm.password !== registerForm.confirmPassword) {
      setMessage('Password and confirm password must match.');
      setSubmitting(false);
      return;
    }

    const fullName = [registerForm.firstName, registerForm.middleName, registerForm.lastName]
      .filter(Boolean)
      .join(' ')
      .trim();

    try {
      await http.post('/register', {
        username: registerForm.username || registerForm.email.split('@')[0],
        password: registerForm.password,
        email: registerForm.email,
        displayName: fullName || registerForm.username,
        mobileNumber: registerForm.mobileNumber,
        firstName: registerForm.firstName,
        middleName: registerForm.middleName,
        lastName: registerForm.lastName,
        gender: registerForm.gender,
        confirmPassword: registerForm.confirmPassword,
      });
      setLoginForm({ username: registerForm.username || registerForm.email, password: '' });
      setRegisterForm(DEFAULT_REGISTRATION);
      setMessage('Registration completed. Sign in above to verify OTP.');
      navigateAuth('login');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Registration failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleConnect = async () => {
    if (!selected) {
      return;
    }

    setBusyServerId(selected.id);
    setStatus('Connecting');

    try {
      if (window.vpn) {
        const result = await window.vpn.connect(selected.id);
        if (!result.ok) {
          throw new Error(result.error || 'Desktop tunnel failed.');
        }

        setStatus(`Connected to ${selected.country}`);
        setMessage(`Connected through ${selected.name} using ${result.protocol || selected.type}.`);
      } else {
        await http.get(`/config/${selected.id}`);
        window.open(`${API}/config/${selected.id}/raw`, '_blank', 'noopener,noreferrer');
        setStatus(`Profile ready for ${selected.country}`);
        setMessage('Web mode downloaded the VPN profile. Use the native client for real system routing.');
      }
    } catch (error: any) {
      setStatus('Connection failed');
      setMessage(error?.message || 'Unable to prepare VPN connection.');
    } finally {
      setBusyServerId('');
    }
  };

  const handleDisconnect = async () => {
    if (!selected || !window.vpn) {
      setMessage('Disconnect is available in the native client where the tunnel process is owned.');
      return;
    }

    setBusyServerId(selected.id);
    try {
      const result = await window.vpn.disconnect(selected.id);
      if (!result.ok) {
        throw new Error(result.error || 'Disconnect failed.');
      }
      setStatus('Not connected');
      setMessage('VPN disconnected.');
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
      setMessage(role === 'Admin' ? 'User promoted to admin.' : 'Admin access removed from user.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Role update failed.');
    }
  };

  const signOut = () => {
    localStorage.removeItem(REMEMBER_KEY);
    setToken('');
    setUser(null);
    setUsers([]);
    setServers([]);
    setSelected(null);
    setPendingAuth(null);
    setStatus('Not connected');
    setMessage('Signed out.');
  };

  const navigateAuth = (nextRoute: 'login' | 'register') => {
    const path = nextRoute === 'register' ? '/register' : '/';
    window.history.pushState({}, '', path);
    setRoute(nextRoute);
    setPendingAuth(null);
    setOtpCode('');
    setOtpInput('');
  };

  const applySourceKind = (kind: VpnSourceKind) => {
    setSourceKind(kind);
    setSourceForm((current) => ({
      ...current,
      protocol: kind === 'wireguard-config' ? 'wireguard' : 'openvpn',
      source: kind === 'free-internet' ? 'Free internet source' : 'Admin',
      path: kind === 'free-internet' ? '' : current.path,
      url: kind === 'free-internet' ? current.url : '',
    }));
  };

  const saveVpnSource = async (event: FormEvent) => {
    event.preventDefault();
    setSourceBusy(true);
    setMessage('Saving VPN source...');

    try {
      const payload = {
        ...sourceForm,
        id: sourceForm.id || `${sourceForm.protocol}-${Date.now()}`,
        path: sourceForm.path?.trim() || null,
        url: sourceForm.url?.trim() || null,
      };
      const response = await http.post('/vpn/sources', payload, { headers: authHeaders });
      setVpnSources(response.data.sourceManifest?.sources ?? []);
      setSourceForm(DEFAULT_SOURCE_FORM);
      setSourceKind('ovpn-file');
      await loadDashboard();
      setMessage('VPN source saved and server inventory refreshed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source save failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  const removeVpnSource = async (id: string) => {
    setSourceBusy(true);
    setMessage('Removing VPN source...');

    try {
      const response = await http.delete(`/vpn/sources/${id}`, { headers: authHeaders });
      setVpnSources(response.data.sourceManifest?.sources ?? []);
      await loadDashboard();
      setMessage('VPN source removed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source removal failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  const refreshSources = async () => {
    setSourceBusy(true);
    setMessage('Refreshing free VPN sources from backend collector...');

    try {
      await http.post('/servers/refresh', {}, { headers: authHeaders });
      await loadDashboard();
      setMessage('VPN sources refreshed.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'VPN source refresh failed.');
    } finally {
      setSourceBusy(false);
    }
  };

  if (!token) {
    if (route === 'register') {
      return (
        <main className="auth-shell register-page">
          <section className="auth-card register-page-card">
            <div className="auth-top">
              <BeyondLogo />
              <div className="topbar-actions">
                <button className="theme-toggle" type="button" onClick={() => setTheme((current) => (current === 'light' ? 'dark' : 'light'))}>
                  {theme === 'light' ? 'Dark' : 'Light'}
                </button>
                <button className="secondary" type="button" onClick={() => navigateAuth('login')}>
                  Back to login
                </button>
              </div>
            </div>

            <div className="auth-title">
              <h1>Create account</h1>
              <p>Complete your profile once, then sign in and verify OTP.</p>
            </div>

            <form className="register-form standalone-register" onSubmit={handleRegister}>
              <label>
                Email
                <input type="email" value={registerForm.email} onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })} autoComplete="email" required />
              </label>
              <label>
                Mobile number
                <input value={registerForm.mobileNumber} onChange={(e) => setRegisterForm({ ...registerForm, mobileNumber: e.target.value })} autoComplete="tel" required />
              </label>
              <label>
                First name
                <input value={registerForm.firstName} onChange={(e) => setRegisterForm({ ...registerForm, firstName: e.target.value })} autoComplete="given-name" required />
              </label>
              <label>
                Middle name
                <input value={registerForm.middleName} onChange={(e) => setRegisterForm({ ...registerForm, middleName: e.target.value })} />
              </label>
              <label>
                Last name
                <input value={registerForm.lastName} onChange={(e) => setRegisterForm({ ...registerForm, lastName: e.target.value })} autoComplete="family-name" required />
              </label>
              <label>
                Gender
                <select value={registerForm.gender} onChange={(e) => setRegisterForm({ ...registerForm, gender: e.target.value })} required>
                  <option value="">Select gender</option>
                  <option value="Female">Female</option>
                  <option value="Male">Male</option>
                  <option value="Non-binary">Non-binary</option>
                  <option value="Prefer not to say">Prefer not to say</option>
                </select>
              </label>
              <label>
                Username
                <input value={registerForm.username} onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })} autoComplete="username" required />
              </label>
              <label>
                Password
                <input type="password" value={registerForm.password} onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })} autoComplete="new-password" required />
              </label>
              <label>
                Confirm password
                <input type="password" value={registerForm.confirmPassword} onChange={(e) => setRegisterForm({ ...registerForm, confirmPassword: e.target.value })} autoComplete="new-password" required />
              </label>
              <button className="primary wide" disabled={submitting || !backendHealthy}>
                {submitting ? 'Creating...' : 'Create account'}
              </button>
            </form>

            <p className={backendHealthy ? 'system-message ok' : 'system-message'}>{message}</p>
          </section>
          {notice && <Toast notice={notice} onClose={() => setNotice(null)} />}
        </main>
      );
    }

    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="auth-top">
            <BeyondLogo />
            <button
              className="theme-toggle"
              type="button"
              onClick={() => setTheme((current) => (current === 'light' ? 'dark' : 'light'))}
            >
              {theme === 'light' ? 'Dark' : 'Light'}
            </button>
          </div>

          <div className="auth-title">
            <h1>Login</h1>
            <p>Choose your account, verify OTP, then connect to a VPN country.</p>
          </div>

          <form className="login-form" onSubmit={handleLogin}>
            <label>
              Username
              <input value={loginForm.username} onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })} autoComplete="username" />
            </label>
            <label>
              Password
              <input type="password" value={loginForm.password} onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })} autoComplete="current-password" />
            </label>
            <label className="check-row">
              <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
              Remember me on this browser
            </label>
            <button className="primary wide" disabled={submitting || !backendHealthy}>
              {submitting ? 'Working...' : 'Continue'}
            </button>
          </form>

          {pendingAuth && (
            <form className="otp-box" onSubmit={verifyOtp}>
              <div>
                <strong>OTP verification</strong>
                <p>Enter the six digit code sent to your email.</p>
              </div>
              <input value={otpInput} onChange={(e) => setOtpInput(e.target.value)} inputMode="numeric" maxLength={6} placeholder="000000" />
              <button className="secondary wide">Verify OTP</button>
            </form>
          )}

          <button type="button" className="register-link-card" onClick={() => navigateAuth('register')}>
            <span>Create a new account</span>
            <strong>Open registration page</strong>
          </button>

          <div className="oauth-row">
            {providers.map((provider) => (
              <button key={provider.id} type="button" className="oauth-button" onClick={() => setMessage(provider.enabled ? `${provider.name} OAuth is available from the backend.` : provider.note)}>
                {provider.name}
              </button>
            ))}
          </div>

          <p className={backendHealthy ? 'system-message ok' : 'system-message'}>{message}</p>
        </section>
        {notice && <Toast notice={notice} onClose={() => setNotice(null)} />}
      </main>
    );
  }

  const isAdmin = user?.role === 'Admin';

  return (
    <main className="app-shell">
      <header className="topbar">
        <BeyondLogo />
        <div className="topbar-actions">
          <span className={backendHealthy ? 'status-pill up' : 'status-pill down'}>{backendHealthy ? 'Backend online' : 'Backend offline'}</span>
          <button className="theme-toggle" type="button" onClick={() => setTheme((current) => (current === 'light' ? 'dark' : 'light'))}>
            {theme === 'light' ? 'Dark' : 'Light'}
          </button>
          <button className="secondary" type="button" onClick={signOut}>Sign out</button>
        </div>
      </header>

      {isAdmin ? (
        <section className="admin-dashboard">
          <section className="admin-hero">
            <div>
              <span className="label">Admin dashboard</span>
              <h1>Manage VPN servers and users</h1>
              <p>Add OVPN files, WireGuard configs, or free internet VPN sources. Then promote or demote users from one place.</p>
            </div>
            <button className="primary" type="button" onClick={refreshSources} disabled={sourceBusy}>
              {sourceBusy ? 'Refreshing...' : 'Refresh internet sources'}
            </button>
          </section>

          <section className="admin-grid">
            <section className="user-panel source-panel">
              <div className="panel-heading">
                <div>
                  <span>VPN server source</span>
                  <h2>Add server</h2>
                </div>
              </div>

              <div className="source-kind-grid">
                <button type="button" className={sourceKind === 'ovpn-file' ? 'source-kind active' : 'source-kind'} onClick={() => applySourceKind('ovpn-file')}>
                  <strong>OVPN file</strong>
                  <span>OpenVPN .ovpn path</span>
                </button>
                <button type="button" className={sourceKind === 'wireguard-config' ? 'source-kind active' : 'source-kind'} onClick={() => applySourceKind('wireguard-config')}>
                  <strong>WireGuard</strong>
                  <span>.conf path</span>
                </button>
                <button type="button" className={sourceKind === 'free-internet' ? 'source-kind active' : 'source-kind'} onClick={() => applySourceKind('free-internet')}>
                  <strong>Free internet VPN</strong>
                  <span>Public config URL</span>
                </button>
              </div>

              <form className="source-form" onSubmit={saveVpnSource}>
                <label>
                  Source id
                  <input value={sourceForm.id} onChange={(e) => setSourceForm({ ...sourceForm, id: e.target.value })} placeholder="us-openvpn-01" />
                </label>
                <label>
                  Server name
                  <input value={sourceForm.name} onChange={(e) => setSourceForm({ ...sourceForm, name: e.target.value })} placeholder="US Free OpenVPN" required />
                </label>
                <label>
                  Country
                  <input value={sourceForm.country} onChange={(e) => setSourceForm({ ...sourceForm, country: e.target.value })} placeholder="United States" required />
                </label>
                <label>
                  Protocol
                  <select value={sourceForm.protocol} onChange={(e) => setSourceForm({ ...sourceForm, protocol: e.target.value as VpnSource['protocol'] })}>
                    <option value="openvpn">OpenVPN / OVPN</option>
                    <option value="wireguard">WireGuard</option>
                  </select>
                </label>
                <label>
                  Latency estimate
                  <input type="number" min="1" value={sourceForm.latencyMs} onChange={(e) => setSourceForm({ ...sourceForm, latencyMs: Number(e.target.value) || 999 })} />
                </label>
                <label>
                  Source label
                  <input value={sourceForm.source} onChange={(e) => setSourceForm({ ...sourceForm, source: e.target.value })} />
                </label>
                {sourceKind === 'free-internet' ? (
                  <label className="span-two">
                    Public config URL
                    <input value={sourceForm.url ?? ''} onChange={(e) => setSourceForm({ ...sourceForm, url: e.target.value })} placeholder="https://example.com/free-profile.ovpn" required />
                  </label>
                ) : (
                  <label className="span-two">
                    Local config path
                    <input value={sourceForm.path ?? ''} onChange={(e) => setSourceForm({ ...sourceForm, path: e.target.value })} placeholder={sourceKind === 'wireguard-config' ? 'samples/wireguard-sample.conf' : 'samples/openvpn-sample.ovpn'} required />
                  </label>
                )}
                <button className="primary wide span-two" disabled={sourceBusy}>
                  {sourceBusy ? 'Saving...' : 'Save VPN server'}
                </button>
              </form>
            </section>

            <section className="user-panel">
              <div className="panel-heading">
                <div>
                  <span>Source inventory</span>
                  <h2>Configured VPN sources</h2>
                </div>
              </div>
              <div className="source-list">
                {vpnSources.map((source) => (
                  <div className="source-row" key={source.id}>
                    <div>
                      <strong>{source.name}</strong>
                      <span>{source.protocol} / {source.country}</span>
                      <span>{source.path || source.url || 'No path or URL saved'}</span>
                    </div>
                    <button className="secondary danger-action" type="button" onClick={() => removeVpnSource(source.id)} disabled={sourceBusy}>
                      Remove
                    </button>
                  </div>
                ))}
                {!vpnSources.length && <p className="empty-copy">No admin VPN sources saved yet.</p>}
              </div>
            </section>
          </section>

          <section className="user-panel">
            <div className="panel-heading">
              <div>
                <span>User assignment</span>
                <h2>Common users and admins</h2>
              </div>
            </div>
            <div className="user-tools">
              <input value={userSearch} onChange={(e) => setUserSearch(e.target.value)} placeholder="Search users" />
              <select value={roleFilter} onChange={(e) => setRoleFilter(e.target.value as typeof roleFilter)}>
                <option value="all">All roles</option>
                <option value="Admin">Admins</option>
                <option value="User">Common users</option>
              </select>
            </div>
            <div className="user-list">
              {filteredUsers.map((entry) => (
                <div className="user-row admin-user-row" key={entry.id}>
                  <div>
                    <strong>{entry.displayName || entry.username}</strong>
                    <span>{entry.email || `@${entry.username}`}</span>
                  </div>
                  <select value={entry.role} onChange={(e) => updateRole(entry.id, e.target.value)}>
                    <option value="Admin">Admin</option>
                    <option value="User">Common user</option>
                  </select>
                </div>
              ))}
            </div>
          </section>
        </section>
      ) : (
        <section className="dashboard-grid">
          <aside className="country-panel">
            <div className="panel-heading">
              <div>
                <span>User dashboard</span>
                <h2>Choose location</h2>
              </div>
              <button className="icon-button" type="button" onClick={() => loadDashboard(true)} disabled={reloadingData}>
                {reloadingData ? '...' : 'Refresh'}
              </button>
            </div>

            <input className="search-input" value={countrySearch} onChange={(e) => setCountrySearch(e.target.value)} placeholder="Search country" />

            <div className="country-list">
              {visibleCountries.map((entry) => (
                <button
                  key={entry.country}
                  className={selected?.country === entry.country ? 'country-card active' : 'country-card'}
                  type="button"
                  onClick={() => setSelected(entry.fastest)}
                >
                  <div>
                    <strong>{entry.country}</strong>
                    <span>{entry.total} server{entry.total === 1 ? '' : 's'} available</span>
                  </div>
                  <div className="country-meta">
                    <span className={entry.up ? 'dot-label up' : 'dot-label down'}>{entry.up ? 'Up' : 'Down'}</span>
                    <span>{entry.avgLatency} ms</span>
                  </div>
                </button>
              ))}
            </div>
          </aside>

          <section className="connect-panel">
            <div className="connect-card">
              <div className={isConnected ? 'vpn-orb connected' : 'vpn-orb'}>
                <span>{isConnected ? 'ON' : 'VPN'}</span>
              </div>
              <div className="connect-copy">
                <span className="label">Selected country</span>
                <h1>{selected?.country || 'No country selected'}</h1>
                <p>{selected ? `${selected.name} / ${selected.type.toUpperCase()} / ${selected.latencyMs} ms` : 'Pick a country from the left, then press Connect.'}</p>
                <div className="action-row">
                  <button className="primary" type="button" onClick={handleConnect} disabled={!canConnect}>
                    {busyServerId ? 'Connecting...' : 'Connect'}
                  </button>
                  <button className="secondary" type="button" onClick={handleDisconnect} disabled={!canDisconnect}>
                    Disconnect
                  </button>
                </div>
              </div>
            </div>

            <div className="status-strip">
              <article>
                <span>Status</span>
                <strong>{status}</strong>
              </article>
              <article>
                <span>Mode</span>
                <strong>{window.vpn ? 'Native tunnel' : 'Web profile'}</strong>
              </article>
              <article>
                <span>Account</span>
                <strong>{user?.displayName || user?.username}</strong>
              </article>
            </div>

            <section className="chart-card realtime-panel">
              <div className="panel-heading">
                <div>
                  <span>Realtime availability</span>
                  <h2>Up vs down trend</h2>
                </div>
                <div className="chart-legend">
                  <span className="legend-up">Up {availabilityTotals.up}</span>
                  <span className="legend-down">Down {availabilityTotals.down}</span>
                </div>
              </div>
              <svg className="realtime-chart" viewBox="0 0 640 240" role="img" aria-label="Realtime up and down VPN server chart">
                <path className="grid-line" d="M 0 40 H 640 M 0 125 H 640 M 0 210 H 640" />
                <path className="line-up" d={getLinePath('up')} />
                <path className="line-down" d={getLinePath('down')} />
              </svg>
              <div className="chart-times">
                <span>{availabilityHistory[0]?.time || 'Waiting'}</span>
                <span>{availabilityHistory.at(-1)?.time || 'Waiting'}</span>
              </div>
            </section>
          </section>
        </section>
      )}

      <footer className="footer-message">{message}</footer>
      {notice && <Toast notice={notice} onClose={() => setNotice(null)} />}
    </main>
  );
}

function Toast({ notice, onClose }: { notice: Notice; onClose: () => void }) {
  return (
    <div className={`toast toast-${notice.tone}`} role="status" aria-live="polite">
      <p>{notice.text}</p>
      <button type="button" onClick={onClose} aria-label="Close message">
        x
      </button>
    </div>
  );
}
