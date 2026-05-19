import React, { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import axios from 'axios';
import {
  configureNativeVpn,
  getNativeVpnStatus,
  importNativeProfileToClient,
  prepareNativeVpnPermission,
  shareNativeVpnProfile,
  startNativeVpn,
  stopNativeVpn,
} from './native/fortiVpn';

const API =
  Platform.OS === 'android'
    ? 'http://10.0.2.2:5000/api'
    : 'http://localhost:5000/api';

const http = axios.create({ baseURL: API });

type User = {
  id: string;
  username: string;
  displayName: string;
  email: string;
  role: string;
  provider: string;
  lastLoginAt?: string;
};

type Server = {
  id: string;
  name: string;
  country: string;
  type: string;
  latencyMs: number;
  source?: string;
};

type Provider = {
  id: string;
  name: string;
  enabled: boolean;
  note: string;
};

type ConfigPayload = {
  id: string;
  name: string;
  country: string;
  type: string;
  source?: string;
  config: string;
};

type Mode = 'login' | 'register';
type ProtocolFilter = 'all' | 'openvpn' | 'wireguard';

type NativeVpnState = {
  available: boolean;
  running: boolean;
  profileId: string;
  protocol: string;
  permissionReady: boolean;
  hasConfig: boolean;
  remoteHost?: string;
  dnsTarget?: string;
  engineMode?: string;
  clients?: {
    openvpn: boolean;
    wireguard: boolean;
  };
};

type NetworkProbe = {
  ip: string;
  city: string;
  region: string;
  country: string;
  org: string;
  checkedAt: string;
};

function emptyNetworkProbe(): NetworkProbe {
  return {
    ip: 'Unknown',
    city: '',
    region: '',
    country: '',
    org: '',
    checkedAt: '',
  };
}

function describeNetworkProbe(probe: NetworkProbe | null): string {
  if (!probe) {
    return 'No network snapshot yet.';
  }

  const location = [probe.city, probe.region, probe.country].filter(Boolean).join(', ');
  const place = location || 'Location unavailable';
  return `${probe.ip} | ${place}${probe.org ? ` | ${probe.org}` : ''}`;
}

function buildProofSummary(
  baseline: NetworkProbe | null,
  current: NetworkProbe | null,
  nativeVpnState: NativeVpnState
): string {
  if (!baseline || !current) {
    return 'Run a proof check to capture device networking before and after VPN actions.';
  }

  if (!nativeVpnState.running) {
    return 'Native service is stopped, so the device should still match the baseline route.';
  }

  if (baseline.ip !== 'Unknown' && current.ip !== 'Unknown' && baseline.ip !== current.ip) {
    return `Public IP changed from ${baseline.ip} to ${current.ip}.`;
  }

  if (nativeVpnState.running && nativeVpnState.hasConfig) {
    return `Native tunnel is running in ${nativeVpnState.engineMode || 'foundation'} mode, but the public IP did not change yet. Use the embedded foundation for proofing or open the profile in a full VPN client for production traffic.`;
  }

  return 'VPN config has not been staged yet, so there is nothing to prove on-device.';
}

async function fetchNetworkProbe(): Promise<NetworkProbe> {
  try {
    const response = await axios.get('https://ipapi.co/json/', { timeout: 8000 });
    return {
      ip: response.data?.ip || 'Unknown',
      city: response.data?.city || '',
      region: response.data?.region || '',
      country: response.data?.country_name || '',
      org: response.data?.org || '',
      checkedAt: new Date().toISOString(),
    };
  } catch {
    return {
      ...emptyNetworkProbe(),
      checkedAt: new Date().toISOString(),
    };
  }
}

export default function App() {
  const [mode, setMode] = useState<Mode>('login');
  const [backendHealthy, setBackendHealthy] = useState(false);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [token, setToken] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [servers, setServers] = useState<Server[]>([]);
  const [selected, setSelected] = useState<Server | null>(null);
  const [status, setStatus] = useState('Idle');
  const [message, setMessage] = useState('Android is ready to use the same auth and route catalog as desktop.');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [proofLoading, setProofLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<ProtocolFilter>('all');
  const [nativeVpnState, setNativeVpnState] = useState<NativeVpnState>({
    available: false,
    running: false,
    profileId: '',
    protocol: '',
    permissionReady: false,
    hasConfig: false,
    remoteHost: '',
    dnsTarget: '',
    engineMode: 'unavailable',
    clients: {
      openvpn: false,
      wireguard: false,
    },
  });
  const [baselineProbe, setBaselineProbe] = useState<NetworkProbe | null>(null);
  const [currentProbe, setCurrentProbe] = useState<NetworkProbe | null>(null);
  const [form, setForm] = useState({
    username: 'demo',
    password: 'demo',
    displayName: '',
    email: '',
  });

  const authHeaders = useMemo(
    () => (token ? { Authorization: `Bearer ${token}` } : undefined),
    [token]
  );

  const protocolCapability = selected?.type
    ? `${selected.type.toUpperCase()} profile ready`
    : 'Select a route to stage a profile';

  const recommendedClient = selected?.type === 'wireguard' ? 'wireguard' : selected?.type === 'openvpn' ? 'openvpn' : null;

  useEffect(() => {
    const boot = async () => {
      try {
        await http.get('/health');
        setBackendHealthy(true);
      } catch {
        setBackendHealthy(false);
        setMessage('Backend unavailable on port 5000.');
      }

      try {
        const response = await http.get('/oauth/providers');
        setProviders(response.data.providers ?? []);
      } catch {
        setProviders([]);
      }

      const vpnState = await getNativeVpnStatus();
      setNativeVpnState(vpnState);
    };

    boot();
  }, []);

  useEffect(() => {
    if (!token) {
      return;
    }

    let alive = true;
    const refreshNativeState = async () => {
      const vpnState = await getNativeVpnStatus();
      if (alive) {
        setNativeVpnState(vpnState);
      }
    };

    refreshNativeState();
    const interval = setInterval(refreshNativeState, 15000);

    return () => {
      alive = false;
      clearInterval(interval);
    };
  }, [token, status]);

  const refreshProof = async (captureBaseline = false) => {
    setProofLoading(true);

    try {
      const probe = await fetchNetworkProbe();
      setCurrentProbe(probe);
      if (captureBaseline || !baselineProbe) {
        setBaselineProbe(probe);
      }
    } finally {
      setProofLoading(false);
    }
  };

  const loadDashboard = async (showRefresh = false) => {
    if (!token) {
      return;
    }

    if (showRefresh) {
      setRefreshing(true);
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
      setMessage('Android is synchronized with the live backend inventory.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Unable to load mobile session data.');
    } finally {
      setRefreshing(false);
    }
  };

  useEffect(() => {
    if (!token) {
      return;
    }

    loadDashboard();
    refreshProof(true);
  }, [token, authHeaders]);

  const filteredServers = servers.filter((server) => {
    const query = search.toLowerCase();
    const matchesProtocol = protocolFilter === 'all' || server.type === protocolFilter;
    const matchesSearch =
      server.name.toLowerCase().includes(query) ||
      server.country.toLowerCase().includes(query) ||
      server.type.toLowerCase().includes(query);

    return matchesProtocol && matchesSearch;
  });

  const submit = async () => {
    setLoading(true);
    setMessage(mode === 'register' ? 'Creating Android account...' : 'Authorizing Android session...');

    try {
      const endpoint = mode === 'register' ? '/register' : '/auth';
      const payload =
        mode === 'register'
          ? form
          : { username: form.username, password: form.password };

      const response = await http.post(endpoint, payload);
      setToken(response.data.token);
      setUser(response.data.user);
      setMessage(mode === 'register' ? 'Registration completed on Android.' : 'Signed in on Android.');
    } catch (error: any) {
      setMessage(error?.response?.data?.error || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  const hydrateNativeProfile = async (server: Server) => {
    const response = await http.get(`/config/${server.id}`);
    const payload = response.data as ConfigPayload;

    if (!payload.config) {
      throw new Error('Backend returned an empty profile.');
    }

    const configured = await configureNativeVpn(server.id, payload.type, payload.config);
    if (!configured) {
      throw new Error('Native Android VPN module is unavailable in this build.');
    }

    const nextState = await getNativeVpnStatus();
    setNativeVpnState(nextState);

    return payload;
  };

  const prepareServer = async (server: Server) => {
    setSelected(server);
    setStatus(`Preparing ${server.type}`);

    try {
      const payload = await hydrateNativeProfile(server);
      setStatus(`Profile ready: ${payload.type}`);
      setMessage(`Stored ${payload.type} profile for ${payload.country}. You can now start the native tunnel or export it to another VPN app.`);
    } catch (error: any) {
      setStatus('Profile failed');
      setMessage(error?.response?.data?.error || error?.message || 'Could not fetch profile metadata from backend.');
    }
  };

  const clearFilters = () => {
    setSearch('');
    setProtocolFilter('all');
    setMessage('Android filters cleared.');
  };

  const signOut = () => {
    setToken('');
    setUser(null);
    setServers([]);
    setSelected(null);
    setStatus('Idle');
    setBaselineProbe(null);
    setCurrentProbe(null);
    setMessage('Android session ended.');
  };

  const requestNativePermission = async () => {
    const granted = await prepareNativeVpnPermission();
    const nextState = await getNativeVpnStatus();
    setNativeVpnState(nextState);
    setMessage(granted ? 'Android VPN permission is ready.' : 'Android opened the native VPN permission flow.');
  };

  const startNativeSession = async () => {
    if (!selected) {
      setMessage('Select a server before starting the Android VPN service.');
      return;
    }

    try {
      if (!nativeVpnState.hasConfig || nativeVpnState.profileId !== selected.id) {
        await hydrateNativeProfile(selected);
      }

      const started = await startNativeVpn(selected.id, selected.type);
      const nextState = await getNativeVpnStatus();
      setNativeVpnState(nextState);
      setStatus(started ? `Native VPN started: ${selected.type}` : 'Native VPN pending');
      await refreshProof(false);
      setMessage(
        started
          ? 'Android native VPN service started. Use Check route to confirm whether your public IP changed.'
          : 'Native VPN module is not available yet in this build.'
      );
    } catch (error: any) {
      setMessage(error?.message || 'Android native VPN start failed.');
    }
  };

  const stopNativeSession = async () => {
    await stopNativeVpn();
    const nextState = await getNativeVpnStatus();
    setNativeVpnState(nextState);
    setStatus('Native VPN stopped');
    await refreshProof(false);
    setMessage('Android native VPN service stopped.');
  };

  const exportProfile = async () => {
    if (!selected) {
      setMessage('Choose a server before exporting a profile.');
      return;
    }

    try {
      if (!nativeVpnState.hasConfig || nativeVpnState.profileId !== selected.id) {
        await hydrateNativeProfile(selected);
      }

      const shared = await shareNativeVpnProfile();
      setMessage(
        shared
          ? 'Android opened the system share sheet so you can import the profile into a full VPN client.'
          : 'No staged profile is ready to share yet.'
      );
    } catch (error: any) {
      setMessage(error?.message || 'Profile export failed.');
    }
  };

  const importIntoVpnClient = async (client: 'openvpn' | 'wireguard') => {
    if (!selected) {
      setMessage('Choose a server before importing into a VPN client.');
      return;
    }

    try {
      if (!nativeVpnState.hasConfig || nativeVpnState.profileId !== selected.id) {
        await hydrateNativeProfile(selected);
      }

      const imported = await importNativeProfileToClient(client);
      setMessage(
        imported
          ? `${client === 'wireguard' ? 'WireGuard' : 'OpenVPN'} app opened with the staged profile.`
          : `${client === 'wireguard' ? 'WireGuard' : 'OpenVPN'} app is not installed or did not accept the profile.`
      );
    } catch (error: any) {
      setMessage(error?.message || 'Client import failed.');
    }
  };

  const handleOAuthPress = (provider: Provider) => {
    if (!provider.enabled) {
      setMessage(`${provider.name} OAuth is not enabled yet. ${provider.note}`);
      return;
    }

    setMessage(`${provider.name} OAuth is configured on the backend. Native redirect flow is the next step once credentials are finalized.`);
  };

  if (!token) {
    return (
      <SafeAreaView style={styles.screen}>
        <StatusBar barStyle="light-content" />
        <ScrollView contentContainerStyle={styles.authWrap}>
          <View style={styles.heroBlock}>
            <Text style={styles.eyebrow}>FortiClone Android</Text>
            <Text style={styles.title}>A mobile VPN surface that looks serious and tells the truth.</Text>
            <Text style={styles.copy}>
              Android uses the same backend contract as web and desktop for auth, registration,
              profile inventory, and route preparation.
            </Text>
            <View style={styles.badgeRow}>
              <View style={[styles.badge, backendHealthy ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>{backendHealthy ? 'Backend online' : 'Backend offline'}</Text>
              </View>
              <View style={styles.badge}>
                <Text style={styles.badgeText}>Android client</Text>
              </View>
            </View>
          </View>

          <View style={styles.panel}>
            <View style={styles.toggleRow}>
              <Pressable style={[styles.toggle, mode === 'login' && styles.toggleActive]} onPress={() => setMode('login')}>
                <Text style={[styles.toggleText, mode === 'login' && styles.toggleTextActive]}>Login</Text>
              </Pressable>
              <Pressable style={[styles.toggle, mode === 'register' && styles.toggleActive]} onPress={() => setMode('register')}>
                <Text style={[styles.toggleText, mode === 'register' && styles.toggleTextActive]}>Register</Text>
              </Pressable>
            </View>

            <TextInput
              style={styles.input}
              placeholder="Username"
              placeholderTextColor="#7f96aa"
              value={form.username}
              onChangeText={(value) => setForm({ ...form, username: value })}
            />
            <TextInput
              style={styles.input}
              placeholder="Password"
              placeholderTextColor="#7f96aa"
              secureTextEntry
              value={form.password}
              onChangeText={(value) => setForm({ ...form, password: value })}
            />

            {mode === 'register' && (
              <>
                <TextInput
                  style={styles.input}
                  placeholder="Display name"
                  placeholderTextColor="#7f96aa"
                  value={form.displayName}
                  onChangeText={(value) => setForm({ ...form, displayName: value })}
                />
                <TextInput
                  style={styles.input}
                  placeholder="Email"
                  placeholderTextColor="#7f96aa"
                  value={form.email}
                  onChangeText={(value) => setForm({ ...form, email: value })}
                />
              </>
            )}

            <Pressable
              style={[styles.primaryButton, (!backendHealthy || loading) && styles.disabledButton]}
              onPress={submit}
              disabled={!backendHealthy || loading}
            >
              {loading ? (
                <ActivityIndicator color="#07111a" />
              ) : (
                <Text style={styles.primaryButtonText}>{mode === 'register' ? 'Create account' : 'Sign in'}</Text>
              )}
            </Pressable>
          </View>

          <View style={styles.panel}>
            <Text style={styles.sectionTitle}>OAuth readiness</Text>
            {providers.map((provider) => (
              <Pressable key={provider.id} style={styles.oauthRow} onPress={() => handleOAuthPress(provider)}>
                <View style={styles.oauthCopy}>
                  <Text style={styles.oauthName}>{provider.name}</Text>
                  <Text style={styles.oauthNote}>{provider.enabled ? 'Client configured' : provider.note}</Text>
                </View>
                <Text style={styles.oauthChevron}>{'>'}</Text>
              </Pressable>
            ))}
          </View>

          <Text style={styles.footer}>{message}</Text>
        </ScrollView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.screen}>
      <StatusBar barStyle="light-content" />
      <ScrollView contentContainerStyle={styles.dashboardWrap}>
        <View style={styles.heroCard}>
          <Text style={styles.eyebrow}>Session</Text>
          <Text style={styles.sectionTitle}>{user?.displayName || user?.username}</Text>
          <Text style={styles.copy}>{user?.email || user?.provider}</Text>
          <View style={styles.badgeRow}>
            <View style={styles.badge}>
              <Text style={styles.badgeText}>{user?.role || 'User'}</Text>
            </View>
            <View style={styles.badge}>
              <Text style={styles.badgeText}>{user?.provider || 'local'}</Text>
            </View>
          </View>
          <View style={styles.actionRow}>
            <Pressable style={styles.secondaryButton} onPress={() => loadDashboard(true)} disabled={refreshing}>
              <Text style={styles.secondaryButtonText}>{refreshing ? 'Refreshing...' : 'Refresh'}</Text>
            </Pressable>
            <Pressable style={styles.secondaryButton} onPress={signOut}>
              <Text style={styles.secondaryButtonText}>Sign out</Text>
            </Pressable>
          </View>
        </View>

        <View style={styles.panel}>
          <Text style={styles.eyebrow}>Live Status</Text>
          <Text style={styles.statusTitle}>{status}</Text>
          <Text style={styles.oauthNote}>{message}</Text>
            <View style={styles.badgeRow}>
              <View style={[styles.badge, nativeVpnState.available ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>{nativeVpnState.available ? 'Native module ready' : 'Native module unavailable'}</Text>
            </View>
            <View style={[styles.badge, nativeVpnState.permissionReady ? styles.badgeLive : styles.badgeDown]}>
              <Text style={styles.badgeText}>{nativeVpnState.permissionReady ? 'VPN permission ready' : 'Permission required'}</Text>
            </View>
            <View style={[styles.badge, nativeVpnState.running ? styles.badgeLive : styles.badgeDown]}>
              <Text style={styles.badgeText}>{nativeVpnState.running ? 'Service running' : 'Service stopped'}</Text>
            </View>
              <View style={[styles.badge, nativeVpnState.hasConfig ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>{nativeVpnState.hasConfig ? 'Profile staged' : 'No profile staged'}</Text>
              </View>
              <View style={[styles.badge, nativeVpnState.engineMode === 'foundation' || nativeVpnState.engineMode === 'staged' ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>
                  {nativeVpnState.engineMode === 'foundation' || nativeVpnState.engineMode === 'staged'
                    ? `Engine ${nativeVpnState.engineMode}`
                    : 'Engine unavailable'}
                </Text>
              </View>
              <View style={[styles.badge, nativeVpnState.clients?.openvpn ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>{nativeVpnState.clients?.openvpn ? 'OpenVPN app installed' : 'OpenVPN app missing'}</Text>
              </View>
              <View style={[styles.badge, nativeVpnState.clients?.wireguard ? styles.badgeLive : styles.badgeDown]}>
                <Text style={styles.badgeText}>{nativeVpnState.clients?.wireguard ? 'WireGuard app installed' : 'WireGuard app missing'}</Text>
              </View>
            </View>
            <View style={styles.actionWrap}>
            <Pressable style={styles.secondaryButton} onPress={requestNativePermission}>
              <Text style={styles.secondaryButtonText}>Prepare permission</Text>
            </Pressable>
            <Pressable style={styles.secondaryButton} onPress={startNativeSession}>
              <Text style={styles.secondaryButtonText}>Start native</Text>
            </Pressable>
            <Pressable style={styles.secondaryButton} onPress={stopNativeSession}>
              <Text style={styles.secondaryButtonText}>Stop native</Text>
            </Pressable>
              <Pressable style={styles.secondaryButton} onPress={exportProfile}>
                <Text style={styles.secondaryButtonText}>Export profile</Text>
              </Pressable>
              <Pressable
                style={[
                  styles.secondaryButton,
                  (!nativeVpnState.clients?.openvpn || recommendedClient === 'wireguard') && styles.dimmedButton,
                ]}
                onPress={() => importIntoVpnClient('openvpn')}
              >
                <Text style={styles.secondaryButtonText}>Open in OpenVPN</Text>
              </Pressable>
              <Pressable
                style={[
                  styles.secondaryButton,
                  (!nativeVpnState.clients?.wireguard || recommendedClient === 'openvpn') && styles.dimmedButton,
                ]}
                onPress={() => importIntoVpnClient('wireguard')}
              >
                <Text style={styles.secondaryButtonText}>Open in WireGuard</Text>
              </Pressable>
              <Pressable style={styles.secondaryButton} onPress={() => refreshProof(false)} disabled={proofLoading}>
                <Text style={styles.secondaryButtonText}>{proofLoading ? 'Checking...' : 'Check route'}</Text>
              </Pressable>
            </View>
          </View>

        <View style={styles.panel}>
          <Text style={styles.eyebrow}>Proof</Text>
          <Text style={styles.sectionTitle}>Device route verification</Text>
          <Text style={styles.oauthNote}>{buildProofSummary(baselineProbe, currentProbe, nativeVpnState)}</Text>
          <View style={styles.proofGrid}>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>Baseline IP</Text>
              <Text style={styles.proofValue}>{baselineProbe?.ip || 'Not captured'}</Text>
              <Text style={styles.oauthNote}>{describeNetworkProbe(baselineProbe)}</Text>
            </View>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>Current IP</Text>
              <Text style={styles.proofValue}>{currentProbe?.ip || 'Not captured'}</Text>
              <Text style={styles.oauthNote}>{describeNetworkProbe(currentProbe)}</Text>
            </View>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>Tunnel target</Text>
              <Text style={styles.proofValue}>{nativeVpnState.protocol ? nativeVpnState.protocol.toUpperCase() : 'No protocol'}</Text>
              <Text style={styles.oauthNote}>{protocolCapability}</Text>
            </View>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>DNS target</Text>
              <Text style={styles.proofValue}>{nativeVpnState.running ? nativeVpnState.dnsTarget || '1.1.1.1' : 'Device default'}</Text>
              <Text style={styles.oauthNote}>
                {nativeVpnState.running
                  ? 'Current native VpnService foundation reports the active DNS target parsed from the staged profile or the fallback builder.'
                  : 'Android JS cannot read system DNS directly, so the app reports the active tunnel target instead.'}
              </Text>
            </View>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>Remote endpoint</Text>
              <Text style={styles.proofValue}>{nativeVpnState.remoteHost || 'Not parsed yet'}</Text>
              <Text style={styles.oauthNote}>
                {nativeVpnState.remoteHost
                  ? 'This endpoint was parsed from the staged VPN profile before handoff or native start.'
                  : 'Stage a route to parse and display the target endpoint from the VPN profile.'}
              </Text>
            </View>
            <View style={styles.proofCard}>
              <Text style={styles.proofLabel}>Client handoff</Text>
              <Text style={styles.proofValue}>
                {recommendedClient
                  ? recommendedClient === 'wireguard'
                    ? 'WireGuard preferred'
                    : 'OpenVPN preferred'
                  : 'Choose protocol'}
              </Text>
              <Text style={styles.oauthNote}>
                {recommendedClient
                  ? `For real-world traffic today, stage the profile here and hand it to the installed ${recommendedClient === 'wireguard' ? 'WireGuard' : 'OpenVPN'} app.`
                  : 'Once a route is selected, the app can direct the profile to a matching Android VPN client.'}
              </Text>
            </View>
          </View>
        </View>

        <View style={styles.panel}>
          <Text style={styles.eyebrow}>Server Search</Text>
          <TextInput
            style={styles.input}
            placeholder="country, name, protocol"
            placeholderTextColor="#7f96aa"
            value={search}
            onChangeText={setSearch}
          />

          <View style={styles.toggleRow}>
            <Pressable style={[styles.smallToggle, protocolFilter === 'all' && styles.toggleActive]} onPress={() => setProtocolFilter('all')}>
              <Text style={[styles.smallToggleText, protocolFilter === 'all' && styles.toggleTextActive]}>All</Text>
            </Pressable>
            <Pressable
              style={[styles.smallToggle, protocolFilter === 'openvpn' && styles.toggleActive]}
              onPress={() => setProtocolFilter('openvpn')}
            >
              <Text style={[styles.smallToggleText, protocolFilter === 'openvpn' && styles.toggleTextActive]}>OpenVPN</Text>
            </Pressable>
            <Pressable
              style={[styles.smallToggle, protocolFilter === 'wireguard' && styles.toggleActive]}
              onPress={() => setProtocolFilter('wireguard')}
            >
              <Text style={[styles.smallToggleText, protocolFilter === 'wireguard' && styles.toggleTextActive]}>WireGuard</Text>
            </Pressable>
          </View>

          <Pressable style={styles.secondaryButton} onPress={clearFilters}>
            <Text style={styles.secondaryButtonText}>Clear filters</Text>
          </Pressable>
        </View>

        <View style={styles.panel}>
          <Text style={styles.eyebrow}>Selected Route</Text>
          <Text style={styles.sectionTitle}>{selected?.name || 'Choose a server'}</Text>
          <Text style={styles.oauthNote}>
            {selected
              ? `${selected.country} | ${selected.type} | ${selected.latencyMs} ms | ${selected.source || 'source unknown'}`
              : 'Pick a server below to prepare a profile.'}
          </Text>
        </View>

        <View style={styles.panel}>
          <Text style={styles.eyebrow}>Servers</Text>
          {filteredServers.map((server) => {
            const active = selected?.id === server.id;

            return (
              <Pressable key={server.id} style={[styles.serverCard, active && styles.serverCardActive]} onPress={() => prepareServer(server)}>
                <View style={styles.serverTopRow}>
                  <View style={styles.serverCopy}>
                    <Text style={styles.serverName}>{server.name}</Text>
                    <Text style={styles.oauthNote}>{server.country}</Text>
                  </View>
                  <View style={styles.serverStats}>
                    <Text style={styles.serverType}>{server.type.toUpperCase()}</Text>
                    <Text style={styles.oauthNote}>{server.latencyMs} ms</Text>
                  </View>
                </View>
                <View style={styles.badgeRow}>
                  <View style={styles.badge}>
                    <Text style={styles.badgeText}>{server.source || 'source unknown'}</Text>
                  </View>
                </View>
              </Pressable>
            );
          })}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: '#07111a',
  },
  authWrap: {
    padding: 20,
    gap: 16,
  },
  dashboardWrap: {
    padding: 20,
    gap: 16,
  },
  heroBlock: {
    borderRadius: 28,
    padding: 22,
    backgroundColor: 'rgba(10, 23, 35, 0.92)',
    borderWidth: 1,
    borderColor: 'rgba(89, 208, 255, 0.14)',
  },
  heroCard: {
    borderRadius: 28,
    padding: 22,
    backgroundColor: 'rgba(10, 23, 35, 0.92)',
    borderWidth: 1,
    borderColor: 'rgba(89, 208, 255, 0.14)',
  },
  panel: {
    borderRadius: 24,
    padding: 18,
    backgroundColor: 'rgba(14, 28, 42, 0.92)',
    borderWidth: 1,
    borderColor: 'rgba(89, 208, 255, 0.14)',
    gap: 12,
  },
  eyebrow: {
    color: '#59d0ff',
    textTransform: 'uppercase',
    letterSpacing: 2,
    fontSize: 12,
    fontWeight: '700',
  },
  title: {
    color: '#edf6ff',
    fontSize: 34,
    lineHeight: 38,
    fontWeight: '700',
    marginTop: 8,
  },
  sectionTitle: {
    color: '#edf6ff',
    fontSize: 24,
    lineHeight: 28,
    fontWeight: '700',
  },
  copy: {
    color: '#8ea8bf',
    fontSize: 14,
    lineHeight: 20,
    marginTop: 8,
  },
  badgeRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
    marginTop: 8,
  },
  badge: {
    borderRadius: 999,
    borderWidth: 1,
    borderColor: 'rgba(89, 208, 255, 0.16)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    paddingHorizontal: 12,
    paddingVertical: 7,
  },
  badgeLive: {
    backgroundColor: 'rgba(39, 245, 194, 0.14)',
    borderColor: 'rgba(39, 245, 194, 0.22)',
  },
  badgeDown: {
    backgroundColor: 'rgba(255, 125, 109, 0.14)',
    borderColor: 'rgba(255, 125, 109, 0.22)',
  },
  badgeText: {
    color: '#d8ecff',
    fontSize: 11,
    fontWeight: '700',
  },
  toggleRow: {
    flexDirection: 'row',
    gap: 10,
    marginTop: 2,
  },
  toggle: {
    flex: 1,
    borderRadius: 16,
    paddingVertical: 14,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    alignItems: 'center',
  },
  smallToggle: {
    flex: 1,
    borderRadius: 14,
    paddingVertical: 12,
    paddingHorizontal: 8,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    alignItems: 'center',
  },
  toggleActive: {
    backgroundColor: '#59d0ff',
    borderColor: '#59d0ff',
  },
  toggleText: {
    color: '#d8ecff',
    fontWeight: '700',
  },
  smallToggleText: {
    color: '#d8ecff',
    fontWeight: '700',
    fontSize: 12,
  },
  toggleTextActive: {
    color: '#07111a',
  },
  input: {
    borderRadius: 16,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.04)',
    color: '#edf6ff',
    padding: 16,
  },
  primaryButton: {
    borderRadius: 18,
    backgroundColor: '#59d0ff',
    paddingVertical: 16,
    alignItems: 'center',
    justifyContent: 'center',
  },
  disabledButton: {
    opacity: 0.45,
  },
  primaryButtonText: {
    color: '#07111a',
    fontWeight: '800',
    fontSize: 15,
  },
  secondaryButton: {
    minWidth: 132,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.04)',
    paddingVertical: 14,
    paddingHorizontal: 14,
    alignItems: 'center',
    justifyContent: 'center',
  },
  dimmedButton: {
    opacity: 0.55,
  },
  secondaryButtonText: {
    color: '#edf6ff',
    fontWeight: '700',
  },
  oauthRow: {
    borderRadius: 18,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    padding: 16,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
  },
  oauthCopy: {
    flex: 1,
  },
  oauthName: {
    color: '#edf6ff',
    fontWeight: '700',
    fontSize: 16,
  },
  oauthNote: {
    color: '#8ea8bf',
    fontSize: 12,
    lineHeight: 18,
  },
  oauthChevron: {
    color: '#59d0ff',
    fontSize: 22,
  },
  footer: {
    color: '#8ea8bf',
    fontSize: 13,
    lineHeight: 18,
    marginTop: 4,
  },
  statusTitle: {
    color: '#edf6ff',
    fontSize: 20,
    fontWeight: '700',
  },
  actionRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
    marginTop: 12,
  },
  actionWrap: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
    marginTop: 12,
  },
  proofGrid: {
    gap: 10,
  },
  proofCard: {
    borderRadius: 20,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    gap: 8,
  },
  proofLabel: {
    color: '#59d0ff',
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 1.5,
  },
  proofValue: {
    color: '#edf6ff',
    fontSize: 20,
    fontWeight: '700',
  },
  serverCard: {
    borderRadius: 20,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(160, 208, 255, 0.14)',
    backgroundColor: 'rgba(255,255,255,0.03)',
    gap: 10,
  },
  serverCardActive: {
    borderColor: 'rgba(89, 208, 255, 0.34)',
    backgroundColor: 'rgba(89, 208, 255, 0.08)',
  },
  serverTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  serverCopy: {
    flex: 1,
  },
  serverName: {
    color: '#edf6ff',
    fontWeight: '700',
    fontSize: 16,
  },
  serverStats: {
    alignItems: 'flex-end',
  },
  serverType: {
    color: '#d8ecff',
    fontWeight: '800',
    fontSize: 12,
  },
});
