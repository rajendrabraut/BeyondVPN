import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { api, ApiError, del, login, logout, post, resume, SsoProvider, ssoExchange, ssoProviders, ssoStartUrl, takeSsoResult } from "./api";
import { buildWgConfig, ConnectResponse, flag, formatBytes, generateWgKeypair } from "./lib";
import { AdminPages, ADMIN_PAGES } from "./Admin";

export interface Me {
  id: string;
  email: string;
  full_name: string;
  role: string;
  mfa_enabled: boolean;
  data_cap_bytes: number | null;
}

export interface Server {
  id: string;
  name: string;
  country: string;
  city: string;
  hostname: string;
  endpoint: string;
  load: number;
  features: string[];
  tier: string;
  status: string;
}

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = useCallback(() => {
    setError(null);
    fn().then(setData, (e) => setError(e instanceof Error ? e.message : String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(reload, [reload]);
  return { data, error, reload };
}

export function Err({ e }: { e: string | null }) {
  return e ? <div className="err" role="alert">{e}</div> : null;
}

export function Status({ s }: { s: string }) {
  const cls = s === "online" ? "ok" : s === "offline" ? "bad" : "warn";
  return <span className={`pill ${cls}`}>{s}</span>;
}

const USER_PAGES = ["Dashboard", "Servers", "Devices", "Activity", "Security"] as const;

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [booting, setBooting] = useState(true);
  const [page, setPage] = useState<string>("Dashboard");

  const loadMe = useCallback(async () => setMe(await api<Me>("/me")), []);
  useEffect(() => {
    resume()
      .then((ok) => (ok ? loadMe() : undefined))
      .catch(() => undefined)
      .finally(() => setBooting(false));
  }, [loadMe]);

  if (booting) return <div className="auth muted">Loading…</div>;
  if (!me) return <Auth onDone={loadMe} />;
  const staff = me.role === "admin" || me.role === "auditor";

  return (
    <div className="shell">
      <nav className="side" aria-label="Main">
        <div className="logo">Beyond<span>VPN</span></div>
        {USER_PAGES.map((p) => (
          <button key={p} className={`nav ${page === p ? "on" : ""}`} onClick={() => setPage(p)}>{p}</button>
        ))}
        {staff && <div className="navhead">Administration</div>}
        {staff && ADMIN_PAGES.map((p) => (
          <button key={p} className={`nav ${page === p ? "on" : ""}`} onClick={() => setPage(p)}>{p}</button>
        ))}
        <div style={{ flex: 1 }} />
        <div className="muted" style={{ padding: "0 10px", fontSize: 12 }}>{me.email}</div>
        <button className="nav" onClick={() => logout().then(() => setMe(null))}>Sign out</button>
      </nav>
      <main>
        {page === "Dashboard" && <Dashboard me={me} />}
        {page === "Servers" && <Servers />}
        {page === "Devices" && <Devices />}
        {page === "Activity" && <Activity />}
        {page === "Security" && <Security me={me} reload={loadMe} onErased={() => setMe(null)} />}
        {staff && <AdminPages page={page} me={me} />}
      </main>
    </div>
  );
}

const LOGGING_NOTICE =
  "I understand this service records my data usage and the domains/websites I visit while connected, for security and compliance. " +
  "Logs are kept for a limited retention period and I can view or delete mine at any time.";

function Auth({ onDone }: { onDone: () => Promise<void> }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [totp, setTotp] = useState("");
  const [needMfa, setNeedMfa] = useState(false);
  const [consent, setConsent] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  const [ssoCode, setSsoCode] = useState<string | null>(null);

  useEffect(() => {
    ssoProviders().then(setProviders).catch(() => undefined);
    const { code, error } = takeSsoResult();
    if (error) setErr(`Single sign-on failed: ${error}`);
    if (code) {
      ssoExchange(code)
        .then(onDone)
        .catch((x) => {
          if (x instanceof ApiError && x.status === 428) setSsoCode(code);
          else setErr(x instanceof Error ? x.message : String(x));
        });
    }
  }, [onDone]);

  const finishSso = async () => {
    if (!ssoCode) return;
    setErr(null);
    setBusy(true);
    try {
      await ssoExchange(ssoCode, true);
      await onDone();
    } catch (x) {
      setErr(x instanceof Error ? x.message : String(x));
    } finally {
      setBusy(false);
    }
  };

  if (ssoCode) {
    return (
      <div className="auth card">
        <div className="logo" style={{ padding: 0 }}>Beyond<span>VPN</span></div>
        <h1>One more step</h1>
        <label style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
          <input type="checkbox" style={{ width: "auto", marginTop: 4 }} checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>{LOGGING_NOTICE}</span>
        </label>
        <Err e={err} />
        <div className="row" style={{ marginTop: 14 }}>
          <button className="btn" disabled={busy || !consent} onClick={finishSso}>Continue</button>
        </div>
      </div>
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      if (mode === "register") {
        await post("/auth/register", { email, password, full_name: name, accept_logging_policy: consent });
      }
      await login(email, password, totp || undefined);
      await onDone();
    } catch (x) {
      if (x instanceof ApiError && x.message === "mfa_required") setNeedMfa(true);
      else setErr(x instanceof Error ? x.message : String(x));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="auth card" onSubmit={submit}>
      <div className="logo" style={{ padding: 0 }}>Beyond<span>VPN</span></div>
      <h1>{mode === "login" ? "Sign in" : "Create account"}</h1>
      {mode === "register" && (
        <>
          <label htmlFor="n">Full name</label>
          <input id="n" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" />
        </>
      )}
      <label htmlFor="e">Email</label>
      <input id="e" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
      <label htmlFor="p">Password</label>
      <input id="p" type="password" required minLength={mode === "register" ? 10 : 1} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete={mode === "login" ? "current-password" : "new-password"} />
      {mode === "register" && <div className="muted" style={{ fontSize: 12 }}>At least 10 characters with a letter and a digit.</div>}
      {needMfa && (
        <>
          <label htmlFor="t">Authenticator code</label>
          <input id="t" inputMode="numeric" autoComplete="one-time-code" value={totp} onChange={(e) => setTotp(e.target.value)} autoFocus />
        </>
      )}
      {mode === "register" && (
        <label style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
          <input type="checkbox" style={{ width: "auto", marginTop: 4 }} checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>{LOGGING_NOTICE}</span>
        </label>
      )}
      <Err e={err} />
      <div className="row" style={{ marginTop: 14 }}>
        <button className="btn" disabled={busy}>{mode === "login" ? "Sign in" : "Create account"}</button>
        <button type="button" className="btn ghost" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Create account" : "I have an account"}
        </button>
      </div>
      {mode === "login" && providers.length > 0 && (
        <div style={{ marginTop: 18 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Or use your organisation account</div>
          {providers.map((p) => (
            <a key={p.id} className="btn ghost" style={{ display: "block", textAlign: "center", marginTop: 6 }} href={ssoStartUrl(p.id)}>
              Sign in with {p.name}
            </a>
          ))}
        </div>
      )}
    </form>
  );
}

function Dashboard({ me }: { me: Me }) {
  const usage = useLoad(() => api<{ days: { day: string; rx_bytes: number; tx_bytes: number }[]; month_total_bytes: number; data_cap_bytes: number | null }>("/me/usage?days=30"));
  const sessions = useLoad(() => api<{ id: string; server_id: string; kind: string; started_at: string; ended_at: string | null; rx_bytes: number; tx_bytes: number }[]>("/me/sessions?limit=10"));
  const days = usage.data?.days ?? [];
  const max = Math.max(1, ...days.map((d) => d.rx_bytes + d.tx_bytes));
  const active = sessions.data?.filter((s) => !s.ended_at) ?? [];
  return (
    <>
      <h1>Welcome{me.full_name ? `, ${me.full_name}` : ""}</h1>
      <div className="grid">
        <div className="card stat"><div className="k">Status</div><div className="v">{active.length ? "Protected" : "Not connected"}</div></div>
        <div className="card stat"><div className="k">Data this month</div><div className="v">{formatBytes(usage.data?.month_total_bytes)}</div></div>
        <div className="card stat"><div className="k">Monthly cap</div><div className="v">{usage.data?.data_cap_bytes ? formatBytes(usage.data.data_cap_bytes) : "Unlimited"}</div></div>
      </div>
      <div className="card">
        <h2>Daily usage (30 days)</h2>
        <Err e={usage.error} />
        {days.length === 0 ? <p className="muted">No traffic yet. Install an app from the Devices page and connect.</p> : (
          <div className="chart" role="img" aria-label="Daily data usage">
            {days.map((d) => <div key={d.day} title={`${d.day}: ${formatBytes(d.rx_bytes + d.tx_bytes)}`} style={{ height: `${((d.rx_bytes + d.tx_bytes) / max) * 100}%` }} />)}
          </div>
        )}
      </div>
      <div className="card">
        <h2>Recent sessions</h2>
        <div className="tablewrap"><table>
          <thead><tr><th>Server</th><th>Type</th><th>Started</th><th>Ended</th><th>Down</th><th>Up</th></tr></thead>
          <tbody>{sessions.data?.map((s) => (
            <tr key={s.id}><td>{s.server_id}</td><td>{s.kind}</td><td>{new Date(s.started_at + "Z").toLocaleString()}</td><td>{s.ended_at ? new Date(s.ended_at + "Z").toLocaleString() : <span className="pill ok">active</span>}</td><td>{formatBytes(s.rx_bytes)}</td><td>{formatBytes(s.tx_bytes)}</td></tr>
          ))}</tbody>
        </table></div>
      </div>
    </>
  );
}

function Servers() {
  const { data, error } = useLoad(() => api<Server[]>("/servers"));
  return (
    <>
      <h1>Servers</h1>
      <Err e={error} />
      <div className="card tablewrap"><table>
        <thead><tr><th>Location</th><th>Name</th><th>Load</th><th>Features</th><th>Status</th></tr></thead>
        <tbody>{data?.map((s) => (
          <tr key={s.id}>
            <td>{flag(s.country)} {s.city || s.country}</td><td>{s.name}<div className="muted" style={{ fontSize: 12 }}>{s.hostname}</div></td>
            <td><div className="bar"><i style={{ width: `${Math.round(s.load * 100)}%` }} /></div><span className="muted" style={{ fontSize: 12 }}>{Math.round(s.load * 100)}%</span></td>
            <td>{s.features.map((f) => <span key={f} className="pill" style={{ marginRight: 4 }}>{f}</span>)}</td><td><Status s={s.status} /></td>
          </tr>
        ))}</tbody>
      </table></div>
    </>
  );
}

interface Device { id: string; name: string; platform: string; revoked: boolean; created_at: string; last_seen_at: string | null }

function Devices() {
  const devices = useLoad(() => api<Device[]>("/devices"));
  const servers = useLoad(() => api<Server[]>("/servers"));
  const [name, setName] = useState("My phone");
  const [platform, setPlatform] = useState("ios");
  const [server, setServer] = useState("");
  const [conf, setConf] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const online = servers.data?.filter((s) => s.status === "online") ?? [];

  const create = async () => {
    setErr(null);
    setConf(null);
    try {
      const kp = generateWgKeypair(); // private key generated and kept in this tab only
      const dev = await post<{ id: string }>("/devices", { name, platform, public_key: kp.publicKey, posture: { os: platform, source: "web-portal" } });
      const c = await post<ConnectResponse>("/sessions/connect", { device_id: dev.id, server_id: server || online[0]?.id });
      const text = buildWgConfig(kp.privateKey, c);
      setConf(text);
      setQr(await QRCode.toDataURL(text, { errorCorrectionLevel: "M", margin: 1, width: 260 }));
      devices.reload();
    } catch (x) {
      setErr(x instanceof Error ? x.message : String(x));
    }
  };

  const download = () => {
    if (!conf) return;
    const url = URL.createObjectURL(new Blob([conf], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyondvpn-${name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.conf`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <h1>Devices</h1>
      <div className="card">
        <h2>Get the app</h2>
        <p className="muted">Windows / macOS / Linux: Beyond VPN desktop app. Android: Beyond VPN app. Chrome / Edge / Firefox: Beyond VPN extension.
          iPhone, iPad, routers and anything else: add a device below and import the config into the official WireGuard app.</p>
      </div>
      <div className="card">
        <h2>Add a device (WireGuard config)</h2>
        <div className="grid">
          <div><label htmlFor="dn">Device name</label><input id="dn" value={name} maxLength={80} onChange={(e) => setName(e.target.value)} /></div>
          <div><label htmlFor="dp">Platform</label>
            <select id="dp" value={platform} onChange={(e) => setPlatform(e.target.value)}>
              {["ios", "macos", "windows", "linux", "android", "other"].map((p) => <option key={p}>{p}</option>)}
            </select></div>
          <div><label htmlFor="ds">Server</label>
            <select id="ds" value={server} onChange={(e) => setServer(e.target.value)}>
              <option value="">Fastest available</option>
              {online.map((s) => <option key={s.id} value={s.id}>{flag(s.country)} {s.name}</option>)}
            </select></div>
        </div>
        <div className="row" style={{ marginTop: 12 }}><button className="btn" onClick={create} disabled={!online.length}>Generate config</button>
          {!online.length && <span className="muted">No servers online.</span>}</div>
        <Err e={err} />
        {conf && (
          <div className="row" style={{ alignItems: "flex-start", marginTop: 14 }}>
            {qr && <img src={qr} alt="WireGuard configuration QR code" width={260} height={260} />}
            <div style={{ flex: 1, minWidth: 260 }}>
              <p><strong>Scan with the WireGuard app</strong> or download the file. This key is shown once and is not stored by Beyond VPN.</p>
              <button className="btn" onClick={download}>Download .conf</button>
              <pre className="conf">{conf}</pre>
            </div>
          </div>
        )}
      </div>
      <div className="card tablewrap">
        <h2>Your devices</h2>
        <Err e={devices.error} />
        <table><thead><tr><th>Name</th><th>Platform</th><th>Added</th><th>Last seen</th><th /></tr></thead>
          <tbody>{devices.data?.map((d) => (
            <tr key={d.id}><td>{d.name}</td><td>{d.platform}</td><td>{new Date(d.created_at + "Z").toLocaleDateString()}</td>
              <td>{d.last_seen_at ? new Date(d.last_seen_at + "Z").toLocaleString() : "—"}</td>
              <td>{d.revoked ? <span className="pill bad">revoked</span> : <button className="btn ghost" onClick={() => confirm(`Revoke ${d.name}? It will be disconnected immediately.`) && del(`/devices/${d.id}`).then(devices.reload)}>Revoke</button>}</td></tr>
          ))}</tbody></table>
      </div>
    </>
  );
}

function Activity() {
  const { data, error } = useLoad(() => api<{ dns: { ts: string; domain: string; qtype: string; blocked: boolean; server_id: string }[]; web: { ts: string; host: string; port: number; bytes_down: number; bytes_up: number; blocked: boolean }[] }>("/me/activity?limit=300"));
  return (
    <>
      <h1>My activity</h1>
      <p className="muted">Transparency: this is everything recorded about your browsing while connected. Records are deleted automatically after the retention period.</p>
      <Err e={error} />
      <div className="card tablewrap"><h2>Websites (browser extension)</h2><table>
        <thead><tr><th>Time</th><th>Host</th><th>Down</th><th>Up</th><th /></tr></thead>
        <tbody>{data?.web.map((w, i) => <tr key={i}><td>{new Date(w.ts + "Z").toLocaleString()}</td><td>{w.host}:{w.port}</td><td>{formatBytes(w.bytes_down)}</td><td>{formatBytes(w.bytes_up)}</td><td>{w.blocked && <span className="pill bad">blocked</span>}</td></tr>)}</tbody>
      </table></div>
      <div className="card tablewrap"><h2>DNS lookups (apps)</h2><table>
        <thead><tr><th>Time</th><th>Domain</th><th>Type</th><th>Server</th><th /></tr></thead>
        <tbody>{data?.dns.map((d, i) => <tr key={i}><td>{new Date(d.ts + "Z").toLocaleString()}</td><td>{d.domain}</td><td>{d.qtype}</td><td>{d.server_id}</td><td>{d.blocked && <span className="pill bad">blocked</span>}</td></tr>)}</tbody>
      </table></div>
    </>
  );
}

function Security({ me, reload, onErased }: { me: Me; reload: () => Promise<void>; onErased: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const run = (f: () => Promise<unknown>) => () => {
    setErr(null);
    f().catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  };
  return (
    <>
      <h1>Security</h1>
      <div className="card">
        <h2>Two-factor authentication</h2>
        <p>Status: {me.mfa_enabled ? <span className="pill ok">enabled</span> : <span className="pill warn">disabled</span>}</p>
        {!me.mfa_enabled && !setup && <button className="btn" onClick={run(async () => {
          const s = await post<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup");
          setSetup(s);
          setQr(await QRCode.toDataURL(s.otpauth_uri, { margin: 1, width: 200 }));
        })}>Set up authenticator</button>}
        {setup && !me.mfa_enabled && (
          <div className="row" style={{ alignItems: "flex-start" }}>
            {qr && <img src={qr} alt="Authenticator QR code" width={200} height={200} />}
            <div><p>Scan with Google Authenticator, Authy, 1Password…<br /><span className="muted">Manual key: {setup.secret}</span></p>
              <label htmlFor="c">6-digit code</label><input id="c" inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value)} />
              <button className="btn" style={{ marginTop: 8 }} onClick={run(async () => { await post("/auth/mfa/enable", { code }); setSetup(null); await reload(); })}>Enable</button></div>
          </div>
        )}
        {me.mfa_enabled && (
          <div className="row"><input style={{ maxWidth: 160 }} placeholder="Current code" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className="btn ghost" onClick={run(async () => { await post("/auth/mfa/disable", { code }); await reload(); })}>Disable 2FA</button></div>
        )}
      </div>
      <div className="card">
        <h2>Delete account</h2>
        <p className="muted">Permanently deletes your account, devices, usage and activity logs. This cannot be undone.</p>
        <div className="row"><input type="password" style={{ maxWidth: 240 }} placeholder="Confirm password" value={pw} onChange={(e) => setPw(e.target.value)} />
          <button className="btn danger" disabled={!pw} onClick={run(async () => {
            if (!confirm("Delete your Beyond VPN account permanently?")) return;
            await post("/me/erase", { password: pw });
            await logout();
            onErased();
          })}>Delete my account</button></div>
      </div>
      <Err e={err} />
    </>
  );
}
