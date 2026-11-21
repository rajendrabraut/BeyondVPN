import { useState } from "react";
import { api, apiBlob, patch, post, put } from "./api";
import { Err, Me, Status, useLoad } from "./App";
import { flag, formatBytes, parseDomains } from "./lib";

export const ADMIN_PAGES = ["Overview", "Users", "Gateways", "Policy", "Logs", "Audit"] as const;

export function AdminPages({ page, me }: { page: string; me: Me }) {
  const isAdmin = me.role === "admin";
  switch (page) {
    case "Overview": return <Overview />;
    case "Users": return <Users isAdmin={isAdmin} />;
    case "Gateways": return <Gateways isAdmin={isAdmin} />;
    case "Policy": return <Policy isAdmin={isAdmin} />;
    case "Logs": return <Logs />;
    case "Audit": return <Audit />;
    default: return null;
  }
}

function Overview() {
  const s = useLoad(() => api<Record<string, number>>("/admin/reports/summary"));
  const top = useLoad(() => api<{ domain: string; queries: number; users: number }[]>("/admin/reports/top-domains?hours=168&limit=15"));
  const usage = useLoad(() => api<{ email: string; rx_bytes: number; tx_bytes: number }[]>("/admin/reports/usage?days=30"));
  const d = s.data;
  return (
    <>
      <h1>Overview</h1>
      <Err e={s.error} />
      {d && (
        <div className="grid">
          {([["Users", d.users], ["Active users", d.active_users], ["Devices", d.devices], ["Active sessions", d.active_sessions], ["Gateways online", d.servers_online], ["Blocked (24h)", d.blocked_today]] as const).map(([k, v]) => (
            <div key={k} className="card stat"><div className="k">{k}</div><div className="v">{v}</div></div>
          ))}
          <div className="card stat"><div className="k">Traffic today</div><div className="v">{formatBytes(d.bytes_today)}</div></div>
          <div className="card stat"><div className="k">Traffic this month</div><div className="v">{formatBytes(d.bytes_month)}</div></div>
        </div>
      )}
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
        <div className="card tablewrap"><h2>Top domains (7 days)</h2><table><thead><tr><th>Domain</th><th>Queries</th><th>Users</th></tr></thead>
          <tbody>{top.data?.map((t) => <tr key={t.domain}><td>{t.domain}</td><td>{t.queries}</td><td>{t.users}</td></tr>)}</tbody></table></div>
        <div className="card tablewrap"><h2>Top users by data (30 days)</h2><table><thead><tr><th>User</th><th>Down</th><th>Up</th></tr></thead>
          <tbody>{usage.data?.slice(0, 15).map((u) => <tr key={u.email}><td>{u.email}</td><td>{formatBytes(u.rx_bytes)}</td><td>{formatBytes(u.tx_bytes)}</td></tr>)}</tbody></table></div>
      </div>
    </>
  );
}

interface U { id: string; email: string; role: string; is_active: boolean; mfa_enabled: boolean; data_cap_bytes: number | null; last_login_at: string | null }

function Users({ isAdmin }: { isAdmin: boolean }) {
  const [q, setQ] = useState("");
  const users = useLoad(() => api<U[]>(`/admin/users${q ? `?q=${encodeURIComponent(q)}` : ""}`), [q]);
  const [err, setErr] = useState<string | null>(null);
  const change = (id: string, body: object) => patch(`/admin/users/${id}`, body).then(users.reload, (e) => setErr(e.message));
  return (
    <>
      <h1>Users</h1>
      <input placeholder="Search email…" value={q} onChange={(e) => setQ(e.target.value)} style={{ maxWidth: 320, marginBottom: 12 }} />
      <Err e={users.error ?? err} />
      <div className="card tablewrap"><table>
        <thead><tr><th>Email</th><th>Role</th><th>2FA</th><th>Data cap</th><th>Last login</th><th>Status</th></tr></thead>
        <tbody>{users.data?.map((u) => (
          <tr key={u.id}>
            <td>{u.email}</td>
            <td>{isAdmin ? <select value={u.role} onChange={(e) => change(u.id, { role: e.target.value })}>{["user", "auditor", "admin"].map((r) => <option key={r}>{r}</option>)}</select> : u.role}</td>
            <td>{u.mfa_enabled ? "✔" : "—"}</td>
            <td>{isAdmin ? (
              <select value={u.data_cap_bytes ?? ""} onChange={(e) => change(u.id, e.target.value ? { data_cap_bytes: Number(e.target.value) } : { clear_data_cap: true })}>
                <option value="">Unlimited</option>
                {[10, 50, 100, 500].map((g) => <option key={g} value={g * 1024 ** 3}>{g} GB / month</option>)}
                {u.data_cap_bytes && ![10, 50, 100, 500].some((g) => g * 1024 ** 3 === u.data_cap_bytes) && <option value={u.data_cap_bytes}>{formatBytes(u.data_cap_bytes)}</option>}
              </select>) : formatBytes(u.data_cap_bytes)}</td>
            <td>{u.last_login_at ? new Date(u.last_login_at + "Z").toLocaleString() : "—"}</td>
            <td>{isAdmin ? (
              <button className={`btn ${u.is_active ? "ghost" : ""}`} onClick={() => (u.is_active ? confirm(`Disable ${u.email}? All sessions end immediately.`) : true) && change(u.id, { is_active: !u.is_active })}>{u.is_active ? "Disable" : "Enable"}</button>
            ) : u.is_active ? "active" : "disabled"}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </>
  );
}

interface G { id: string; name: string; country: string; city: string; hostname: string; status: string; load: number; active_peers: number; version: string; enabled: boolean; last_heartbeat_at: string | null }

function Gateways({ isAdmin }: { isAdmin: boolean }) {
  const list = useLoad(() => api<G[]>("/admin/servers"));
  const [form, setForm] = useState({ id: "", name: "", country: "IN", city: "", hostname: "", tunnel_cidr: "10.8.0.0/22", features: "" });
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const create = async () => {
    setErr(null);
    try {
      const r = await post<{ gateway_key: string }>("/admin/servers", { ...form, country: form.country.toUpperCase(), features: form.features.split(",").map((s) => s.trim()).filter(Boolean) });
      setSecret(r.gateway_key);
      list.reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <>
      <h1>Gateways</h1>
      <div className="card tablewrap"><table>
        <thead><tr><th>Gateway</th><th>Host</th><th>Peers</th><th>Load</th><th>Version</th><th>Heartbeat</th><th>Status</th>{isAdmin && <th />}</tr></thead>
        <tbody>{list.data?.map((g) => (
          <tr key={g.id}><td>{flag(g.country)} {g.name}<div className="muted" style={{ fontSize: 12 }}>{g.id}</div></td><td>{g.hostname}</td><td>{g.active_peers}</td><td>{Math.round(g.load * 100)}%</td><td>{g.version || "—"}</td>
            <td>{g.last_heartbeat_at ? new Date(g.last_heartbeat_at + "Z").toLocaleTimeString() : "never"}</td><td><Status s={g.status} /></td>
            {isAdmin && <td><button className="btn ghost" onClick={() => patch(`/admin/servers/${g.id}`, { enabled: !g.enabled }).then(list.reload)}>{g.enabled ? "Maintenance" : "Enable"}</button></td>}</tr>
        ))}</tbody>
      </table></div>
      {isAdmin && (
        <div className="card">
          <h2>Add gateway</h2>
          <div className="grid">
            {(["id", "name", "country", "city", "hostname", "tunnel_cidr", "features"] as const).map((k) => (
              <div key={k}><label htmlFor={`g-${k}`}>{k.replace("_", " ")}</label><input id={`g-${k}`} value={form[k]} onChange={(e) => setForm({ ...form, [k]: e.target.value })} placeholder={k === "features" ? "p2p,streaming" : ""} /></div>
            ))}
          </div>
          <button className="btn" style={{ marginTop: 12 }} onClick={create}>Create</button>
          <Err e={err} />
          {secret && <div className="card" style={{ marginTop: 12 }}><strong>Gateway key (shown once):</strong><pre className="conf">BEYOND_GATEWAY_KEY={secret}</pre><span className="muted">Put it in the gateway's environment, then run deploy/gateway/install-gateway.sh.</span></div>}
        </div>
      )}
    </>
  );
}

interface P { logging_mode: string; blocked_domains: string[]; kill_switch_required: boolean; split_tunnel_allowed: boolean; require_device_posture: boolean; max_devices_per_user: number; allowed_platforms: string[] }

function Policy({ isAdmin }: { isAdmin: boolean }) {
  const pol = useLoad(() => api<P>("/admin/policy"));
  const [draft, setDraft] = useState<P | null>(null);
  const [domains, setDomains] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const p = draft ?? pol.data;
  if (!p) return <Err e={pol.error} />;
  const set = <K extends keyof P>(k: K, v: P[K]) => setDraft({ ...p, [k]: v });
  const save = async () => {
    setErr(null);
    try {
      const body = { ...p, blocked_domains: domains === null ? p.blocked_domains : parseDomains(domains) };
      const r = await put<P>("/admin/policy", body);
      setDraft(r);
      setDomains(null);
      setMsg("Saved. Gateways apply changes within ~10 seconds.");
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };
  return (
    <>
      <h1>Policy</h1>
      <div className="card">
        <h2>Activity logging</h2>
        <select disabled={!isAdmin} value={p.logging_mode} onChange={(e) => set("logging_mode", e.target.value)} style={{ maxWidth: 420 }}>
          <option value="full">Full — usage + domains/websites visited</option>
          <option value="metadata">Metadata — usage only (no destinations)</option>
          <option value="off">Off — usage metering only</option>
        </select>
        <p className="muted">Changing this affects legal obligations (consent, retention). See GUARDRAILS.md.</p>
      </div>
      <div className="card">
        <h2>Connection rules</h2>
        {([["kill_switch_required", "Force kill switch on all desktop clients"], ["split_tunnel_allowed", "Allow split tunnelling / LAN access"], ["require_device_posture", "Require healthy device posture (firewall on, not rooted)"]] as const).map(([k, label]) => (
          <label key={k} style={{ display: "flex", gap: 8 }}><input type="checkbox" disabled={!isAdmin} style={{ width: "auto" }} checked={p[k]} onChange={(e) => set(k, e.target.checked)} /> {label}</label>
        ))}
        <label htmlFor="md">Max devices per user</label>
        <input id="md" type="number" min={1} max={1000} disabled={!isAdmin} value={p.max_devices_per_user} onChange={(e) => set("max_devices_per_user", Number(e.target.value))} style={{ maxWidth: 120 }} />
      </div>
      <div className="card">
        <h2>Blocked domains (NetShield)</h2>
        <p className="muted">One domain per line. Sub-domains are blocked too. Applies to DNS (all apps) and the browser proxy.</p>
        <textarea disabled={!isAdmin} value={domains ?? p.blocked_domains.join("\n")} onChange={(e) => setDomains(e.target.value)} />
      </div>
      {isAdmin && <button className="btn" onClick={save}>Save policy</button>}
      {msg && <p className="muted">{msg}</p>}
      <Err e={err} />
    </>
  );
}

function Logs() {
  const [kind, setKind] = useState<"dns" | "web">("dns");
  const [filter, setFilter] = useState("");
  const [hours, setHours] = useState(24);
  const q = kind === "dns" ? `domain=${encodeURIComponent(filter)}` : `host=${encodeURIComponent(filter)}`;
  const logs = useLoad(() => api<Record<string, string | number | boolean | null>[]>(`/admin/logs/${kind}?hours=${hours}&limit=500&${q}`), [kind, filter, hours]);
  const exportCsv = async () => {
    const b = await apiBlob(`/admin/logs/export.csv?kind=${kind}&hours=${hours}`);
    const url = URL.createObjectURL(b);
    const a = document.createElement("a");
    a.href = url;
    a.download = `beyond-${kind}-logs.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <>
      <h1>Activity logs</h1>
      <p className="muted">Every view and export of these logs is recorded in the audit trail.</p>
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={kind} onChange={(e) => setKind(e.target.value as "dns" | "web")} style={{ maxWidth: 160 }}><option value="dns">DNS (all apps)</option><option value="web">Web (extension)</option></select>
        <input placeholder={kind === "dns" ? "Filter domain…" : "Filter host…"} value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 260 }} />
        <select value={hours} onChange={(e) => setHours(Number(e.target.value))} style={{ maxWidth: 140 }}>{[1, 24, 168, 720].map((h) => <option key={h} value={h}>{h < 48 ? `${h} h` : `${h / 24} days`}</option>)}</select>
        <button className="btn ghost" onClick={exportCsv}>Export CSV</button>
      </div>
      <Err e={logs.error} />
      <div className="card tablewrap"><table>
        <thead>{kind === "dns" ? <tr><th>Time</th><th>User</th><th>Domain</th><th>Type</th><th>Gateway</th><th /></tr> : <tr><th>Time</th><th>User</th><th>Host</th><th>Down</th><th>Up</th><th>Duration</th><th /></tr>}</thead>
        <tbody>{logs.data?.map((l, i) => kind === "dns" ? (
          <tr key={i}><td>{new Date(String(l.ts) + "Z").toLocaleString()}</td><td>{l.email ?? l.client_ip}</td><td>{l.domain}</td><td>{l.qtype}</td><td>{l.server_id}</td><td>{l.blocked && <span className="pill bad">blocked</span>}</td></tr>
        ) : (
          <tr key={i}><td>{new Date(String(l.ts) + "Z").toLocaleString()}</td><td>{l.email}</td><td>{l.host}:{l.port}</td><td>{formatBytes(Number(l.bytes_down))}</td><td>{formatBytes(Number(l.bytes_up))}</td><td>{(Number(l.duration_ms) / 1000).toFixed(1)} s</td><td>{l.blocked && <span className="pill bad">blocked</span>}</td></tr>
        ))}</tbody>
      </table></div>
    </>
  );
}

function Audit() {
  const ev = useLoad(() => api<{ id: number; ts: string; actor: string; action: string; target: string; ip: string; detail: object }[]>("/admin/audit?limit=300"));
  const [verify, setVerify] = useState<{ ok: boolean; first_bad_id: number | null } | null>(null);
  return (
    <>
      <h1>Audit trail</h1>
      <div className="row" style={{ marginBottom: 12 }}>
        <button className="btn ghost" onClick={() => api<{ ok: boolean; first_bad_id: number | null }>("/admin/audit/verify").then(setVerify)}>Verify hash chain</button>
        {verify && (verify.ok ? <span className="pill ok">chain intact</span> : <span className="pill bad">tampering detected at #{verify.first_bad_id}</span>)}
      </div>
      <Err e={ev.error} />
      <div className="card tablewrap"><table>
        <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>IP</th><th>Detail</th></tr></thead>
        <tbody>{ev.data?.map((a) => <tr key={a.id}><td>{a.id}</td><td>{new Date(a.ts + "Z").toLocaleString()}</td><td>{a.actor.slice(0, 8)}</td><td>{a.action}</td><td>{a.target}</td><td>{a.ip}</td><td><code style={{ fontSize: 12 }}>{JSON.stringify(a.detail)}</code></td></tr>)}</tbody>
      </table></div>
    </>
  );
}
