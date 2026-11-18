// Beyond VPN extension service worker (Chrome/Edge MV3; Firefox via background script).
import { buildBypassList, chromeProxyConfig, firefoxProxyFor, needsRefresh, normalizeApiUrl, pickFastest } from "./lib.js";

const B = globalThis.browser ?? globalThis.chrome;
const IS_FIREFOX = typeof globalThis.browser !== "undefined" && !!B.proxy?.onRequest;

// Access token lives in session storage (memory, cleared on browser exit);
// the refresh token in local storage so the user stays signed in.
const local = B.storage.local;
const session = B.storage.session ?? B.storage.local;

let conn = null; // { host, port, token, expires_at, server_id, server_name }
let bypass = [];
const authAttempts = new Map();

async function getState() {
  const l = await local.get(["apiUrl", "refreshToken", "email", "settings", "lastServer"]);
  const s = await session.get(["accessToken", "conn"]);
  return { ...l, ...s, settings: { allowLan: true, bypassDomains: [], blockWebRtc: true, ...(l.settings ?? {}) } };
}

async function call(path, { method = "GET", body, auth = true } = {}) {
  const st = await getState();
  if (!st.apiUrl) throw new Error("Not signed in");
  const doFetch = async (token) =>
    fetch(`${st.apiUrl}/api/v1${path}`, {
      method,
      credentials: "omit",
      headers: { "Content-Type": "application/json", ...(auth && token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  let r = await doFetch(st.accessToken);
  if (r.status === 401 && auth && st.refreshToken) {
    const ref = await fetch(`${st.apiUrl}/api/v1/auth/refresh`, {
      method: "POST",
      credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: st.refreshToken }),
    });
    if (ref.ok) {
      const t = await ref.json();
      await session.set({ accessToken: t.access_token });
      await local.set({ refreshToken: t.refresh_token });
      r = await doFetch(t.access_token);
    } else {
      await signOutLocal();
      throw new Error("Session expired, please sign in again");
    }
  }
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error((data && typeof data.detail === "string" && data.detail) || `HTTP ${r.status}`);
  return data;
}

async function applyProxy() {
  const st = await getState();
  bypass = buildBypassList(st.apiUrl, st.settings.bypassDomains, st.settings.allowLan);
  if (IS_FIREFOX) {
    // Firefox consults onRequest per request; nothing else to set.
  } else if (conn) {
    await B.proxy.settings.set({ value: chromeProxyConfig(conn.host, conn.port, bypass), scope: "regular" });
  } else {
    await B.proxy.settings.clear({ scope: "regular" });
  }
  if (B.privacy?.network?.webRTCIPHandlingPolicy) {
    // Prevent WebRTC from revealing the real IP while connected.
    if (conn && st.settings.blockWebRtc) await B.privacy.network.webRTCIPHandlingPolicy.set({ value: "disable_non_proxied_udp" });
    else await B.privacy.network.webRTCIPHandlingPolicy.clear({});
  }
  await B.action.setBadgeText({ text: conn ? "ON" : "" });
  if (conn) await B.action.setBadgeBackgroundColor({ color: "#4f46e5" });
}

async function connect(serverId) {
  const servers = await call("/servers");
  const target = serverId ? servers.find((s) => s.id === serverId) : pickFastest(servers);
  if (!target) throw new Error("No server available");
  const t = await call("/proxy/token", { method: "POST", body: { server_id: target.id } });
  conn = { host: t.host, port: t.port, token: t.token, expires_at: t.expires_at, server_id: target.id, server_name: target.name, country: target.country };
  await session.set({ conn });
  await local.set({ lastServer: target.id });
  await applyProxy();
  return conn;
}

async function disconnect() {
  conn = null;
  await session.remove("conn");
  await applyProxy();
  await call("/proxy/disconnect", { method: "POST" }).catch(() => undefined);
}

async function signOutLocal() {
  conn = null;
  await session.remove(["accessToken", "conn"]);
  await local.remove(["refreshToken"]);
  await applyProxy();
}

async function refreshProxyToken() {
  if (!conn || !needsRefresh(conn.expires_at)) return;
  try {
    const t = await call("/proxy/token", { method: "POST", body: { server_id: conn.server_id } });
    conn = { ...conn, token: t.token, expires_at: t.expires_at };
    await session.set({ conn });
  } catch (e) {
    console.warn("Beyond VPN: token refresh failed", e);
  }
}

// Answer the proxy's 407 challenge with the short-lived token (Chrome).
if (!IS_FIREFOX && B.webRequest?.onAuthRequired) {
  B.webRequest.onAuthRequired.addListener(
    (details, callback) => {
      if (!details.isProxy || !conn || details.challenger?.host !== conn.host) return callback({});
      const n = (authAttempts.get(details.requestId) ?? 0) + 1;
      authAttempts.set(details.requestId, n);
      if (n > 2) return callback({ cancel: true }); // avoid auth loops on revoked tokens
      callback({ authCredentials: { username: "beyond", password: conn.token } });
    },
    { urls: ["<all_urls>"] },
    ["asyncBlocking"],
  );
  B.webRequest.onCompleted.addListener((d) => authAttempts.delete(d.requestId), { urls: ["<all_urls>"] });
  B.webRequest.onErrorOccurred.addListener((d) => authAttempts.delete(d.requestId), { urls: ["<all_urls>"] });
}

if (IS_FIREFOX) {
  B.proxy.onRequest.addListener((req) => firefoxProxyFor(req.url, conn, bypass), { urls: ["<all_urls>"] });
}

B.alarms.create("beyond-refresh", { periodInMinutes: 1 });
B.alarms.onAlarm.addListener((a) => a.name === "beyond-refresh" && refreshProxyToken());

// Restore state when the service worker restarts.
(async () => {
  const s = await session.get(["conn"]);
  conn = s.conn ?? null;
  await applyProxy();
})();

B.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== B.runtime.id) return false; // only our own popup
  (async () => {
    switch (msg?.type) {
      case "state": {
        const st = await getState();
        return { signedIn: !!st.refreshToken, email: st.email, apiUrl: st.apiUrl, conn, settings: st.settings, lastServer: st.lastServer };
      }
      case "login": {
        const apiUrl = normalizeApiUrl(msg.apiUrl);
        const r = await fetch(`${apiUrl}/api/v1/auth/login`, {
          method: "POST",
          credentials: "omit",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: msg.email, password: msg.password, totp_code: msg.totp || null }),
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail === "mfa_required" ? "mfa_required" : data.detail || "Sign-in failed");
        await local.set({ apiUrl, email: msg.email, refreshToken: data.refresh_token });
        await session.set({ accessToken: data.access_token });
        return { ok: true };
      }
      case "logout": {
        const st = await getState();
        await disconnect().catch(() => undefined);
        if (st.refreshToken) await call("/auth/logout", { method: "POST", body: { refresh_token: st.refreshToken }, auth: false }).catch(() => undefined);
        await signOutLocal();
        return { ok: true };
      }
      case "servers":
        return call("/servers");
      case "connect":
        return connect(msg.serverId);
      case "disconnect":
        await disconnect();
        return { ok: true };
      case "settings": {
        const st = await getState();
        await local.set({ settings: { ...st.settings, ...msg.settings } });
        await applyProxy();
        return { ok: true };
      }
      case "usage":
        return call("/me/usage?days=30");
      default:
        throw new Error("unknown message");
    }
  })().then(
    (data) => sendResponse({ ok: true, data }),
    (e) => sendResponse({ ok: false, error: String(e?.message ?? e) }),
  );
  return true;
});
