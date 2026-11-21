// Pure logic for the Beyond VPN extension (unit-tested with `node --test`).

/** Validate the control-plane URL: https only, except loopback for development. */
export function normalizeApiUrl(input) {
  let u;
  try {
    u = new URL(String(input).trim());
  } catch {
    throw new Error("Enter a valid server URL, e.g. https://vpn.example.com");
  }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !(u.protocol === "http:" && loopback)) {
    throw new Error("The server URL must use https://");
  }
  if (u.username || u.password) throw new Error("Credentials in URL are not allowed");
  return `${u.protocol}//${u.host}`;
}

const DOMAIN_RE = /^(\*\.)?([a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$/;

/** Hosts that must never go through the proxy. */
export function buildBypassList(apiUrl, userBypass = [], allowLan = true) {
  const list = ["localhost", "127.0.0.1", "[::1]", "<local>"];
  if (allowLan) list.push("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16");
  // The control plane is bypassed so token refresh still works if a gateway is down.
  if (apiUrl) list.push(new URL(apiUrl).hostname);
  for (const raw of userBypass) {
    const d = String(raw).trim().toLowerCase().replace(/\.$/, "");
    if (d && DOMAIN_RE.test(d)) {
      list.push(d);
      if (!d.startsWith("*.")) list.push(`*.${d}`);
    }
  }
  return Array.from(new Set(list));
}

/** chrome.proxy fixed_servers config. No DIRECT fallback => fails closed (browser kill switch). */
export function chromeProxyConfig(host, port, bypassList) {
  if (!/^[a-z0-9.-]+$/i.test(host) || !(port > 0 && port < 65536)) throw new Error("invalid proxy endpoint");
  return {
    mode: "fixed_servers",
    rules: { singleProxy: { scheme: "https", host, port }, bypassList },
  };
}

/** Firefox proxy.onRequest result for a URL. */
export function firefoxProxyFor(url, conn, bypassList) {
  if (!conn) return { type: "direct" };
  let host;
  try {
    host = new URL(url).hostname;
  } catch {
    return { type: "direct" };
  }
  if (matchesBypass(host, bypassList)) return { type: "direct" };
  return { type: "https", host: conn.host, port: conn.port, proxyAuthorizationHeader: `Bearer ${conn.token}`, failoverTimeout: 5 };
}

function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

export function matchesBypass(host, bypassList) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  for (const rule of bypassList) {
    if (rule === "<local>") {
      if (!h.includes(".") && !h.includes(":")) return true;
      continue;
    }
    if (rule.includes("/")) {
      const [net, bits] = rule.split("/");
      const a = ipv4ToInt(h);
      const b = ipv4ToInt(net);
      if (a === null || b === null) continue;
      const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0;
      if ((a & mask) >>> 0 === (b & mask) >>> 0) return true;
      continue;
    }
    if (rule.startsWith("*.")) {
      if (h.endsWith(rule.slice(1))) return true;
      continue;
    }
    if (h === rule.replace(/^\[|\]$/g, "")) return true;
  }
  return false;
}

/** True when the proxy token should be refreshed (5 minutes before expiry). */
export function needsRefresh(expiresAt, nowSec = Math.floor(Date.now() / 1000), marginSec = 300) {
  return !expiresAt || expiresAt - nowSec <= marginSec;
}

export function pickFastest(servers) {
  const online = servers.filter((s) => s.status === "online");
  online.sort((a, b) => a.load - b.load);
  return online[0] ?? null;
}

export function flag(country) {
  if (!/^[A-Z]{2}$/.test(country)) return "🌐";
  return String.fromCodePoint(...[...country].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
