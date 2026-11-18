// Pure helpers shared by the web portal (unit-tested with vitest).
import nacl from "tweetnacl";

export function formatBytes(n: number | null | undefined): string {
  if (n == null || !isFinite(n)) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function toB64(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}

/** Curve25519 keypair generated in the browser. The private key never leaves the page. */
export function generateWgKeypair(): { privateKey: string; publicKey: string } {
  const kp = nacl.box.keyPair(); // X25519, same curve as WireGuard
  return { privateKey: toB64(kp.secretKey), publicKey: toB64(kp.publicKey) };
}

export function publicFromPrivate(privB64: string): string {
  const raw = Uint8Array.from(atob(privB64), (c) => c.charCodeAt(0));
  return toB64(nacl.scalarMult.base(raw));
}

export interface ConnectResponse {
  session_id: string;
  address: string;
  dns: string[];
  mtu: number;
  peer_public_key: string;
  preshared_key: string;
  endpoint: string;
  allowed_ips: string[];
  persistent_keepalive: number;
}

const SAFE = /^[A-Za-z0-9.:\-_[\]/+=]+$/;

/** Render a WireGuard config (mirror of core/crates/beyond-common/src/wgconf.rs). */
export function buildWgConfig(privateKey: string, c: ConnectResponse): string {
  const fields = [privateKey, c.address, c.peer_public_key, c.preshared_key, c.endpoint, ...c.dns, ...c.allowed_ips];
  if (!fields.every((f) => SAFE.test(f))) throw new Error("server returned an unsafe config value");
  return [
    "# Beyond VPN — keep this file private, it contains your device key.",
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${c.address}`,
    c.dns.length ? `DNS = ${c.dns.join(", ")}` : "",
    `MTU = ${c.mtu}`,
    "",
    "[Peer]",
    `PublicKey = ${c.peer_public_key}`,
    `PresharedKey = ${c.preshared_key}`,
    `AllowedIPs = ${c.allowed_ips.join(", ")}`,
    `Endpoint = ${c.endpoint}`,
    `PersistentKeepalive = ${c.persistent_keepalive}`,
    "",
  ]
    .filter((l, i, a) => !(l === "" && a[i - 1] === ""))
    .join("\n");
}

export function flag(country: string): string {
  if (!/^[A-Z]{2}$/.test(country)) return "🌐";
  return String.fromCodePoint(...[...country].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

export function parseDomains(text: string): string[] {
  return Array.from(
    new Set(
      text
        .split(/[\s,]+/)
        .map((d) => d.trim().toLowerCase().replace(/\.$/, ""))
        .filter((d) => d.length > 0),
    ),
  ).sort();
}
