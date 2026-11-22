// Single sign-on helpers for the desktop app (pure, unit-tested).
//
// Flow: the app opens the system browser at
//   <server>/api/v1/auth/sso/<provider>/start?return_to=beyondvpn://sso?n=<nonce>
// The control plane sends the browser back to beyondvpn://sso?n=<nonce>&sso_code=<code>; Windows /
// macOS hand that link to this app, which checks the nonce (so a web page cannot push a login
// into the app) and gives the code to the local agent, which trades it for tokens.
"use strict";

const crypto = require("node:crypto");

const SCHEME = "beyondvpn";
const PENDING_TTL_MS = 10 * 60 * 1000;

/** Normalised https:// server URL (http only for localhost), or throws. */
function serverUrl(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    throw new Error("Enter the server URL, e.g. https://vpn.example.com");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("Server URL must start with https://");
  if (u.username || u.password) throw new Error("Server URL must not contain credentials");
  return `${u.protocol}//${u.host}`;
}

function newNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function providerId(id) {
  const s = String(id);
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(s)) throw new Error("bad provider id");
  return s;
}

function startUrl(server, provider, nonce) {
  const back = `${SCHEME}://sso?n=${nonce}`;
  return `${serverUrl(server)}/api/v1/auth/sso/${encodeURIComponent(providerId(provider))}/start?return_to=${encodeURIComponent(back)}`;
}

/** Parse a beyondvpn://sso link; accepts the result in the query or the fragment. */
function parseCallback(link) {
  let u;
  try {
    u = new URL(String(link));
  } catch {
    return null;
  }
  if (u.protocol !== `${SCHEME}:` || (u.hostname || u.pathname.replace(/^\/+/, "")) !== "sso") return null;
  const q = new URLSearchParams(u.search);
  const h = new URLSearchParams(u.hash.replace(/^#/, ""));
  const get = (k) => q.get(k) ?? h.get(k);
  return { nonce: get("n"), code: get("sso_code"), error: get("sso_error") };
}

/** Find our link among process arguments (Windows/Linux deliver it on the command line). */
function linkFromArgv(argv) {
  return (argv || []).find((a) => typeof a === "string" && a.toLowerCase().startsWith(`${SCHEME}://`)) || null;
}

/** Decide what to do with a callback given the pending sign-in (or why it is rejected). */
function accept(pending, cb, now = Date.now()) {
  if (!cb) return { ok: false, reason: "not an SSO link" };
  if (!pending) return { ok: false, reason: "no sign-in was started from this app" };
  if (now - pending.started > PENDING_TTL_MS) return { ok: false, reason: "sign-in took too long; start again" };
  const a = Buffer.from(String(cb.nonce || ""));
  const b = Buffer.from(String(pending.nonce));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: "sign-in link does not belong to this sign-in" };
  }
  if (cb.error) return { ok: false, reason: `Single sign-on failed: ${cb.error}` };
  if (!cb.code || !/^[A-Za-z0-9_-]{10,128}$/.test(cb.code)) return { ok: false, reason: "sign-in link has no valid code" };
  return { ok: true, code: cb.code };
}

module.exports = { SCHEME, serverUrl, newNonce, startUrl, parseCallback, linkFromArgv, accept, PENDING_TTL_MS };
