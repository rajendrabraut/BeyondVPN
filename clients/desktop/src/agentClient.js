// Talks to the local beyond-agent daemon (127.0.0.1 only, bearer token from the agent dir).
// Runs in the Electron main process; the renderer never sees the token.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const DEFAULT_PORT = 47800;

function agentDir(env = process.env, platform = process.platform) {
  if (env.BEYOND_AGENT_DIR) return env.BEYOND_AGENT_DIR;
  if (platform === "win32") return path.join(env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"), "BeyondVPN");
  if (platform === "darwin") return path.join(os.homedir(), "Library", "Application Support", "BeyondVPN");
  return path.join(env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "BeyondVPN");
}

function readToken(dir) {
  try {
    const t = fs.readFileSync(path.join(dir, "agent.token"), "utf8").trim();
    return /^[0-9a-f]{64}$/.test(t) ? t : null;
  } catch {
    return null;
  }
}

const ALLOWED = new Set(["GET /v1/status", "GET /v1/servers", "POST /v1/login", "POST /v1/logout", "POST /v1/connect", "POST /v1/disconnect", "POST /v1/settings"]);

class AgentClient {
  constructor({ port = DEFAULT_PORT, dir = agentDir(), fetchImpl = globalThis.fetch } = {}) {
    this.port = port;
    this.dir = dir;
    this.fetch = fetchImpl;
  }

  async request(method, route, body) {
    if (!ALLOWED.has(`${method} ${route}`)) throw new Error(`route not allowed: ${method} ${route}`);
    const token = readToken(this.dir);
    if (!token) throw new Error("Beyond VPN service is not running (agent token missing). Start the Beyond VPN service.");
    let r;
    try {
      r = await this.fetch(`http://127.0.0.1:${this.port}${route}`, {
        method,
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(30000),
      });
    } catch {
      throw new Error("Cannot reach the Beyond VPN service on 127.0.0.1. Is it running?");
    }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `agent error ${r.status}`);
    return data;
  }

  status() { return this.request("GET", "/v1/status"); }
  servers() { return this.request("GET", "/v1/servers"); }
  login(p) { return this.request("POST", "/v1/login", { api_url: String(p.apiUrl), email: String(p.email), password: String(p.password), totp_code: p.totp ? String(p.totp) : null }); }
  logout() { return this.request("POST", "/v1/logout"); }
  connect(serverId) { return this.request("POST", "/v1/connect", { server_id: serverId || null }); }
  disconnect() { return this.request("POST", "/v1/disconnect"); }
  settings(s) {
    const clean = {
      kill_switch: !!s.kill_switch,
      allow_lan: !!s.allow_lan,
      auto_connect: !!s.auto_connect,
      exclude_routes: Array.isArray(s.exclude_routes) ? s.exclude_routes.map(String) : [],
      preferred_server: s.preferred_server ? String(s.preferred_server) : null,
      stealth: !!s.stealth,
      exit_server: s.exit_server ? String(s.exit_server) : null,
    };
    return this.request("POST", "/v1/settings", clean);
  }
}

module.exports = { AgentClient, agentDir, readToken, DEFAULT_PORT };
