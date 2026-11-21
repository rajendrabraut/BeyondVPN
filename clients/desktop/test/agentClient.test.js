"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { AgentClient, agentDir, readToken } = require("../src/agentClient");

const TOKEN = "a".repeat(64);

function tmpDir(token) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "beyond-desktop-"));
  if (token) fs.writeFileSync(path.join(d, "agent.token"), token);
  return d;
}

test("agent dir per platform", () => {
  assert.equal(agentDir({ BEYOND_AGENT_DIR: "/x" }, "linux"), "/x");
  assert.ok(agentDir({ APPDATA: "C:\\Users\\a\\AppData\\Roaming" }, "win32", () => false).startsWith("C:\\Users\\a"));
  // Installed service: its state dir is used when it holds a token.
  assert.equal(agentDir({ ProgramData: "C:\\ProgramData", APPDATA: "C:\\U" }, "win32", (p) => p.includes("ProgramData")), "C:\\ProgramData\\BeyondVPN");
  assert.equal(agentDir({}, "linux", (p) => p.startsWith("/var/lib/beyondvpn")), "/var/lib/beyondvpn");
  assert.ok(agentDir({}, "darwin").includes("Application Support"));
});

test("token validation", () => {
  assert.equal(readToken(tmpDir(TOKEN)), TOKEN);
  assert.equal(readToken(tmpDir("short")), null);
  assert.equal(readToken(tmpDir(null)), null);
});

test("rejects routes outside whitelist and missing service", async () => {
  const c = new AgentClient({ dir: tmpDir(TOKEN), port: 1 });
  await assert.rejects(c.request("DELETE", "/v1/everything"), /not allowed/);
  await assert.rejects(c.status(), /Cannot reach/);
  await assert.rejects(new AgentClient({ dir: tmpDir(null) }).status(), /not running/);
});

test("talks to a fake agent with bearer auth and sanitised settings", async () => {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, host: req.headers.host, body });
      res.setHeader("content-type", "application/json");
      if (req.url === "/v1/connect") {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "no servers available" }));
      }
      res.end(JSON.stringify({ ok: true, logged_in: true }));
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  try {
    const c = new AgentClient({ dir: tmpDir(TOKEN), port });
    assert.equal((await c.status()).logged_in, true);
    await c.settings({ kill_switch: 1, exclude_routes: [1, "10.0.0.0/8"], evil: "x" });
    await assert.rejects(c.connect(null), /no servers available/);
    assert.equal(seen[0].auth, `Bearer ${TOKEN}`);
    assert.equal(seen[0].host, `127.0.0.1:${port}`);
    const settings = JSON.parse(seen[1].body);
    assert.deepEqual(Object.keys(settings).sort(), ["allow_lan", "auto_connect", "exclude_routes", "exit_server", "kill_switch", "preferred_server", "stealth"]);
    assert.equal(settings.kill_switch, true);
    assert.deepEqual(settings.exclude_routes, ["1", "10.0.0.0/8"]);
  } finally {
    srv.close();
  }
});
