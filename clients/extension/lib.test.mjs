import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBypassList, chromeProxyConfig, firefoxProxyFor, matchesBypass, needsRefresh, normalizeApiUrl, pickFastest } from "./lib.js";

test("api url validation", () => {
  assert.equal(normalizeApiUrl("https://vpn.example.com/some/path"), "https://vpn.example.com");
  assert.equal(normalizeApiUrl("http://127.0.0.1:8000"), "http://127.0.0.1:8000");
  assert.throws(() => normalizeApiUrl("http://vpn.example.com"));
  assert.throws(() => normalizeApiUrl("https://user:pw@vpn.example.com"));
  assert.throws(() => normalizeApiUrl("not a url"));
});

test("bypass list includes control plane, LAN and user domains", () => {
  const b = buildBypassList("https://cp.example.com", ["Bank.example.", "bad domain!"]);
  assert.ok(b.includes("cp.example.com"));
  assert.ok(b.includes("192.168.0.0/16"));
  assert.ok(b.includes("bank.example") && b.includes("*.bank.example"));
  assert.ok(!b.some((x) => x.includes("!")));
  assert.ok(!buildBypassList(null, [], false).includes("10.0.0.0/8"));
});

test("bypass matching", () => {
  const b = buildBypassList("https://cp.example.com", ["bank.example"]);
  assert.ok(matchesBypass("192.168.1.20", b));
  assert.ok(matchesBypass("login.bank.example", b));
  assert.ok(matchesBypass("printer", b));
  assert.ok(!matchesBypass("news.example.org", b));
  assert.ok(!matchesBypass("172.32.0.1", b));
});

test("chrome proxy config fails closed and validates", () => {
  const c = chromeProxyConfig("gw.example.com", 8443, ["localhost"]);
  assert.equal(c.mode, "fixed_servers");
  assert.equal(c.rules.singleProxy.scheme, "https");
  assert.throws(() => chromeProxyConfig("evil host", 8443, []));
  assert.throws(() => chromeProxyConfig("gw.example.com", 0, []));
});

test("firefox proxy routing", () => {
  const b = buildBypassList("https://cp.example.com", []);
  const conn = { host: "gw.example.com", port: 8443, token: "T" };
  assert.equal(firefoxProxyFor("https://news.example.org/x", conn, b).type, "https");
  assert.equal(firefoxProxyFor("https://news.example.org/x", conn, b).proxyAuthorizationHeader, "Bearer T");
  assert.equal(firefoxProxyFor("https://cp.example.com/api", conn, b).type, "direct");
  assert.equal(firefoxProxyFor("https://x.org", null, b).type, "direct");
});

test("token refresh timing and fastest pick", () => {
  assert.ok(needsRefresh(1000, 800));
  assert.ok(!needsRefresh(2000, 800));
  assert.ok(needsRefresh(undefined, 0));
  assert.equal(pickFastest([{ id: "a", status: "online", load: 0.5 }, { id: "b", status: "online", load: 0.1 }, { id: "c", status: "offline", load: 0 }]).id, "b");
  assert.equal(pickFastest([]), null);
});
