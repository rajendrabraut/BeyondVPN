"use strict";
const { test } = require("node:test");
const assert = require("node:assert");
const sso = require("../src/sso");

test("server URL rules", () => {
  assert.equal(sso.serverUrl(" https://vpn.example.com/path "), "https://vpn.example.com");
  assert.equal(sso.serverUrl("http://127.0.0.1:8000"), "http://127.0.0.1:8000");
  assert.throws(() => sso.serverUrl("http://vpn.example.com"), /https/);
  assert.throws(() => sso.serverUrl("https://u:p@vpn.example.com"), /credentials/);
  assert.throws(() => sso.serverUrl("javascript:alert(1)"), /https/);
});

test("start URL carries the nonce in an encoded return_to", () => {
  const u = sso.startUrl("https://vpn.example.com", "corp", "ab12");
  assert.equal(u, "https://vpn.example.com/api/v1/auth/sso/corp/start?return_to=beyondvpn%3A%2F%2Fsso%3Fn%3Dab12");
  assert.throws(() => sso.startUrl("https://vpn.example.com", "../admin", "ab12"), /provider/);
});

test("callback parsing: query or fragment", () => {
  assert.deepEqual(sso.parseCallback("beyondvpn://sso?n=ab12&sso_code=Code_1234567890"), { nonce: "ab12", code: "Code_1234567890", error: null });
  assert.deepEqual(sso.parseCallback("beyondvpn://sso?n=ab12#sso_code=Code_1234567890"), { nonce: "ab12", code: "Code_1234567890", error: null });
  assert.equal(sso.parseCallback("https://evil.example/sso?sso_code=x"), null);
  assert.equal(sso.parseCallback("beyondvpn://other?n=1"), null);
  assert.equal(sso.linkFromArgv(["app.exe", "--flag", "beyondvpn://sso?n=1"]), "beyondvpn://sso?n=1");
});

test("only the pending sign-in from this app is accepted", () => {
  const now = 1_000_000;
  const pending = { nonce: "0123456789abcdef0123456789abcdef", started: now };
  const good = { nonce: pending.nonce, code: "Code_1234567890", error: null };
  assert.deepEqual(sso.accept(pending, good, now + 1000), { ok: true, code: "Code_1234567890" });
  assert.equal(sso.accept(null, good, now).ok, false); // a web page opened beyondvpn://... on its own
  assert.equal(sso.accept(pending, { ...good, nonce: "ffff" }, now).ok, false); // wrong / shorter nonce
  assert.equal(sso.accept(pending, { ...good, nonce: "x".repeat(64) }, now).ok, false); // longer nonce
  assert.equal(sso.accept(pending, good, now + sso.PENDING_TTL_MS + 1).ok, false);
  assert.match(sso.accept(pending, { ...good, code: null, error: "denied" }, now).reason, /denied/);
  assert.equal(sso.accept(pending, { ...good, code: "x y" }, now).ok, false);
});
