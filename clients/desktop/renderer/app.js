"use strict";
/* global beyond */
const $ = (id) => document.getElementById(id);

function fmt(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  n = Number(n) || 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function err(e) {
  $("err").textContent = e ? String(e.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, "") : "";
}

let lastServersLoad = 0;

// ---------------------------------------------------------------- single sign-on
let ssoFor = "";
async function loadSsoProviders() {
  const api = $("api").value.trim();
  if (!api || api === ssoFor) return;
  ssoFor = api;
  const box = $("sso-buttons");
  box.replaceChildren();
  let list = [];
  try {
    list = await beyond.ssoProviders(api);
  } catch {
    list = [];
  }
  for (const p of list) {
    const b = document.createElement("button");
    b.textContent = `Sign in with ${p.name}`; // textContent: provider names are untrusted
    b.addEventListener("click", () =>
      busy(b, async () => {
        await beyond.ssoStart({ apiUrl: api, provider: p.id });
        $("sso-wait").hidden = false;
      }),
    );
    box.append(b);
  }
  $("sso").hidden = list.length === 0;
}
$("api").addEventListener("change", loadSsoProviders);
$("api").addEventListener("blur", loadSsoProviders);

beyond.onSso((p) => {
  $("sso-wait").hidden = true;
  $("sso-consent").hidden = p.state !== "consent";
  if (p.state === "error") err(p.message);
  if (p.state === "done") {
    lastServersLoad = 0;
    refresh();
  }
});
$("sso-agree").addEventListener("click", (e) => busy(e.target, () => beyond.ssoConsent(true)));
$("sso-cancel").addEventListener("click", (e) =>
  busy(e.target, async () => {
    await beyond.ssoConsent(false);
    $("sso-consent").hidden = true;
  }),
);

async function refresh() {
  let s;
  try {
    s = await beyond.status();
  } catch (e) {
    $("login").hidden = true;
    $("main").hidden = true;
    return err(e);
  }
  err(null);
  $("login").hidden = s.logged_in;
  $("main").hidden = !s.logged_in;
  if (!s.logged_in) return;
  $("who").textContent = `(${s.email || ""})`;
  $("shield").className = `shield ${s.connected ? "on" : "off"}`;
  $("state").textContent = s.connected ? "Protected" : "Not protected";
  $("where").textContent = s.connected ? `Connected to ${s.server}` : `Engine: ${s.backend}`;
  $("toggle").textContent = s.connected ? "Disconnect" : "Connect";
  $("rx").textContent = fmt(s.rx_bytes);
  $("tx").textContent = fmt(s.tx_bytes);
  if (document.activeElement?.tagName !== "INPUT") {
    $("kill_switch").checked = s.settings.kill_switch;
    $("allow_lan").checked = s.settings.allow_lan;
    $("auto_connect").checked = s.settings.auto_connect;
    $("exclude").value = s.settings.exclude_routes.join(", ");
    $("stealth").checked = !!s.settings.stealth;
  }
  if (Date.now() - lastServersLoad > 60000) {
    lastServersLoad = Date.now();
    try {
      const list = await beyond.servers();
      const sel = $("server");
      const cur = sel.value || s.settings.preferred_server || "";
      sel.replaceChildren(new Option("⚡ Fastest server", ""));
      for (const v of list) {
        const o = new Option(`${v.country} · ${v.name} (${Math.round(v.load * 100)}%)`, v.id);
        o.disabled = v.status !== "online";
        sel.add(o);
      }
      sel.value = cur;
      const exit = $("exit_server");
      exit.replaceChildren(new Option("Off (single hop)", ""));
      for (const v of list) {
        const o = new Option(`${v.country} · ${v.name}`, v.id);
        o.disabled = v.status !== "online";
        exit.add(o);
      }
      exit.value = s.settings.exit_server || "";
    } catch (e) {
      err(e);
    }
  }
}

async function busy(btn, fn) {
  btn.disabled = true;
  err(null);
  try {
    await fn();
  } catch (e) {
    err(e);
  } finally {
    btn.disabled = false;
    await refresh();
  }
}

$("signin").addEventListener("click", (e) =>
  busy(e.target, async () => {
    await beyond.login({ apiUrl: $("api").value.trim(), email: $("email").value.trim(), password: $("pw").value, totp: $("totp").value.trim() });
    $("pw").value = "";
    lastServersLoad = 0;
  }),
);

$("toggle").addEventListener("click", (e) =>
  busy(e.target, async () => {
    const s = await beyond.status();
    if (s.connected) await beyond.disconnect();
    else await beyond.connect($("server").value || null);
  }),
);

$("save").addEventListener("click", (e) =>
  busy(e.target, () =>
    beyond.settings({
      kill_switch: $("kill_switch").checked,
      allow_lan: $("allow_lan").checked,
      auto_connect: $("auto_connect").checked,
      exclude_routes: $("exclude").value.split(",").map((x) => x.trim()).filter(Boolean),
      preferred_server: $("server").value || null,
      stealth: $("stealth").checked,
      exit_server: $("exit_server").value || null,
    }),
  ),
);

$("logout").addEventListener("click", (e) => busy(e.target, () => beyond.logout()));

refresh();
setInterval(refresh, 3000);
