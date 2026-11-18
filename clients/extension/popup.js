import { flag } from "./lib.js";

const B = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

function send(msg) {
  return new Promise((resolve, reject) => {
    B.runtime.sendMessage(msg, (r) => {
      if (!r) return reject(new Error(B.runtime.lastError?.message || "no response"));
      r.ok ? resolve(r.data) : reject(new Error(r.error));
    });
  });
}

function fmt(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function showErr(e) {
  $("err").textContent = e ? String(e.message ?? e) : "";
}

async function render() {
  showErr(null);
  const st = await send({ type: "state" });
  $("login").hidden = st.signedIn;
  $("main").hidden = !st.signedIn;
  if (!st.signedIn) {
    $("api").value = st.apiUrl ?? "";
    $("email").value = st.email ?? "";
    return;
  }
  $("who").textContent = `(${st.email})`;
  $("allowLan").checked = st.settings.allowLan;
  $("blockWebRtc").checked = st.settings.blockWebRtc;
  $("bypass").value = (st.settings.bypassDomains ?? []).join("\n");
  const on = !!st.conn;
  $("status").className = `status ${on ? "on" : "off"}`;
  $("statusText").textContent = on ? "Protected" : "Not protected";
  $("statusSub").textContent = on ? `${flag(st.conn.country)} ${st.conn.server_name}` : "Browser traffic is not encrypted by Beyond VPN";
  $("toggle").textContent = on ? "Disconnect" : "Connect";
  try {
    const servers = await send({ type: "servers" });
    const sel = $("server");
    sel.replaceChildren(new Option("⚡ Fastest", ""));
    for (const s of servers) {
      const o = new Option(`${flag(s.country)} ${s.name} — ${Math.round(s.load * 100)}%${s.status !== "online" ? " (offline)" : ""}`, s.id);
      o.disabled = s.status !== "online";
      sel.add(o);
    }
    sel.value = st.conn?.server_id ?? st.lastServer ?? "";
    const u = await send({ type: "usage" });
    $("usage").textContent = `This month: ${fmt(u.month_total_bytes)}${u.data_cap_bytes ? ` of ${fmt(u.data_cap_bytes)}` : ""}`;
  } catch (e) {
    showErr(e);
  }
}

$("signin").addEventListener("click", async () => {
  showErr(null);
  try {
    await send({ type: "login", apiUrl: $("api").value, email: $("email").value, password: $("pw").value, totp: $("totp").value });
    $("pw").value = "";
    await render();
  } catch (e) {
    if (e.message === "mfa_required") {
      $("mfa").hidden = false;
      $("totp").focus();
    } else showErr(e);
  }
});

$("toggle").addEventListener("click", async () => {
  showErr(null);
  $("toggle").disabled = true;
  try {
    const st = await send({ type: "state" });
    if (st.conn) await send({ type: "disconnect" });
    else await send({ type: "connect", serverId: $("server").value || null });
    await render();
  } catch (e) {
    showErr(e);
  } finally {
    $("toggle").disabled = false;
  }
});

$("save").addEventListener("click", async () => {
  try {
    await send({
      type: "settings",
      settings: { allowLan: $("allowLan").checked, blockWebRtc: $("blockWebRtc").checked, bypassDomains: $("bypass").value.split(/\s+/).filter(Boolean) },
    });
    await render();
  } catch (e) {
    showErr(e);
  }
});

$("logout").addEventListener("click", async () => {
  await send({ type: "logout" }).catch(showErr);
  await render();
});

render().catch(showErr);
