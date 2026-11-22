"use strict";
// Beyond VPN desktop shell. The privileged work (tunnel, kill switch) is done by
// the beyond-agent service; this process only renders UI and relays whitelisted calls.
const { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage, shell } = require("electron");
const path = require("node:path");
const { AgentClient } = require("./agentClient");
const sso = require("./sso");

const agent = new AgentClient();
let win = null;
let tray = null;

if (!app.requestSingleInstanceLock()) app.quit();

function createWindow() {
  win = new BrowserWindow({
    width: 420,
    height: 700,
    minWidth: 380,
    title: "Beyond VPN",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
    },
  });
  win.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
  // Never navigate away from the bundled UI; open external links in the browser.
  win.webContents.on("will-navigate", (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });
  win.on("close", (e) => {
    if (!app.isQuitting && tray) {
      e.preventDefault();
      win.hide();
    }
  });
}

async function refreshTray() {
  if (!tray) return;
  let connected = false;
  try {
    connected = (await agent.status()).connected;
  } catch {
    /* agent down */
  }
  tray.setToolTip(connected ? "Beyond VPN — protected" : "Beyond VPN — not connected");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: connected ? "Disconnect" : "Quick connect", click: () => (connected ? agent.disconnect() : agent.connect(null)).finally(refreshTray) },
      { label: "Open Beyond VPN", click: () => win.show() },
      { type: "separator" },
      { label: "Quit", click: () => { app.isQuitting = true; app.quit(); } },
    ]),
  );
}

// ---------------------------------------------------------------- single sign-on
// One sign-in at a time: the nonce ties the beyondvpn://sso link back to a sign-in started here.
let pendingSso = null; // { api, nonce, started, code? }

function notifySso(payload) {
  if (win) {
    win.show();
    win.webContents.send("sso", payload);
  }
}

async function finishSso(acceptLogging) {
  const p = pendingSso;
  if (!p || !p.code) throw new Error("no single sign-on in progress");
  try {
    await agent.loginSso({ apiUrl: p.api, code: p.code, acceptLogging });
    pendingSso = null;
    notifySso({ state: "done" });
  } catch (e) {
    if (String(e.message) === "logging_consent_required") {
      notifySso({ state: "consent" }); // keep the code (valid ~2 min) for the retry
      return;
    }
    pendingSso = null;
    notifySso({ state: "error", message: String(e.message) });
  }
}

function handleSsoLink(link) {
  if (!link) return;
  const verdict = sso.accept(pendingSso, sso.parseCallback(link));
  if (!verdict.ok) {
    // Links nobody asked for (e.g. opened by a web page) are ignored silently.
    if (pendingSso) notifySso({ state: "error", message: verdict.reason });
    return;
  }
  pendingSso.code = verdict.code;
  finishSso(false);
}

async function ssoProviders(apiUrl) {
  const base = sso.serverUrl(apiUrl);
  const r = await fetch(`${base}/api/v1/auth/sso/providers`, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) return [];
  const list = await r.json().catch(() => []);
  return Array.isArray(list) ? list.filter((p) => p && typeof p.id === "string" && typeof p.name === "string").map((p) => ({ id: p.id, name: p.name.slice(0, 80) })) : [];
}

function ssoStart(p) {
  const api = sso.serverUrl(p.apiUrl);
  const nonce = sso.newNonce();
  const url = sso.startUrl(api, p.provider, nonce);
  pendingSso = { api, nonce, started: Date.now() };
  shell.openExternal(url);
  return { opened: true };
}

const handlers = {
  status: () => agent.status(),
  servers: () => agent.servers(),
  login: (p) => agent.login(p),
  ssoProviders: (apiUrl) => ssoProviders(apiUrl),
  ssoStart: (p) => ssoStart(p),
  ssoConsent: (accepted) => (accepted ? finishSso(true) : ((pendingSso = null), { cancelled: true })),
  logout: () => agent.logout(),
  connect: (id) => agent.connect(id),
  disconnect: () => agent.disconnect(),
  settings: (s) => agent.settings(s),
};

for (const [name, fn] of Object.entries(handlers)) {
  ipcMain.handle(`agent:${name}`, async (event, arg) => {
    // Only accept IPC from our own bundled page.
    if (!event.senderFrame || !event.senderFrame.url.startsWith("file://")) throw new Error("forbidden");
    const r = await fn(arg);
    if (name === "connect" || name === "disconnect") refreshTray();
    return r;
  });
}

app.whenReady().then(() => {
  createWindow();
  const icon = nativeImage.createFromDataURL(
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAOUlEQVR4nGNgGAWjYBSMglEwCkbBKBgFo2AUjIJRMAqGAvj///9/BkZGRkYGBgYGJgYGBgYGBkYGAI0BBQGgjX1DAAAAAElFTkSuQmCC",
  );
  tray = new Tray(icon);
  tray.on("click", () => win.show());
  refreshTray();
  setInterval(refreshTray, 15000);
});

// beyondvpn:// links: registered for this user; in development point the OS at electron + this app.
if (process.defaultApp && process.argv.length >= 2) {
  app.setAsDefaultProtocolClient(sso.SCHEME, process.execPath, [path.resolve(process.argv[1])]);
} else {
  app.setAsDefaultProtocolClient(sso.SCHEME);
}
// Windows/Linux: a second launch carries the link on its command line.
app.on("second-instance", (_e, argv) => {
  if (win) win.show();
  handleSsoLink(sso.linkFromArgv(argv));
});
// macOS delivers it as an event.
app.on("open-url", (e, url) => {
  e.preventDefault();
  handleSsoLink(url);
});
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
