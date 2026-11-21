"use strict";
// Beyond VPN desktop shell. The privileged work (tunnel, kill switch) is done by
// the beyond-agent service; this process only renders UI and relays whitelisted calls.
const { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage, shell } = require("electron");
const path = require("node:path");
const { AgentClient } = require("./agentClient");

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

const handlers = {
  status: () => agent.status(),
  servers: () => agent.servers(),
  login: (p) => agent.login(p),
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

app.on("second-instance", () => win && win.show());
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
