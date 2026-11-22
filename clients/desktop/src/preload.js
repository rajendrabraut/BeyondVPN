"use strict";
const { contextBridge, ipcRenderer } = require("electron");

// Minimal, whitelisted bridge. No Node APIs are exposed to the page.
contextBridge.exposeInMainWorld("beyond", {
  status: () => ipcRenderer.invoke("agent:status"),
  servers: () => ipcRenderer.invoke("agent:servers"),
  login: (p) => ipcRenderer.invoke("agent:login", p),
  ssoProviders: (apiUrl) => ipcRenderer.invoke("agent:ssoProviders", apiUrl),
  ssoStart: (p) => ipcRenderer.invoke("agent:ssoStart", p),
  ssoConsent: (accepted) => ipcRenderer.invoke("agent:ssoConsent", !!accepted),
  // Only the payload object reaches the page, never the IPC event.
  onSso: (cb) => ipcRenderer.on("sso", (_e, payload) => cb(payload)),
  logout: () => ipcRenderer.invoke("agent:logout"),
  connect: (id) => ipcRenderer.invoke("agent:connect", id),
  disconnect: () => ipcRenderer.invoke("agent:disconnect"),
  settings: (s) => ipcRenderer.invoke("agent:settings", s),
});
