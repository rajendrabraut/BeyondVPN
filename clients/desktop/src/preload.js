"use strict";
const { contextBridge, ipcRenderer } = require("electron");

// Minimal, whitelisted bridge. No Node APIs are exposed to the page.
contextBridge.exposeInMainWorld("beyond", {
  status: () => ipcRenderer.invoke("agent:status"),
  servers: () => ipcRenderer.invoke("agent:servers"),
  login: (p) => ipcRenderer.invoke("agent:login", p),
  logout: () => ipcRenderer.invoke("agent:logout"),
  connect: (id) => ipcRenderer.invoke("agent:connect", id),
  disconnect: () => ipcRenderer.invoke("agent:disconnect"),
  settings: (s) => ipcRenderer.invoke("agent:settings", s),
});
