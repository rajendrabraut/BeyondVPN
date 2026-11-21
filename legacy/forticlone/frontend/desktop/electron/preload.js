const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('vpn', {
  connect: (id) => ipcRenderer.invoke('vpn-connect', id),
  disconnect: (path) => ipcRenderer.invoke('vpn-disconnect', path),
  status: () => ipcRenderer.invoke('vpn-status')
})
