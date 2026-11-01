'use strict';
/* The only bridge between the page and Windows: read-only facts for the page's network, clock and build checks. */
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('qprDesktop', Object.freeze({
  info: () => ipcRenderer.invoke('qpr:info'),                       // version, build + .exe SHA-256, computer name, server
  network: () => ipcRenderer.invoke('qpr:network'),                 // connected network adapters
  clock: () => ipcRenderer.invoke('qpr:clock'),                     // uptime and sleep/resume count
  timeChanges: since => ipcRenderer.invoke('qpr:time-changes', String(since)),   // Windows' own record of clock changes
  onTimeChanged: cb => { ipcRenderer.on('qpr:time-changed', () => cb()); },
  onNetworkChanged: cb => { ipcRenderer.on('qpr:network-changed', () => cb()); }
}));
