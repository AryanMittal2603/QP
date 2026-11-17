'use strict';
/* The only bridge between the page and Windows: read-only facts for the page's network and clock notes, and the certificate's PDF / print. */
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('qprDesktop', Object.freeze({
  local: true,                                                      // 3.x: everything stays on this computer; /api is answered by the app itself
  info: () => ipcRenderer.invoke('qpr:info'),                       // version, build SHA-256, computer name
  network: () => ipcRenderer.invoke('qpr:network'),                 // connected network adapters
  clock: () => ipcRenderer.invoke('qpr:clock'),                     // uptime and sleep/resume count
  savePdf: (html, name) => ipcRenderer.invoke('qpr:save-pdf', String(html), String(name)),   // QP-Draw certificate → PDF file (asks where to save)
  printHtml: html => ipcRenderer.invoke('qpr:print-html', String(html)),                  // QP-Draw certificate → printer
  onTimeChanged: cb => { ipcRenderer.on('qpr:time-changed', () => cb()); },
  onNetworkChanged: cb => { ipcRenderer.on('qpr:network-changed', () => cb()); }
}));
