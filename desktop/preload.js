// Minimal, isolated bridge: the frameless window has no OS controls, so the page's injected controls
// call back here to drive the real window. Nothing else is exposed to the (remote) page.
'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('__ddShell', {
  native: true,
  minimize: () => ipcRenderer.send('dd-win', 'minimize'),
  close: () => ipcRenderer.send('dd-win', 'close'),
});
