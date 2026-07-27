// DEAD DROP desktop shell (Electron) — macOS test build.
//
// Loads the LIVE origin https://d3addr0p.com in a hardened, FRAMELESS window. The CLIENT itself detects
// this shell (window.__ddShell, exposed by preload.js) and switches to its "dd-native" single-window
// layout: the app fills the frame, the simulated desktop is dropped, the app titlebar is the drag handle,
// and the titlebar minimize/close buttons drive this OS window over the bridge below. So the shell only
// has to be frameless + expose the bridge; all presentation lives in the client (no fragile injection).
//
// Because Electron keeps its own Chromium storage (separate from the user's browser) the app onboards as
// a NEW DEVICE with an empty encrypted vault, which is the intended desktop model.
//
// Hardening: a renderer XSS reaches the same-origin IndexedDB vault + in-RAM MSK with or without Node, so
// we keep the standard isolation defaults on and expose only a two-method window-control bridge.
'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { app, BrowserWindow, ipcMain, session, shell } = require('electron');

const APP_URL = process.env.DD_APP_URL || 'https://d3addr0p.com';
const SHOT_PATH = process.env.DD_SHOT; // set to capture the window to a PNG (dev verification only)

// One instance only: a second launch racing the first over the Chromium storage databases produces
// "quota database IO error" and a dead Web Worker (black screen). Bail if we don't own the lock.
if (!app.requestSingleInstanceLock()) {
  app.quit();
}

// Optional dev capture: write the rendered window to a PNG a few times (first-run boot can take seconds),
// and log a native-state snapshot so the dd-native layout can be confirmed without a native inspector.
const PROBE_JS = `(function(){
  var root = document.querySelector('.dd-desk');
  var win = document.querySelector('.dd-window:not(.dd-window-parked)');
  var tb = win && win.querySelector('.dd-titlebar');
  var wr = win && win.getBoundingClientRect();
  return JSON.stringify({
    ddNative: !!(root && root.classList.contains('dd-native')),
    fills: wr ? { w: Math.round(wr.width), h: Math.round(wr.height), vw: innerWidth, vh: innerHeight } : null,
    titlebarDrag: tb ? getComputedStyle(tb).getPropertyValue('-webkit-app-region') : null,
    winctl: !!(win && win.querySelector('[data-action="win-close"]')),
    bridge: !!(window.__ddShell && window.__ddShell.native)
  });
})();`;
function maybeCapture(win) {
  if (!SHOT_PATH) return;
  const shoot = () => {
    win.webContents.capturePage()
      .then((img) => { fs.writeFileSync(SHOT_PATH, img.toPNG()); console.log('[shell] captured', SHOT_PATH); })
      .catch((e) => console.log('[shell] capture error:', String(e)));
    win.webContents.executeJavaScript(PROBE_JS, true)
      .then((s) => console.log('[shell] native-state:', s))
      .catch(() => {});
  };
  for (const t of [2500, 6000, 10000]) setTimeout(shoot, t);
}

function createWindow() {
  const win = new BrowserWindow({
    width: 460,
    height: 760,
    minWidth: 320,
    minHeight: 460,
    title: 'DEAD DROP',
    frame: false,
    backgroundColor: '#07070c',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
    },
  });

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  win.webContents.on('did-finish-load', () => maybeCapture(win));
  win.loadURL(APP_URL);
  return win;
}

app.whenReady().then(() => {
  const allowed = new Set(['media', 'clipboard-read', 'clipboard-sanitized-write']);
  session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => {
    callback(allowed.has(permission));
  });

  // The frameless window's controls call these. Drive only the window that sent the request.
  ipcMain.on('dd-win', (e, action) => {
    const w = BrowserWindow.fromWebContents(e.sender);
    if (!w) return;
    if (action === 'minimize') w.minimize();
    else if (action === 'close') w.close();
  });

  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
