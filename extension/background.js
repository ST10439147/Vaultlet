// Holds the one connection to the native helper. The browser keeps a service worker alive while
// it has an open native port, and the helper (not this worker) locks itself when idle.
"use strict";

const HOST = "com.vaultlet.helper";
const pending = new Map();
let port = null;
let nextId = 1;

function connect() {
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((msg) => {
    const resolve = pending.get(msg.id);
    if (resolve) {
      pending.delete(msg.id);
      resolve(msg);
    }
  });
  port.onDisconnect.addListener(() => {
    const reason = chrome.runtime.lastError?.message || "The Vaultlet helper stopped.";
    const error = /not found|forbidden/i.test(reason)
      ? "Vaultlet helper not installed. Run: vaultlet native install"
      : reason;
    for (const resolve of pending.values()) resolve({ ok: false, error });
    pending.clear();
    port = null;
  });
}

function call(msg) {
  return new Promise((resolve) => {
    if (!port) connect();
    const id = nextId++;
    pending.set(id, resolve);
    port.postMessage({ ...msg, id });
  });
}

// Only this extension's own pages (the popup) may talk to the helper: no content scripts exist,
// and there's no onMessageExternal, so web pages and other extensions can't reach this.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.tab) return false;
  call(msg).then(sendResponse);
  return true; // async response
});
