"use strict";

const $ = (id) => document.getElementById(id);
let tab = null;
let fillable = false;

async function send(msg) {
  try {
    return (await chrome.runtime.sendMessage(msg)) || { ok: false, error: "No answer from the extension." };
  } catch (err) {
    return { ok: false, error: String(err.message || err) };
  }
}

function say(text, isError = false) {
  $("message").textContent = text;
  $("message").className = isError ? "error" : "";
}

function show(view) {
  $("unlock").hidden = view !== "unlock";
  $("vault").hidden = view !== "vault";
  $("lock").hidden = view !== "vault";
  if (view === "unlock") $("password").focus();
}

function button(label, onClick, primary = false) {
  const b = document.createElement("button");
  b.textContent = label;
  if (primary) b.className = "primary";
  b.addEventListener("click", onClick);
  return b;
}

// Entry text is page-independent but still user data: textContent only, never innerHTML.
function renderList(list, entries, canFill) {
  list.replaceChildren(...entries.map((e) => {
    const li = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = e.title;
    const who = document.createElement("span");
    who.className = "who";
    who.textContent = e.username || e.url || "";
    const actions = document.createElement("div");
    actions.className = "actions";
    if (canFill) actions.append(button("Fill", () => fill(e), true));
    actions.append(button("Copy password", () => copy(e, "password")));
    if (e.username) actions.append(button("Copy user", () => copy(e, "username")));
    if (e.has_totp) actions.append(button("Copy code", () => copy(e, "totp")));
    li.append(title, who, actions);
    return li;
  }));
}

async function copy(entry, field) {
  const r = await send({ cmd: "copy", entry: entry.id, field });
  if (!r.ok) return handleError(r);
  say(`Copied. Clipboard clears in ${r.seconds}s.`);
}

async function fill(entry) {
  const r = await send({ cmd: "fill", entry: entry.id, url: tab.url });
  if (!r.ok) return handleError(r);
  let result;
  try {
    [result] = await chrome.scripting.executeScript({
      target: { tabId: tab.id }, // top frame only: iframes from other sites never get credentials
      func: fillPage,
      args: [r.host, r.username, r.password],
    });
  } catch (err) {
    return say(`Can't fill this page: ${err.message}`, true);
  }
  if (result?.result) return say(result.result, true);
  window.close();
}

// Runs inside the page. Re-checks the host, because the tab may have navigated since the popup opened.
function fillPage(expectedHost, username, password) {
  if (location.hostname !== expectedHost) return "The page changed; nothing was filled.";
  const visible = (el) => !el.disabled && !el.readOnly && el.getClientRects().length > 0 &&
    getComputedStyle(el).visibility !== "hidden";
  const setValue = (el, value) => {
    // Use the native setter so frameworks that track input values (React, Vue) see the change.
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const textish = (el) => ["text", "email", "tel", ""].includes(el.type);
  const pass = [...document.querySelectorAll("input[type=password]")].find(visible);
  const scope = pass?.form || document;
  const inputs = [...scope.querySelectorAll("input")].filter(visible);
  let user = null;
  if (pass) {
    user = inputs.slice(0, inputs.indexOf(pass)).reverse().find(textish) || null;
  } else {
    // Two-step logins: the first page asks for the username only.
    user = inputs.find((el) => /username|email/i.test(el.autocomplete)) ||
      inputs.find((el) => el.type === "email") || inputs.find(textish) || null;
  }
  if (!pass && !user) return "No login fields found on this page.";
  if (user && username) setValue(user, username);
  if (pass) {
    setValue(pass, password);
    pass.focus();
  }
  return "";
}

function handleError(r) {
  if (r.error === "locked") {
    show("unlock");
    return say("Vaultlet locked itself. Unlock again.");
  }
  say(r.error || "Something went wrong.", true);
}

async function loadVault() {
  show("vault");
  let host = "";
  try {
    host = new URL(tab.url).hostname;
  } catch { /* chrome:// pages, blank tabs */ }
  const r = await send({ cmd: "match", url: tab.url || "" });
  if (!r.ok) return handleError(r);
  fillable = r.fillable;
  $("site").textContent = r.entries.length
    ? `Logins for ${host}` + (fillable ? "" : " (not https: copy only)")
    : host ? `No logins saved for ${host}.` : "No site on this tab.";
  renderList($("matches"), r.entries, fillable);
  $("search").focus();
}

$("unlock").addEventListener("submit", async (event) => {
  event.preventDefault();
  say("Unlocking...");
  const password = $("password").value;
  $("password").value = "";
  const r = await send({ cmd: "unlock", password });
  if (!r.ok) return handleError(r);
  say("");
  loadVault();
});

$("lock").addEventListener("click", async () => {
  await send({ cmd: "lock" });
  $("results").replaceChildren();
  show("unlock");
  say("Locked.");
});

let searchSeq = 0;
$("search").addEventListener("input", async () => {
  const query = $("search").value.trim();
  const seq = ++searchSeq;
  if (!query) return $("results").replaceChildren();
  const r = await send({ cmd: "search", query });
  if (seq !== searchSeq) return; // a newer keystroke already answered
  if (!r.ok) return handleError(r);
  renderList($("results"), r.entries, false); // fill stays tied to the site match above
});

(async () => {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const r = await send({ cmd: "status" });
  if (!r.ok) {
    show("none");
    return say(r.error, true);
  }
  r.unlocked ? loadVault() : show("unlock");
})();
