/*
 * Minos web client (plain JavaScript).
 *
 * Every button calls the Java Minos Server. No cryptography runs in the
 * browser, and the screens use plain language so people without any
 * security background can use the system.
 */
"use strict";

const state = { status: null, me: null, lastSearch: null, alertCount: 0, requestCount: 0, changeCount: 0 };
const $view = document.getElementById("view");

// ------------------------------------------------------------------ helpers
function esc(v) {
  return String(v == null ? "" : v).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmt(t) {
  if (t == null || t === "") return "";
  const d = typeof t === "number" ? new Date(t) : new Date(String(t));
  return isNaN(d) ? esc(t) : d.toLocaleString();
}
function size(n) {
  if (n == null) return "";
  if (n < 1024) return n + " bytes";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(1) + " MB";
}
function param(name) {
  const q = location.hash.split("?")[1] || "";
  return new URLSearchParams(q).get(name);
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let res;
  try { res = await fetch(path, opts); }
  catch (e) { throw new Error("The server at " + location.host + " is not reachable."); }
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (!res.ok || data.success === false) {
    const err = new Error(data.message || data.error || ("Request failed (" + res.status + ")"));
    err.status = res.status;
    throw err;
  }
  return data;
}
const GET = p => api("GET", p);
const POST = (p, b) => api("POST", p, b || {});

let toastTimer;
function toast(msg, isError) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = "toast"; }, isError ? 7000 : 4000);
}

/** Runs an async action with the button disabled; reports errors. */
async function busy(btn, fn) {
  const label = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "Working…"; }
  try { return await fn(); }
  catch (e) { toast(e.message, true); }
  finally { if (btn && btn.isConnected) { btn.disabled = false; btn.textContent = label; } }
}

function tag(kind, text) { return `<span class="tag ${kind}">${esc(text)}</span>`; }

function table(cols, rows, empty) {
  if (!rows.length) return `<p class="empty">${esc(empty || "Nothing here yet.")}</p>`;
  return `<div class="tablewrap"><table><thead><tr>${cols.map(c => `<th>${esc(c)}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function render(html) { $view.innerHTML = html; $view.focus({ preventScroll: true }); window.scrollTo(0, 0); }
function go(route) { location.hash = "#/" + route; }

const PERM_LABEL = { VIEW: "View", DOWNLOAD: "Download", MODIFY: "Modify" };
function permTags(p) {
  if (!p || !p.length) return tag("plain", "no access");
  return p.map(x => tag(x === "MODIFY" ? "ext" : "ok", PERM_LABEL[x] || x)).join(" ");
}
function approvalTag(a) {
  return ({ NOT_REQUIRED: tag("plain", "not needed"), NONE: tag("plain", "not requested yet"),
    PENDING: tag("ext", "waiting for owner"), APPROVED: tag("ok", "approved"), DENIED: tag("alarm", "denied") })[a] || "";
}
function changeTag(s) {
  return ({ PENDING: tag("ext", "waiting for review"), APPROVED: tag("ok", "approved"),
    REJECTED: tag("alarm", "rejected") })[s] || tag("plain", s);
}
const ACTION_LABEL = {
  ACCESS_GRANTED: "Access granted", ACCESS_DENIED: "Access denied", VIEWED: "Viewed",
  DOWNLOADED: "Downloaded", CHANGE_PROPOSED: "Suggested a change", CHANGE_REVIEWED: "Opened a change for review",
  CHANGE_APPROVED: "Change approved", CHANGE_REJECTED: "Change rejected", OWNER_DOWNLOADED: "Owner downloaded",
  LEAK_TRACED: "Leak traced", COPY_ATTEMPT: "Tried to copy", PRINT_ATTEMPT: "Tried to print",
  PRINT_SCREEN: "Print Screen", WINDOW_LEFT: "Left the window"
};
function actionTag(a) {
  const kind = a === "CHANGE_REJECTED" || a === "ACCESS_DENIED" || a === "LEAK_TRACED" || a === "COPY_ATTEMPT"
    || a === "PRINT_ATTEMPT" || a === "PRINT_SCREEN" ? "alarm" : a === "WINDOW_LEFT" ? "ext"
    : a === "CHANGE_PROPOSED" ? "ext" : a === "CHANGE_APPROVED" || a === "ACCESS_GRANTED" ? "ok" : "plain";
  return tag(kind, ACTION_LABEL[a] || a);
}
function versionLabel(v) { return Number(v) === 1 ? "Original" : "Version " + v; }

/** Downloads through fetch so errors are shown as a message instead of a blank page. */
async function downloadFile(url, fallbackName) {
  const res = await fetch(url, { credentials: "same-origin" });
  if (!res.ok) {
    let msg = "Download failed (" + res.status + ")";
    try { const j = await res.json(); msg = j.message || j.error || msg; } catch (e) { /* not JSON */ }
    throw new Error(msg);
  }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const m = /filename="([^"]+)"/.exec(cd);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = m ? m[1] : (fallbackName || "document");
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}
function readFileBase64(file) {
  return new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(String(fr.result).split(",")[1] || "");
    fr.onerror = () => rej(new Error("Could not read the file."));
    fr.readAsDataURL(file);
  });
}

// ------------------------------------------------------------------ chrome
async function refreshSession() {
  try { state.me = (await GET("/api/me")).user; }
  catch (e) { state.me = null; }
  if (state.me && state.me.actingAs === "owner") {
    const [a, r, c] = await Promise.all([
      GET("/api/owner/alerts").catch(() => ({ alerts: [] })),
      GET("/api/owner/access-requests").catch(() => ({ requests: [] })),
      GET("/api/owner/changes").catch(() => ({ changes: [] }))]);
    state.alertCount = a.unseen != null ? a.unseen : a.alerts.length;   // only alerts not seen yet
    state.requestCount = r.requests.filter(x => x.status === "PENDING").length;
    state.changeCount = c.changes.filter(x => x.status === "PENDING").length;
  }
  drawChrome();
}

function count(n) { return n ? ` <span class="count">${n}</span>` : ""; }

function drawChrome() {
  const s = document.getElementById("session");
  const me = state.me;
  if (me) {
    const other = me.actingAs === "owner" ? "user" : "owner";
    s.innerHTML = `<span>${esc(me.displayName || me.userId)} (${esc(me.userId)}) · <b>${me.actingAs === "owner" ? "Data owner" : "Data user"}</b></span>
      <button class="secondary" id="switchRole">Switch to data ${other}</button>
      <button class="secondary" id="logout">Log out</button>`;
    document.getElementById("switchRole").onclick = e => busy(e.target, async () => {
      state.me = (await POST("/api/me/role", { actingAs: other })).user;
      await refreshSession();
      go(other === "owner" ? "owner" : "user");
    });
    document.getElementById("logout").onclick = e => busy(e.target, async () => {
      await POST("/api/logout");
      state.me = null; state.lastSearch = null;
      drawChrome(); go("home");
    });
  } else {
    s.innerHTML = `<a class="btn secondary" href="#/login">Log in</a> <a class="btn" href="#/register">Register</a>`;
  }

  const links = [];
  const init = state.status && state.status.initialized;
  if (!init) links.push(["System", [["setup", "Setup"]]]);
  links.push(["General", [["home", "Home"]].concat(me ? [] : [["register", "Register"], ["login", "Log in"]])]);
  if (me && me.actingAs === "owner") {
    links.push(["Data owner", [["owner", "Owner dashboard"], ["upload", "Upload document"],
      ["requests", "Access requests" + count(state.requestCount)],
      ["changes", "Change requests" + count(state.changeCount)],
      ["leak", "Find the leaker"],
      ["alerts", "Security alerts" + count(state.alertCount)]]]);
  }
  if (me && me.actingAs === "user") {
    links.push(["Data user", [["user", "User dashboard"], ["search", "Search"], ["results", "Search results"],
      ["myrequests", "My access requests"], ["mychanges", "My suggested changes"], ["replay", "Security test"]]]);
  }
  if (me) links.push(["Information", [["trace", "Ownership claims"], ["access", "Access and roles"], ["logs", "Activity logs"]]]);

  const cur = (location.hash.replace(/^#\//, "") || "home").split("?")[0];
  document.getElementById("nav").innerHTML = links.map(([h, items]) =>
    `<h4>${esc(h)}</h4>` + items.map(([r, label]) =>
      `<a href="#/${r}" class="${r === cur ? "active" : ""}">${label}</a>`).join("")).join("");
}

// ------------------------------------------------------------------ pages
const pages = {};

pages.setup = async () => {
  const st = state.status;
  if (st.initialized) {
    render(`<h1>Setup</h1><div class="panel ok"><p>The system was set up on ${fmt(st.setupAt)}.
      Roles: ${esc((st.attributes || []).join(", "))}.</p></div><a class="btn" href="#/home">Go to home</a>`);
    return;
  }
  render(`<h1>First-time setup</h1>
    <p class="lead">This prepares the system's security settings. It runs only once; after that the same settings are loaded every time the system starts.</p>
    <div class="panel">
      <label for="attrs">Roles in your organisation <span class="hint">separate with commas</span></label>
      <input type="text" id="attrs" value="${esc(st.defaultAttributes.join(", "))}">
      <p class="hint">Cloud storage server: ${st.cspOnline ? tag("ok", "online") : tag("alarm", "offline - start the cloud server first")}</p>
      <div class="actions"><button id="runSetup">Run Setup</button></div>
    </div><div id="out"></div>`);
  document.getElementById("runSetup").onclick = e => busy(e.target, async () => {
    const attributes = document.getElementById("attrs").value.split(",").map(x => x.trim()).filter(Boolean);
    await POST("/api/setup", { attributes });
    toast("Setup complete.");
    document.getElementById("out").innerHTML = `<div class="panel ok"><p>The system is ready.</p>
      <a class="btn" href="#/register">Register the first user</a></div>`;
    await boot(false);
  });
};

pages.home = async () => {
  const st = state.status, c = st.csp || {};
  render(`<h1>Minos secure document sharing</h1>
    <p class="lead">Owners upload documents that are encrypted before they reach the cloud. Users search with keywords and can open only
      the documents their role allows. Every access is recorded, misuse is detected, and owners stay in control of every change.</p>
    <div class="grid2">
      <div class="panel"><h2 style="margin-top:0">System</h2>
        <div class="statrow">
          <div><b class="stat">${esc(st.users)}</b><span>registered users</span></div>
          <div><b class="stat">${esc(st.documents)}</b><span>documents</span></div>
          <div><b class="stat">${esc(c.alerts ?? "–")}</b><span>security alerts</span></div>
        </div>
        <p class="hint">Roles: ${esc((st.attributes || []).join(", "))}</p>
        <p class="hint">Cloud storage server: ${st.cspOnline ? tag("ok", "online") : tag("alarm", "offline")}</p>
      </div>
      <div class="panel"><h2 style="margin-top:0">Get started</h2>
        ${state.me ? `<p>You are logged in as <b>${esc(state.me.userId)}</b>.</p>
          <a class="btn" href="#/${state.me.actingAs === "owner" ? "owner" : "user"}">Open my dashboard</a>` :
        `<p>Register an account, then log in as a <b>data owner</b> to upload documents or as a <b>data user</b> to search.
          One account can do both.</p>
        <div class="actions"><a class="btn" href="#/register">Register</a><a class="btn secondary" href="#/login">Log in</a></div>`}
      </div>
    </div>`);
};

pages.register = async () => {
  const attrs = state.status.attributes || [];
  render(`<h1>Register</h1>
    <p class="lead">Your security keys are created automatically and kept safe on the server. Choose the roles you hold.</p>
    <div class="panel">
      <label for="uid">User ID <span class="hint">letters, digits, dot, dash, underscore</span></label><input type="text" id="uid" autocomplete="username">
      <label for="dname">Display name</label><input type="text" id="dname">
      <label for="pw">Password <span class="hint">at least 8 characters</span></label><input type="password" id="pw" autocomplete="new-password">
      <label>Roles</label>
      <div class="checks">${attrs.map(a => `<label><input type="checkbox" name="attr" value="${esc(a)}"> ${esc(a)}</label>`).join("")}</div>
      <div class="actions"><button id="doReg">Register</button></div>
    </div><div id="out"></div>`);
  document.getElementById("doReg").onclick = e => busy(e.target, async () => {
    const attributes = [...document.querySelectorAll("input[name=attr]:checked")].map(x => x.value);
    const r = await POST("/api/register", {
      userId: document.getElementById("uid").value.trim(),
      displayName: document.getElementById("dname").value.trim(),
      password: document.getElementById("pw").value, attributes
    });
    toast("Account " + r.userId + " is ready.");
    document.getElementById("out").innerHTML = `<div class="panel ok">
      <p>Account <b>${esc(r.userId)}</b> is ready. Roles: ${esc(r.attributes.join(", ") || "none")}.</p>
      <a class="btn" href="#/login">Log in</a></div>`;
    state.status = await GET("/api/status");
  });
};

pages.login = async () => {
  render(`<h1>Log in</h1>
    <div class="panel">
      <label for="uid">User ID</label><input type="text" id="uid" autocomplete="username">
      <label for="pw">Password</label><input type="password" id="pw" autocomplete="current-password">
      <label>Log in as</label>
      <div class="checks">
        <label><input type="radio" name="role" value="user" checked> Data user (search and open documents)</label>
        <label><input type="radio" name="role" value="owner"> Data owner (upload and manage documents)</label>
      </div>
      <div class="actions"><button id="doLogin">Log in</button></div>
    </div>`);
  const submit = () => busy(document.getElementById("doLogin"), async () => {
    const actingAs = document.querySelector("input[name=role]:checked").value;
    const r = await POST("/api/login", {
      userId: document.getElementById("uid").value.trim(),
      password: document.getElementById("pw").value, actingAs
    });
    state.me = r.user;
    await refreshSession();
    go(actingAs === "owner" ? "owner" : "user");
  });
  document.getElementById("doLogin").onclick = submit;
  document.getElementById("pw").addEventListener("keydown", e => { if (e.key === "Enter") submit(); });
};

// ---------- owner
pages.owner = async () => {
  const [docs, alerts, rev, reqs, changes, log] = await Promise.all([
    GET("/api/owner/documents"), GET("/api/owner/alerts"), GET("/api/owner/revocations"),
    GET("/api/owner/access-requests"), GET("/api/owner/changes"), GET("/api/owner/document-log")]);
  const pending = reqs.requests.filter(r => r.status === "PENDING").length;
  const pendingChanges = changes.changes.filter(c => c.status === "PENDING").length;
  render(`<h1>Owner dashboard</h1>
    ${alerts.alerts.length ? `<div class="panel alarm"><b>${alerts.alerts.length} security alert${alerts.alerts.length > 1 ? "s" : ""}</b>
      for your documents. <a href="#/alerts">Review alerts</a></div>` : ""}
    ${pending ? `<div class="panel alarm"><b>${pending} access request${pending > 1 ? "s" : ""}</b> waiting for your decision.
      <a href="#/requests">Review requests</a></div>` : ""}
    ${pendingChanges ? `<div class="panel alarm"><b>${pendingChanges} suggested change${pendingChanges > 1 ? "s" : ""}</b> waiting for your review.
      <a href="#/changes">Review changes</a></div>` : ""}
    <h2>My documents</h2>
    ${table(["Document", "Who can access", "Your approval", "Current version", "Uploaded", ""], docs.documents.map(d => [
      `<b>${esc(d.fileName)}</b>`, esc(d.policy),
      d.requireApproval ? tag("ext", "required") : tag("plain", "not required"),
      esc(versionLabel(d.currentVersion || 1)), fmt(d.uploadedAt),
      `<button class="secondary" data-dl="${esc(d.documentId)}" data-name="${esc(d.fileName)}">Download</button>
       <a class="btn secondary" href="#/history?doc=${encodeURIComponent(d.documentId)}">History</a>`]),
      "No documents yet. Upload one to get started.")}
    <div class="actions"><a class="btn" href="#/upload">Upload document</a></div>
    <h2>Blocked users</h2>
    ${table(["User", "Blocked on", "Cause", ""], rev.revocations.map(r => [esc(r.userId), fmt(r.revokedAt),
      r.alertId ? "security alert" : "manual",
      `<button class="secondary" data-restore="${esc(r.userId)}">Restore access</button>`]), "Nobody is blocked.")}
    <h2>Recent activity on my documents</h2>
    ${logTable(log.log.slice(0, 30), true)}`);
  bindRestore();
  document.querySelectorAll("[data-dl]").forEach(b => b.onclick = () => busy(b, () =>
    downloadFile(`/api/owner/documents/${encodeURIComponent(b.dataset.dl)}/download`, b.dataset.name)));
};

function logTable(entries, withDoc) {
  const cols = ["Date and time", "User"].concat(withDoc ? ["Document"] : []).concat(["Action", "Version", "Details"]);
  return table(cols, entries.map(e => [fmt(e.time), `<b>${esc(e.userId)}</b>`]
    .concat(withDoc ? [esc(e.fileName || "")] : [])
    .concat([actionTag(e.action), e.version ? esc(versionLabel(e.version)) : "", esc(e.detail || "")])),
    "No activity yet.");
}

function bindRestore() {
  document.querySelectorAll("[data-restore]").forEach(b => b.onclick = () => busy(b, async () => {
    await POST("/api/owner/revocations/remove", { userId: b.dataset.restore });
    toast("Access restored for " + b.dataset.restore);
    route();
  }));
}

pages.upload = async () => {
  const attrs = state.status.attributes || [];
  render(`<h1>Upload document</h1>
    <p class="lead">Your document is encrypted before it is stored in the cloud. The cloud never sees its content or its keywords.</p>
    <div class="panel">
      <label for="file">Document</label><input type="file" id="file">
      <label for="kw">Keywords <span class="hint">words people will search for, separated by commas</span></label><input type="text" id="kw">
      <label>Who can access <span class="hint">anyone with at least one ticked role</span></label>
      <div class="checks">${attrs.map(a => `<label><input type="checkbox" name="role" value="${esc(a)}"> ${esc(a)}</label>`).join("")}</div>
      <label for="pol">Or write a rule <span class="hint">optional, e.g. (Finance AND Manager) OR Admin</span></label>
      <input type="text" id="pol" placeholder="leave empty to use the ticked roles">
      <label>Your approval</label>
      <div class="checks"><label><input type="checkbox" id="approve" checked> Users must ask me first. I decide who may view, download or modify.</label></div>

      <div class="actions"><button id="doUp">Upload</button></div>
    </div><div id="out"></div>`);
  document.getElementById("doUp").onclick = e => busy(e.target, async () => {
    const f = document.getElementById("file").files[0];
    if (!f) throw new Error("Choose a document to upload.");
    if (f.size > 25 * 1024 * 1024) throw new Error("Documents up to 25 MB are supported.");
    const dataBase64 = await readFileBase64(f);
    const allowedRoles = [...document.querySelectorAll("input[name=role]:checked")].map(x => x.value);
    const r = await POST("/api/owner/documents", {
      fileName: f.name, contentType: f.type, dataBase64,
      keywords: document.getElementById("kw").value, allowedRoles,
      policy: document.getElementById("pol").value.trim(),
      requireApproval: document.getElementById("approve").checked,
      leakTracing: true
    });
    toast(r.fileName + " uploaded.");
    document.getElementById("out").innerHTML = `<div class="panel ok">
      <p><b>${esc(r.fileName)}</b> was encrypted and uploaded. Who can access: <b>${esc(r.policy)}</b>.</p>
      <p>${document.getElementById("approve").checked ? "Users will need your approval (see Access requests)."
        : "Users with these roles can open it without asking you."}</p>
      <p>${r.leakTracing ? `Leak tracing is on: every copy a user views or downloads is unique and recorded
        (${esc(r.changePoints)} place${r.changePoints === 1 ? "" : "s"} where copies can differ). Your own download is always the exact original.`
        : "Leak tracing is off for this document: users receive the exact original."}</p></div>
      ${r.leakTracingWarning ? `<div class="panel alarm"><p style="margin:0">${esc(r.leakTracingWarning)}</p></div>` : ""}`;
  });
};

pages.requests = async () => {
  const reqs = (await GET("/api/owner/access-requests")).requests;
  const pending = reqs.filter(r => r.status === "PENDING"), done = reqs.filter(r => r.status !== "PENDING");
  const checks = r => {
    const p = r.permissions && r.permissions.length ? r.permissions : ["VIEW"];
    return `<div class="checks">${["VIEW", "DOWNLOAD", "MODIFY"].map(x =>
      `<label><input type="checkbox" data-perm="${x}" data-for="${esc(r.requestId)}" ${p.includes(x) ? "checked" : ""}> ${PERM_LABEL[x]}</label>`).join("")}</div>`;
  };
  const row = r => [`<b>${esc(r.userId)}</b><br><span class="hint">${esc((r.userAttributes || []).join(", "))}</span>`,
    esc(r.fileName || r.documentId), fmt(r.requestedAt),
    approvalTag(r.status) + (r.status === "APPROVED" ? "<br>" + permTags(r.permissions) : ""),
    checks(r) + `<div class="actions" style="margin-top:6px">
      <button data-decide="approve" data-id="${esc(r.requestId)}">${r.status === "APPROVED" ? "Save permissions" : "Approve"}</button>
      ${r.status !== "DENIED" ? `<button class="danger" data-decide="deny" data-id="${esc(r.requestId)}">Deny</button>` : ""}</div>`];
  render(`<h1>Access requests</h1>
    <p class="lead">Choose what each person may do with your document. You can change this at any time.</p>
    <div class="panel"><p style="margin:0"><b>View</b>: read the document in the browser.
      <b>Download</b>: save a copy. <b>Modify</b>: suggest changes. A suggested change never replaces your document until you approve it,
      and your original is always kept.</p></div>
    <h2>Waiting for your decision</h2>
    ${table(["User", "Document", "Requested", "Status", "Permissions"], pending.map(row), "No requests are waiting.")}
    <h2>Decided</h2>
    ${table(["User", "Document", "Requested", "Status", "Permissions"], done.map(row), "You have not decided any requests yet.")}`);
  document.querySelectorAll("[data-decide]").forEach(b => b.onclick = () => busy(b, async () => {
    const id = b.dataset.id;
    if (b.dataset.decide === "approve") {
      const permissions = [...document.querySelectorAll(`[data-for="${CSS.escape(id)}"]:checked`)].map(x => x.dataset.perm);
      if (!permissions.length) throw new Error("Tick at least one permission.");
      await POST(`/api/owner/access-requests/${encodeURIComponent(id)}/approve`, { permissions });
      toast("Access approved.");
    } else {
      await POST(`/api/owner/access-requests/${encodeURIComponent(id)}/deny`);
      toast("Access denied.");
    }
    await refreshSession(); route();
  }));
};

pages.changes = async () => {
  const ch = (await GET("/api/owner/changes")).changes;
  const pending = ch.filter(c => c.status === "PENDING"), done = ch.filter(c => c.status !== "PENDING");
  const row = c => [`<b>${esc(c.fileName)}</b>`, `<b>${esc(c.proposedBy)}</b>`, fmt(c.proposedAt),
    esc(c.note || ""), esc(c.summary || ""), changeTag(c.status) + (c.ownerComment ? `<br><span class="hint">${esc(c.ownerComment)}</span>` : ""),
    `<a class="btn ${c.status === "PENDING" ? "" : "secondary"}" href="#/review?doc=${encodeURIComponent(c.documentId)}&v=${c.version}">
      ${c.status === "PENDING" ? "Review" : "Open"}</a>`];
  render(`<h1>Change requests</h1>
    <p class="lead">People you allowed to modify a document can only <b>suggest</b> changes. Nothing changes until you approve it,
      and every earlier version is kept.</p>
    <h2>Waiting for your review</h2>
    ${table(["Document", "Suggested by", "When", "Their note", "What changed", "Status", ""], pending.map(row), "No changes are waiting.")}
    <h2>Decided</h2>
    ${table(["Document", "Suggested by", "When", "Their note", "What changed", "Status", ""], done.map(row), "Nothing decided yet.")}`);
};

pages.review = async () => {
  const docId = param("doc"), v = param("v");
  const d = await GET(`/api/owner/changes/${encodeURIComponent(docId)}/${encodeURIComponent(v)}`);
  let body;
  if (d.kind === "text") {
    const lines = d.lines.map(l => {
      const cls = l.type === "added" ? "diff-add" : l.type === "removed" ? "diff-del" : "diff-same";
      const sign = l.type === "added" ? "+" : l.type === "removed" ? "−" : " ";
      return `<div class="${cls}"><span class="diff-sign">${sign}</span>${esc(l.text) || "&nbsp;"}</div>`;
    }).join("");
    body = `<p class="legend">${tag("ok", "+ added")} ${tag("alarm", "− removed")}</p><div class="diff">${lines}</div>`;
  } else {
    body = `<p>This file type cannot be compared line by line (${size(d.beforeBytes)} → ${size(d.afterBytes)}).
      Download both versions to compare them.</p>`;
  }
  render(`<h1>Review change</h1>
    <div class="panel">
      <p style="margin-top:0"><b>${esc(d.fileName)}</b> · ${esc(versionLabel(d.version))} suggested by <b>${esc(d.proposedBy)}</b> on ${fmt(d.proposedAt)}</p>
      <p>Their note: “${esc(d.note)}”</p>
      <p>Status: ${changeTag(d.status)} ${d.ownerComment ? "· your comment: " + esc(d.ownerComment) : ""}</p>
      <p class="hint">The change is signed with ${esc(d.proposedBy)}'s personal key, so it cannot be denied later.</p>
      ${d.basedOnOlderVersion && d.status === "PENDING" ? `<p class="tag alarm" style="display:inline-block">This change was made on
        ${esc(versionLabel(d.baseVersion))}, but the current version is ${esc(versionLabel(d.currentVersion))}.
        Approving it would replace the newer version.</p>` : ""}
      <div class="actions">
        <button class="secondary" data-dl="${d.baseVersion}">Download ${esc(versionLabel(d.baseVersion))}</button>
        <button class="secondary" data-dl="${d.version}">Download suggested version</button>
      </div>
    </div>
    <h2>What changed (compared with ${esc(versionLabel(d.baseVersion))})</h2>
    ${body}
    ${d.status === "PENDING" ? `<div class="panel">
      <label for="cmt">Comment for ${esc(d.proposedBy)} <span class="hint">optional</span></label>
      <input type="text" id="cmt">
      <div class="actions"><button id="ok">Approve change</button><button class="danger" id="no">Reject change</button></div>
    </div>` : ""}
    <div class="actions"><a class="btn secondary" href="#/changes">Back to change requests</a>
      <a class="btn secondary" href="#/history?doc=${encodeURIComponent(docId)}">Document history</a></div>`);
  document.querySelectorAll("[data-dl]").forEach(b => b.onclick = () => busy(b, () =>
    downloadFile(`/api/owner/documents/${encodeURIComponent(docId)}/download?version=${b.dataset.dl}`, d.fileName)));
  const decide = (btn, ok) => busy(btn, async () => {
    await POST(`/api/owner/changes/${encodeURIComponent(docId)}/${encodeURIComponent(v)}/${ok ? "approve" : "reject"}`,
      { comment: document.getElementById("cmt").value });
    toast(ok ? "Change approved. It is now the current version." : "Change rejected. The document is unchanged.");
    await refreshSession(); route();
  });
  if (document.getElementById("ok")) {
    document.getElementById("ok").onclick = e => decide(e.target, true);
    document.getElementById("no").onclick = e => decide(e.target, false);
  }
};

pages.history = async () => {
  const docId = param("doc");
  const h = await GET(`/api/owner/documents/${encodeURIComponent(docId)}/history`);
  render(`<h1>History of ${esc(h.fileName)}</h1>
    <p class="lead">Every version is kept. You can always download the original you uploaded.</p>
    <h2>Versions</h2>
    ${table(["Version", "Made by", "When", "Note", "What changed", "Status", ""], h.versions.map(v => [
      `<b>${esc(versionLabel(v.version))}</b>${Number(v.version) === Number(h.currentVersion) ? " " + tag("ok", "current") : ""}`,
      esc(v.proposedBy), fmt(v.proposedAt), esc(v.note || ""), esc(v.summary || ""),
      changeTag(v.status) + (v.ownerComment ? `<br><span class="hint">${esc(v.ownerComment)}</span>` : ""),
      `<button class="secondary" data-dl="${v.version}">Download</button>` +
      (Number(v.version) > 1 ? ` <a class="btn secondary" href="#/review?doc=${encodeURIComponent(docId)}&v=${v.version}">Changes</a>` : "")]))}
    <h2>Who accessed this document</h2>
    ${logTable(h.log, false)}
    <h2>Traceable copies issued</h2>
    <div id="copies"><p class="empty">Loading…</p></div>
    <div class="actions"><a class="btn secondary" href="#/owner">Back to dashboard</a></div>`);
  document.querySelectorAll("[data-dl]").forEach(b => b.onclick = () => busy(b, () =>
    downloadFile(`/api/owner/documents/${encodeURIComponent(docId)}/download?version=${b.dataset.dl}`, h.fileName)));
  const c = await GET(`/api/owner/documents/${encodeURIComponent(docId)}/copies`).catch(() => ({ copies: [] }));
  const box = document.getElementById("copies");
  if (box) box.innerHTML = table(["Copy reference", "Given to", "How", "Version", "When"], c.copies.map(x => [
    `<span class="mono">${esc(x.copyId)}</span>`, `<b>${esc(x.userId)}</b>`,
    tag("plain", x.channel === "VIEW" ? "Viewed in browser" : "Downloaded"), esc(versionLabel(x.version)), fmt(x.issuedAt)]),
    "No traceable copies have been given out yet.");
};

pages.alerts = async () => {
  const [a, rev] = await Promise.all([GET("/api/owner/alerts"), GET("/api/owner/revocations")]);
  const revoked = new Set(rev.revocations.map(r => r.userId));
  render(`<h1>Security alerts</h1>
    <p class="lead">Each search token works only once. If someone tries to use a token again (for example one that was copied or shared),
      the search is refused and the system finds out which account the token belongs to. False ownership claims on your documents,
      and attempts to copy, print or screenshot a document on the View page, are also shown here.</p>
    <div class="panel"><p style="margin:0">The alert names the <b>account</b> the search token was issued to. It does not prove who physically
      sent the copy: the account holder may have shared it, or it may have been stolen.</p></div>
    ${a.alerts.length ? a.alerts.map(x => {
      const card = alertCard(x, revoked);
      return x.seen ? card : card.replace('<h2 style="margin:0 0 4px">', '<h2 style="margin:0 0 4px">' + tag("ext", "new") + " ");
    }).join("") : `<p class="empty">No alerts.</p>`}`);
  // the owner has now seen these alerts: clear the number in the menu
  if (a.unseen) {
    POST("/api/owner/alerts/seen").then(() => { state.alertCount = 0; drawChrome(); }).catch(() => {});
  }
  document.querySelectorAll("[data-revoke]").forEach(b => b.onclick = () => busy(b, async () => {
    await POST("/api/owner/revocations", { userId: b.dataset.revoke, alertId: b.dataset.alert });
    toast(b.dataset.revoke + " is now blocked from your documents.");
    await refreshSession(); route();
  }));
  document.querySelectorAll("[data-detect]").forEach(b => b.onclick = () => busy(b, async () => {
    await POST("/api/owner/alerts/" + encodeURIComponent(b.dataset.detect) + "/detect");
    toast("Check finished."); route();
  }));
  bindRestore();
};

function blockButtons(x, who, isRevoked) {
  return `<div class="actions">
    ${who && !isRevoked ? `<button class="danger" data-revoke="${esc(who)}" data-alert="${esc(x.alertId)}">Block ${esc(who)} from my documents</button>` : ""}
    ${who && isRevoked ? `<button class="secondary" data-restore="${esc(who)}">Restore ${esc(who)}'s access</button>` : ""}
  </div>`;
}

function alertCard(x, revoked) {
  if (x.type === "FALSE_OWNERSHIP_CLAIM") return claimAlertCard(x, revoked);
  if (x.type === "VIEW_PROTECTION") return viewAlertCard(x, revoked);
  const who = x.identifiedUserId;
  const isRevoked = who && revoked.has(who);
  const tampered = x.trapdoorIntegrity && !String(x.trapdoorIntegrity).startsWith("verified");
  return `<div class="panel alert-card">
    <h2 style="margin:0 0 4px">Security alert ${tag("alarm", "search token reused")}</h2>
    <dl>
      <dt>Token belongs to</dt><dd>${who ? `<b>${esc(who)}</b>` : tag("plain", "checking…")}</dd>
      <dt>Document</dt><dd>${esc(x.fileName || "")}</dd>
      <dt>First used</dt><dd>${fmt(x.firstUsedAt)}${x.firstSubmittedBy ? " · by " + esc(x.firstSubmittedBy) : ""}</dd>
      <dt>Used again</dt><dd>${fmt(x.reusedAt)}${x.reusedBy ? " · by " + esc(x.reusedBy) : ""}</dd>
      <dt>What happened</dt><dd>The same search token was used a second time, so the search was refused.
        ${tampered ? "The copy had also been altered." : ""}</dd>
      <dt>Access</dt><dd>${who ? (isRevoked ? tag("alarm", "blocked") : tag("ok", "still has access")) : ""}</dd>
    </dl>
    ${blockButtons(x, who, isRevoked)}
    ${x.detectStatus !== "IDENTIFIED" ? `<div class="actions"><button class="secondary" data-detect="${esc(x.alertId)}">Find the account now</button></div>` : ""}
  </div>`;
}

function viewAlertCard(x, revoked) {
  const who = x.identifiedUserId;
  const isRevoked = who && revoked.has(who);
  const what = { COPY_ATTEMPT: "tried to copy", PRINT_ATTEMPT: "tried to print", PRINT_SCREEN: "pressed Print Screen" }[x.event] || x.event;
  return `<div class="panel alert-card">
    <h2 style="margin:0 0 4px">Security alert ${tag("alarm", what)}</h2>
    <dl>
      <dt>User</dt><dd><b>${esc(who)}</b></dd>
      <dt>Document</dt><dd>${esc(x.fileName || x.documentId || "")}</dd>
      <dt>What happened</dt><dd>${esc(x.label)}${Number(x.count) > 1 ? ` · <b>${esc(x.count)} times</b>` : ""}</dd>
      <dt>When</dt><dd>${fmt(x.firstAt)}${Number(x.count) > 1 ? " to " + fmt(x.lastAt) : ""}</dd>
      <dt>Note</dt><dd>The page blocked the action or blurred the document. Every copy the user received is marked, so if the text
        appears somewhere you can check it on <a href="#/leak">Find the leaker</a>.</dd>
      <dt>Access</dt><dd>${isRevoked ? tag("alarm", "blocked") : tag("ok", "still has access")}</dd>
    </dl>
    ${blockButtons(x, who, isRevoked)}
  </div>`;
}

function claimAlertCard(x, revoked) {
  const who = x.identifiedUserId;
  const isRevoked = who && revoked.has(who);
  return `<div class="panel alert-card">
    <h2 style="margin:0 0 4px">Security alert ${tag("alarm", "false ownership claim")}</h2>
    <dl>
      <dt>Claimed by</dt><dd><b>${esc(who)}</b></dd>
      <dt>Document</dt><dd>${esc(x.fileName || "")}</dd>
      <dt>When</dt><dd>${fmt(x.claimedAt)}</dd>
      <dt>Reason given</dt><dd>${esc(x.claimantReason || "–")}</dd>
      <dt>Result</dt><dd>The check proved that ${esc(who)} is not the owner.</dd>
      <dt>False claims</dt><dd>${esc(x.falseClaimsIn24h)} of ${esc(x.maxFalseClaims)} in 24 hours
        ${x.claimantBlocked ? tag("alarm", "blocked from new claims") : ""}</dd>
      <dt>Access</dt><dd>${isRevoked ? tag("alarm", "blocked") : tag("ok", "still has access")}</dd>
    </dl>
    ${blockButtons(x, who, isRevoked)}
  </div>`;
}

// ---------- find the leaker (owner)
function readFileText(file) {
  return new Promise((res, rej) => {
    const fr = new FileReader();
    fr.onload = () => res(String(fr.result));
    fr.onerror = () => rej(new Error("Could not read the file."));
    fr.readAsText(file, "utf-8");
  });
}

function leakMatchTable(list) {
  return table(["Copy given to", "Document", "How", "When", "Evidence", "Copy reference"], list.map(m => [
    `<b>${esc(m.userId)}</b>${m.displayName && m.displayName !== m.userId ? `<br><span class="hint">${esc(m.displayName)}</span>` : ""}`,
    esc(m.fileName) + `<br><span class="hint">${esc(versionLabel(m.version))}</span>`,
    tag("plain", m.channel === "VIEW" ? "Viewed in browser" : "Downloaded"), fmt(m.issuedAt), esc(m.evidence),
    `<span class="mono">${esc(m.copyId)}</span>`]));
}

/** "1 in N": chance that an unrelated copy agrees on at least (n - k) of n coin-flip differences. */
function oneIn(n, k) {
  let ways = 0, c = 1;
  for (let i = 0; i <= k; i++) { ways += c; c = c * (n - i) / (i + 1); }
  const v = Math.round(Math.pow(2, n) / ways);
  return v >= 1e6 ? (v / 1e6).toFixed(v >= 1e7 ? 0 : 1) + " million" : v.toLocaleString();
}

function pctBar(p, best) {
  return `<div class="pct"><div class="pct-bar ${best ? "best" : ""}" style="width:${Math.max(2, Math.min(100, p))}%"></div></div>`;
}

function rankingTable(list, total) {
  if (!list || !list.length) return "";
  const rows = list.map((m, i) => [
    `<b>${esc(m.userId)}</b>${m.displayName && m.displayName !== m.userId ? `<br><span class="hint">${esc(m.displayName)}</span>` : ""}`,
    tag("plain", m.channel === "VIEW" ? "Viewed in browser" : "Downloaded") + `<br><span class="hint">${fmt(m.issuedAt)}</span>`,
    `<b>${m.hiddenCode ? "100" : esc(m.percent)}%</b> ${m.hiddenCode ? tag("ok", "hidden code") : ""}${pctBar(m.hiddenCode ? 100 : m.percent, i === 0)}`,
    m.hiddenCode ? "signed hidden code found" : `${esc(m.matched)} of ${esc(m.observed)} differences match`,
    `<span class="mono">${esc(m.copyId)}</span>`]);
  return `<h2>How well each copy matches</h2>
    <p class="hint">Every copy of <b>${esc(list[0].fileName)}</b> that was given out, best match first.
      A copy that was <i>not</i> leaked matches about 50% just by chance, so look for one copy near 100% and the rest far below.
      ${total > list.length ? `Showing the best ${list.length} of ${total} copies.` : ""}</p>
    ${table(["Copy given to", "How and when", "Match", "Details", "Copy reference"], rows)}`;
}

function modificationsBlock(md) {
  if (!md) return "";
  const title = `<h2>Changes compared with the original${md.fileName ? ` (${esc(md.fileName)})` : ""}</h2>`;
  if (!md.compared) return `${title}<p class="hint">${esc(md.reason)}</p>`;
  const changed = md.linesRemoved + md.linesAdded;
  const summary = changed
    ? `<b>${esc(md.linesRemoved)} line${md.linesRemoved === 1 ? "" : "s"} removed</b> and <b>${esc(md.linesAdded)} line${md.linesAdded === 1 ? "" : "s"} added</b>
       compared with your original (${esc(md.linesSame)} line${md.linesSame === 1 ? "" : "s"} unchanged).`
    : `<b>No changes.</b> Every line of the leaked text is the same as your original.`;
  const rows = md.rows.map(r => {
    if (r.type === "fold") {
      const range = r.toLine && r.toLine !== r.line ? `${esc(r.line)}–${esc(r.toLine)}` : esc(r.line);
      return `<div class="diff-fold ${r.what === "removed" ? "fold-del" : ""}">⋯ ${esc(r.count)} ${r.what === "removed" ? "more removed" : "unchanged"} line${r.count === 1 ? "" : "s"} (${range}) ⋯</div>`;
    }
    const num = r.line ? `<span class="diff-num">${esc(r.line)}</span>` : `<span class="diff-num"></span>`;
    if (r.type === "misread") {
      return `<div class="diff-misread" title="Original: ${esc(r.original)}">${num}<span class="diff-sign">~</span>${esc(r.text) || "&nbsp;"}
        <span class="hint">(probably misread from the screenshot)</span></div>`;
    }
    const cls = r.type === "added" ? "diff-add" : r.type === "removed" ? "diff-del" : "diff-same";
    const sign = r.type === "added" ? "+" : r.type === "removed" ? "−" : " ";
    return `<div class="${cls}">${num}<span class="diff-sign">${sign}</span>${esc(r.text) || "&nbsp;"}</div>`;
  }).join("");
  return `${title}
    <div class="panel ${changed ? "alarm" : "ok"}"><p style="margin:0">${summary}</p>
      <p class="hint" style="margin-bottom:0">The small per-copy differences (such as 2000 / 2,000 or cannot / can't), capital letters,
        spaces and punctuation are ignored, so only real edits are shown.${md.reflowed ? " The pasted text was one long line (as Google Lens gives it), so it was matched back to the original's lines." : ""}
        ${md.linesMisread ? ` ${esc(md.linesMisread)} line${md.linesMisread === 1 ? "" : "s"} differ by one letter only, probably a misread (marked ~).` : ""}</p></div>
    <p class="legend">${tag("ok", "+ added in the leaked text")} ${tag("alarm", "− removed from the original")} <span class="hint">Numbers are line numbers in your original.</span></p>
    <div class="diff">${rows}</div>
    ${md.truncated ? `<p class="hint">Only the first part of a very long comparison is shown.</p>` : ""}`;
}

pages.leak = async () => {
  render(`<h1>Find the leaker</h1>
    <p class="lead">Found your document somewhere it should not be? Paste the text or upload the file here. Every copy a user viewed or
      downloaded was made unique, so the system can tell whose copy it was.</p>
    <div class="panel">
      <p style="margin-top:0"><b>Copied or forwarded text</b> carries a hidden code on every line: even two copied lines are enough.<br>
      <b>Screenshot or printout</b>: type the lines you can see (with the exact numbers, dates and words). Small differences in
      wording identify the copy.</p>
      <label for="lt">Leaked text</label>
      <textarea id="lt" class="editor" style="min-height:200px" placeholder="Paste the leaked text here"></textarea>
      <label for="lf">Or upload the leaked file <span class="hint">.txt</span></label>
      <input type="file" id="lf" accept=".txt,.csv,.md,.log,text/*">
      <div class="actions"><button id="chk">Find whose copy this is</button></div>
    </div><div id="out"></div>`);
  document.getElementById("lf").onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    try { document.getElementById("lt").value = await readFileText(f); toast("Loaded " + f.name); }
    catch (x) { toast(x.message, true); }
  };
  document.getElementById("chk").onclick = e => busy(e.target, async () => {
    const text = document.getElementById("lt").value;
    if (!text.trim()) throw new Error("Paste the leaked text or upload the file.");
    const r = await POST("/api/owner/leak-check", { text });
    const out = document.getElementById("out");
    const first = (r.exactMatches[0] || r.wordingMatches[0]);
    let head;
    if (r.verdict === "EXACT") head = `<div class="panel alarm"><h2 style="margin:0">This is <b>${esc(first.userId)}</b>'s copy</h2>
      <p style="margin-bottom:0">The hidden code in the text matches a copy given only to ${esc(first.userId)}. The code is signed by this server,
      so it cannot have been invented to blame someone else.</p></div>`;
    else if (r.verdict === "SEVERAL_EXACT") head = `<div class="panel alarm"><h2 style="margin:0">Text from several copies</h2>
      <p style="margin-bottom:0">The text contains lines from more than one person's copy. They may have combined their copies.</p></div>`;
    else if (r.verdict === "WORDING_UNIQUE") {
      const top = (r.ranking || [])[0] || first, next = (r.ranking || [])[1];
      const p = top.percent != null ? top.percent : 100;
      const obs = top.observed || first.observed;
      head = `<div class="panel alarm"><h2 style="margin:0"><b>${esc(p)}%</b> match with <b>${esc(first.userId)}</b>'s copy</h2>
      <p>There was no hidden code (for example a screenshot, a printout or retyped text), so the visible wording differences were compared:
        <b>${esc(top.matched != null ? top.matched : obs)} of ${esc(obs)}</b> match the copy given to ${esc(first.userId)}${first.mismatched
        ? ` (${esc(first.mismatched)} probably misread, which is normal for screenshots)` : ""}.
        ${next ? `The next closest copy (${esc(next.userId)}) matches only <b>${esc(next.percent)}%</b>.` : ""}</p>
      <p class="hint" style="margin-bottom:0">Chance that a different copy would match this well by accident: about 1 in
        ${oneIn(obs, first.mismatched || 0)}.</p></div>`;
    }
    else if (r.verdict === "WORDING_SEVERAL") head = `<div class="panel"><h2 style="margin:0">Could be one of ${r.wordingMatches.length} copies</h2>
      <p style="margin-bottom:0">The text is too short to tell these copies apart. Add more lines (especially lines with numbers, dates or
      words like "cannot" / "can't") and check again.</p></div>`;
    else head = `<div class="panel ok"><h2 style="margin:0">No matching copy found</h2>
      <p>This text does not match any copy of your documents that was given to a user.</p>
      <p class="hint" style="margin-bottom:0">${r.observedPoints
        ? `${r.observedPoints} place${r.observedPoints === 1 ? "" : "s"} where copies differ ${r.observedPoints === 1 ? "was" : "were"} recognised, but they do not fit any copy. Check that the text recognition read the numbers, dates and short forms correctly.`
        : "None of the places where copies differ (numbers, dates, words like cannot / can't) were recognised. Paste more lines, exactly as they appear."}
        It may also come from your own original, from a copy you downloaded yourself, or from a document with leak tracing switched off.</p></div>`;
    out.innerHTML = head
      + (r.alteredMarks ? `<div class="panel alarm"><p style="margin:0">${esc(r.alteredMarks)} hidden code${r.alteredMarks === 1 ? " was" : "s were"}
          altered or forged. Someone tried to change the code, possibly to blame another person.</p></div>` : "")
      + (r.otherOwnersCopies ? `<p class="hint">The text also contains codes from another owner's documents (not shown).</p>` : "")
      + (r.exactMatches.length ? `<h2>Matched by the hidden code</h2>${leakMatchTable(r.exactMatches)}` : "")
      + rankingTable(r.ranking, r.copiesCompared)
      + modificationsBlock(r.modifications)
      + (first && first.userId ? `<div class="actions"><a class="btn secondary" href="#/alerts">Security alerts (block a user)</a>
          <a class="btn secondary" href="#/history?doc=${encodeURIComponent(first.documentId)}">Document history</a></div>` : "");
    out.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
};

// ---------- ownership claims (any logged-in user)
function claimTag(r) {
  return ({ VERIFIED: tag("ok", "confirmed owner"), FALSE_CLAIM: tag("alarm", "false claim"),
    BLOCKED: tag("alarm", "blocked") })[r] || tag("plain", r);
}

pages.trace = async () => {
  const [docs, claims] = await Promise.all([GET("/api/documents"), GET("/api/ownership/claims")]);
  if (!docs.documents.length) {
    render(`<h1>Ownership claims</h1><p class="empty">No documents have been uploaded yet, so there is nothing to claim.</p>`);
    return;
  }
  const me = state.me.userId;
  render(`<h1>Ownership claims</h1>
    <p class="lead">Anyone can claim to own a document. The system checks the claim with the claimant's own security keys;
      only the real owner's claim succeeds.</p>
    <div class="panel"><p style="margin:0">A false claim is recorded and the real owner is alerted.
      After 3 false claims within 24 hours, the person cannot make more claims until the 24 hours pass.</p></div>
    <div class="panel">
      <label for="doc">Document</label>
      <select id="doc">${docs.documents.map(d => `<option value="${esc(d.documentId)}">${esc(d.fileName)} (owner ${esc(d.ownerUserId)})</option>`).join("")}</select>
      <label for="reason">Reason for the claim <span class="hint">optional; the owner sees it if the claim is false</span></label>
      <textarea id="reason" style="min-height:70px" placeholder="e.g. I created this file"></textarea>
      <label for="kw">Keyword <span class="hint">optional</span></label>
      <input type="text" id="kw">
      <div class="actions"><button id="doClaim">Claim ownership as ${esc(me)}</button></div>
    </div><div id="out"></div>
    <h2>Claims I made</h2>
    ${table(["Date and time", "Document", "Result"], claims.myClaims.map(c => [fmt(c.claimedAt), esc(c.fileName || c.documentId),
      claimTag(c.result) + (c.result === "FALSE_CLAIM" ? `<br><span class="hint">${esc(c.falseClaimsIn24h)} of 3 in 24 h</span>` : "")]),
      "You have not made any ownership claims.")}
    <h2>Claims on my documents</h2>
    ${table(["Date and time", "Document", "Claimed by", "Reason given", "Result"], claims.claimsOnMyDocuments.map(c => [fmt(c.claimedAt),
      esc(c.fileName || c.documentId), `<b>${esc(c.claimantUserId)}</b>`, esc(c.reason || "–"), claimTag(c.result)]),
      "Nobody has claimed your documents.")}`);
  document.getElementById("doClaim").onclick = e => busy(e.target, async () => {
    const r = await POST("/api/ownership/claim", { documentId: document.getElementById("doc").value,
      keyword: document.getElementById("kw").value, reason: document.getElementById("reason").value });
    let html;
    if (r.status === "VERIFIED") {
      html = `<div class="panel ok"><p>Confirmed: <b>${esc(r.claimant)}</b> is the owner of <b>${esc(r.fileName)}</b>.</p></div>`;
    } else if (r.status === "BLOCKED") {
      html = `<div class="panel alarm"><p><b>Claim refused.</b> ${esc(r.claimant)} made ${esc(r.falseClaims)} false ownership claims in the
        last 24 hours and cannot make claims until ${fmt(r.blockedUntil)}.</p></div>`;
    } else {
      html = `<div class="panel alarm"><p><b>False claim.</b> ${esc(r.claimant)} is not the owner of <b>${esc(r.fileName)}</b>.
        The claim was recorded and the owner was alerted. False claims in the last 24 hours: <b>${esc(r.falseClaims)} of ${esc(r.maxFalseClaims)}</b>.
        ${r.blocked ? "<br><b>The limit is reached: further ownership claims are blocked for 24 hours.</b>" : ""}</p></div>`;
    }
    route();
    setTimeout(() => { const o = document.getElementById("out"); if (o) { o.innerHTML = html; o.scrollIntoView({ block: "nearest" }); } }, 300);
  });
};

// ---------- user
pages.user = async () => {
  const [info, reqs, changes] = await Promise.all([GET("/api/access-info"), GET("/api/user/access-requests"), GET("/api/user/changes")]);
  const usable = info.documents.filter(d => d.permissions && d.permissions.length && !d.revokedByOwner && d.satisfiedByMyAttributes);
  const waiting = reqs.requests.filter(r => r.status === "PENDING").length;
  render(`<h1>User dashboard</h1>
    <p class="lead">Your roles: <b>${esc(info.user.attributes.join(", ") || "none")}</b>.</p>
    <div class="actions"><a class="btn" href="#/search">Search documents</a></div>
    ${waiting ? `<div class="panel"><b>${waiting}</b> access request${waiting > 1 ? "s are" : " is"} waiting for an owner. <a href="#/myrequests">See requests</a></div>` : ""}
    <h2>Documents you can use</h2>
    <p class="hint">Search with one of a document's keywords to open it.</p>
    ${table(["Document", "Owner", "What you can do"], usable.map(d => [esc(d.fileName), esc(d.owner), permTags(d.permissions)]),
      "None yet. Search for a document; if its owner wants to approve you first, a request is sent automatically.")}
    <h2>My suggested changes</h2>
    ${table(["Document", "When", "Note", "Status"], changes.changes.slice(0, 10).map(c => [esc(c.fileName), fmt(c.proposedAt), esc(c.note),
      changeTag(c.status)]), "You have not suggested any changes.")}`);
};

async function runSearch(keyword) {
  state.lastSearch = await POST("/api/user/search", { keyword });
  state.lastSearch.keywordShown = keyword;
  if (location.hash === "#/results") route(); else go("results");
}

pages.search = async () => {
  render(`<h1>Search</h1>
    <p class="lead">Type a keyword. Only documents your role allows are searched. Your keyword is never revealed to the cloud
      or to document owners. If an owner wants to approve you first, a request is sent to them automatically.</p>
    <div class="panel">
      <label for="kw">Keyword</label><input type="text" id="kw" autocomplete="off">
      <div class="actions"><button id="doSearch">Search</button></div>
    </div>`);
  const run = () => busy(document.getElementById("doSearch"), async () => {
    const kw = document.getElementById("kw").value.trim();
    if (!kw) throw new Error("Enter a keyword to search for.");
    await runSearch(kw);
  });
  document.getElementById("doSearch").onclick = run;
  document.getElementById("kw").addEventListener("keydown", e => { if (e.key === "Enter") run(); });
  document.getElementById("kw").focus();
};

pages.results = async () => {
  const s = state.lastSearch;
  if (!s) { render(`<h1>Search results</h1><p class="empty">Run a search first.</p><a class="btn" href="#/search">Search</a>`); return; }
  const waiting = s.denied.filter(d => d.approval);
  const refused = s.denied.filter(d => !d.approval);
  render(`<h1>Search results</h1>
    <p class="lead">Results for “${esc(s.keywordShown || "")}”: ${esc(s.matches.length)} document${s.matches.length === 1 ? "" : "s"} found.</p>
    <div class="actions" style="margin-top:0"><button class="secondary" id="again">Search again</button>
      <a class="btn secondary" href="#/search">New search</a></div>
    <h2>Documents found</h2>
    ${table(["Document", "Owner", "Size", "What you can do"], s.matches.map(m => {
      const p = m.permissions || [];
      return [`<b>${esc(m.fileName)}</b>${m.currentVersion > 1 ? "<br><span class='hint'>" + esc(versionLabel(m.currentVersion)) + "</span>" : ""}`,
        esc(m.owner), size(m.sizeBytes),
        (p.includes("VIEW") ? `<button data-view="${esc(m.documentId)}">View</button> ` : "") +
        (p.includes("DOWNLOAD") ? `<button class="secondary" data-download="${esc(m.documentId)}" data-name="${esc(m.fileName)}">Download</button> ` : "") +
        (p.includes("MODIFY") ? `<button class="secondary" data-edit="${esc(m.documentId)}">Suggest changes</button>` : "") +
        (!p.length ? tag("plain", "no permission") : "")];
    }), "No document matches this keyword (or none you are allowed to open).")}
    ${waiting.length ? `<h2>Waiting for owner approval</h2>
      <p class="hint">Your role fits these documents, but their owners want to approve you first. A request was sent.
        When it is approved, press <b>Search again</b>.</p>
      ${table(["Document", "Owner", "Status"], waiting.map(d => [esc(d.fileName || ""), esc(d.owner),
        d.approval === "PENDING" ? tag("ext", "request sent") : tag("alarm", "denied by owner")]))}` : ""}
    ${refused.length ? `<h2>Not allowed</h2>
      ${table(["Owner", "Reason"], refused.map(d => [esc(d.owner), tag("alarm", plainReason(d.reason))]))}` : ""}`);
  document.getElementById("again").onclick = e => busy(e.target, () => runSearch(s.keywordShown));
  document.querySelectorAll("[data-download]").forEach(b => b.onclick = () => busy(b, async () => {
    await downloadFile(`/api/user/documents/${encodeURIComponent(b.dataset.download)}/download?searchId=${encodeURIComponent(s.searchId)}`, b.dataset.name);
    toast("Downloaded " + b.dataset.name);
  }));
  document.querySelectorAll("[data-view]").forEach(b => b.onclick = () => go(`view?doc=${encodeURIComponent(b.dataset.view)}`));
  document.querySelectorAll("[data-edit]").forEach(b => b.onclick = () => go(`edit?doc=${encodeURIComponent(b.dataset.edit)}`));
};

function plainReason(r) {
  r = String(r || "");
  if (/revoked/i.test(r)) return "The owner blocked your access";
  if (/attribute|access structure|policy/i.test(r)) return "Your role does not allow this document";
  if (/registered/i.test(r)) return "Your account is not registered";
  return "Not allowed";
}

pages.view = async () => {
  const s = state.lastSearch, docId = param("doc");
  if (!s) { go("search"); return; }
  const d = await GET(`/api/user/documents/${encodeURIComponent(docId)}/view?searchId=${encodeURIComponent(s.searchId)}`);
  let body;
  if (d.kind === "text") body = `<pre class="viewer">${esc(d.text)}</pre>`;
  else if (d.kind === "image") body = `<img class="viewer-img" alt="${esc(d.fileName)}" src="data:${esc(d.contentType)};base64,${d.dataBase64}" draggable="false">`;
  else if (d.kind === "pdf") body = `<iframe class="viewer-pdf" title="${esc(d.fileName)}" id="pdf"></iframe>`;
  else body = `<p class="empty">This type of file cannot be shown in the browser.${d.permissions.includes("DOWNLOAD") ? " Download it instead." : ""}</p>`;
  const v = d.viewer || { userId: state.me.userId, displayName: state.me.displayName, at: new Date().toLocaleString() };
  if (d.kind === "text" || d.kind === "image") {
    body = `<div id="protected" class="protected">${body}
      <div class="wm" style="background-image:url('${watermarkTile(v)}')"></div>
      <div class="shield"><b>Document hidden</b><span>Click here to keep reading.</span></div></div>`;
  }
  render(`<h1>${esc(d.fileName)}</h1>
    <p class="lead">${esc(versionLabel(d.version))} · ${size(d.sizeBytes)} · Your access: ${permTags(d.permissions)}</p>
    ${!d.permissions.includes("DOWNLOAD") ? `<p class="hint">View only: you can read this document here but not download it. Your viewing is recorded.</p>` : ""}
    ${d.kind === "text" || d.kind === "image" ? `<p class="hint">This copy is marked with your name and is unique to you. Copying, printing and
      screenshots are blocked and reported to the owner.</p>` : ""}
    ${body}
    <div class="actions">
      ${d.permissions.includes("DOWNLOAD") ? `<button id="dl">Download</button>` : ""}
      ${d.permissions.includes("MODIFY") ? `<a class="btn secondary" href="#/edit?doc=${encodeURIComponent(docId)}">Suggest changes</a>` : ""}
      <a class="btn secondary" href="#/results">Back to results</a></div>`);
  if (d.kind === "pdf") {
    const bytes = Uint8Array.from(atob(d.dataBase64), c => c.charCodeAt(0));
    document.getElementById("pdf").src = URL.createObjectURL(new Blob([bytes], { type: "application/pdf" }));
  }
  if (d.kind === "text" || d.kind === "image") installViewGuard(docId);
  const dl = document.getElementById("dl");
  if (dl) dl.onclick = () => busy(dl, async () => {
    await downloadFile(`/api/user/documents/${encodeURIComponent(docId)}/download?searchId=${encodeURIComponent(s.searchId)}`, d.fileName);
    toast("Downloaded " + d.fileName);
  });
};

pages.edit = async () => {
  const s = state.lastSearch, docId = param("doc");
  if (!s) { go("search"); return; }
  const d = await GET(`/api/user/documents/${encodeURIComponent(docId)}/view?searchId=${encodeURIComponent(s.searchId)}`);
  const isText = d.kind === "text";
  render(`<h1>Suggest changes to ${esc(d.fileName)}</h1>
    <div class="panel"><p style="margin:0">Your changes are sent to the owner for approval. Until the owner approves them, everyone keeps
      seeing the current version, and the original is always kept. Your suggestion is signed with your personal key and recorded.</p></div>
    <div class="panel">
      ${isText ? `<label for="txt">Document text <span class="hint">edit directly</span></label>
        <textarea id="txt" class="editor">${esc(d.text)}</textarea>`
      : `<label for="file">Upload the changed file</label><input type="file" id="file">
         <p class="hint">This type of file cannot be edited in the browser.</p>`}
      <label for="note">What did you change and why? <span class="hint">required; the owner sees this</span></label>
      <input type="text" id="note" placeholder="e.g. Corrected the phone number in section 2">
      <div class="actions"><button id="send">Send to owner for approval</button>
        <a class="btn secondary" href="#/results">Cancel</a></div>
    </div>`);
  const ta = document.getElementById("txt");
  if (ta) {
    const block = e => { e.preventDefault(); toast("Copying is disabled for this document. The owner has been told.", true);
      POST(`/api/user/documents/${encodeURIComponent(docId)}/view-event`, { event: "COPY_ATTEMPT" }).catch(() => {}); };
    ta.addEventListener("copy", block);
    ta.addEventListener("cut", block);
    ta.addEventListener("dragstart", e => e.preventDefault());
  }
  document.getElementById("send").onclick = e => busy(e.target, async () => {
    const note = document.getElementById("note").value.trim();
    if (!note) throw new Error("Describe what you changed.");
    const body = { searchId: s.searchId, note };
    if (isText) {
      body.text = document.getElementById("txt").value;
    } else {
      const f = document.getElementById("file").files[0];
      if (!f) throw new Error("Choose the changed file.");
      body.dataBase64 = await readFileBase64(f);
    }
    const r = await POST(`/api/user/documents/${encodeURIComponent(docId)}/changes`, body);
    toast("Sent to the owner for approval (" + r.summary + ").");
    go("mychanges");
  });
};

pages.mychanges = async () => {
  const ch = (await GET("/api/user/changes")).changes;
  render(`<h1>My suggested changes</h1>
    <p class="lead">Changes you suggested and the owner's decision.</p>
    ${table(["Document", "Owner", "When", "Your note", "What changed", "Status"], ch.map(c => [esc(c.fileName), esc(c.owner),
      fmt(c.proposedAt), esc(c.note), esc(c.summary), changeTag(c.status) +
      (c.ownerComment ? `<br><span class="hint">Owner: ${esc(c.ownerComment)}</span>` : "")]),
      "You have not suggested any changes.")}`);
};

pages.myrequests = async () => {
  const reqs = (await GET("/api/user/access-requests")).requests;
  const approved = reqs.filter(r => r.status === "APPROVED");
  render(`<h1>My access requests</h1>
    <p class="lead">Some owners approve each person before their documents can be opened. A request is sent automatically when you search.</p>
    ${approved.length ? `<div class="panel ok"><b>Approved: ${approved.map(r => esc(r.fileName || r.documentId)).join(", ")}.</b>
      Type a keyword of the document and press <b>Search</b> to open it.
      <label for="kw">Keyword</label><input type="text" id="kw" autocomplete="off">
      <div class="actions"><button id="go">Search</button></div></div>` : ""}
    ${table(["Document", "Owner", "Requested", "Status", "What you can do"], reqs.map(r => [esc(r.fileName || r.documentId), esc(r.ownerUserId),
      fmt(r.requestedAt), approvalTag(r.status), r.status === "APPROVED" ? permTags(r.permissions) : ""]),
      "No requests yet.")}`);
  const goBtn = document.getElementById("go");
  if (goBtn) {
    const run = () => busy(goBtn, async () => {
      const kw = document.getElementById("kw").value.trim();
      if (!kw) throw new Error("Type a keyword of the document.");
      await runSearch(kw);
    });
    goBtn.onclick = run;
    document.getElementById("kw").addEventListener("keydown", e => { if (e.key === "Enter") run(); });
  }
};

function showSubmitResult(r) {
  const out = document.getElementById("out");
  const ok = r.accepted;
  const msg = ok ? "The token was accepted."
    : r.status === "REJECTED_REPLAY" ? "Refused: this search token was already used. The owner has been alerted."
    : r.status === "REJECTED_INVALID_ENVELOPE" ? "Refused: the search token was altered or forged."
    : r.status === "REJECTED_EXPIRED" ? "Refused: the search token has expired."
    : "Refused: " + (r.message || r.status);
  out.innerHTML = `<div class="panel ${ok ? "ok" : "alarm"}"><p><b>${esc(msg)}</b></p></div>`;
  if (!ok) toast(msg, true);
  out.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

pages.replay = async () => {
  render(`<h1>Security test</h1>
    <p class="lead">Every search uses a one-time search token. Use this page to check that a token cannot be used twice,
      for example a token copied from your browser's network traffic and sent to someone else.</p>
    <div class="panel">
      <label for="env">Search token</label>
      <textarea id="env" placeholder="Paste a search token here"></textarea>
      <div class="actions">
        <button id="fill" class="secondary">Use the token from my last search</button>
        <button id="tamper" class="secondary">Alter the token</button>
        <button id="send">Submit</button>
      </div>
    </div><div id="out"></div>`);
  const ta = document.getElementById("env");
  document.getElementById("fill").onclick = () => {
    const env = state.lastSearch && Object.values(state.lastSearch.envelopes || {})[0];
    if (!env) { toast("No token available. Run a search first.", true); return; }
    ta.value = JSON.stringify(env, null, 2);
  };
  document.getElementById("tamper").onclick = () => {
    try {
      const env = JSON.parse(ta.value);
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      env.nonce = btoa(String.fromCharCode(...bytes));
      ta.value = JSON.stringify(env, null, 2);
      toast("The token was altered.");
    } catch (e) { toast("Paste a search token first.", true); }
  };
  document.getElementById("send").onclick = e => busy(e.target, async () => {
    let env;
    try { env = JSON.parse(ta.value); } catch (x) { throw new Error("That is not a valid search token."); }
    showSubmitResult(await POST("/api/security/submit-trapdoor", { envelope: env }));
  });
};

// ---------- shared information
pages.access = async () => {
  const info = await GET("/api/access-info");
  render(`<h1>Access and roles</h1>
    <div class="panel"><p style="margin:0">Account <b>${esc(info.user.userId)}</b> · roles ${info.user.attributes.map(a => tag("ok", a)).join(" ") || "none"}
      · registered ${fmt(info.user.registeredAt)}</p></div>
    <h2>Documents</h2>
    ${table(["Document", "Owner", "Who can access", "Your role", "Owner approval", "What you can do"], info.documents.map(d => [
      esc(d.fileName), esc(d.owner), esc(d.policy),
      d.revokedByOwner ? tag("alarm", "blocked by owner") : d.satisfiedByMyAttributes ? tag("ok", "allowed") : tag("plain", "not allowed"),
      approvalTag(d.approval), d.satisfiedByMyAttributes && !d.revokedByOwner ? permTags(d.permissions) : ""]),
      "No documents have been uploaded yet.")}
    <h2>Registered users</h2>
    <div id="users"><p class="empty">Loading…</p></div>`);
  const u = await GET("/api/users");
  document.getElementById("users").innerHTML = table(["User", "Name", "Roles", "Registered"],
    u.users.map(x => [esc(x.userId), esc(x.displayName), esc(x.attributes.join(", ")), fmt(x.registeredAt)]));
};

function friendly(event) {
  return String(event || "").replace(/TRAPDOOR/g, "SEARCH_TOKEN").toLowerCase().replace(/_/g, " ")
    .replace(/^./, c => c.toUpperCase());
}

pages.logs = async () => {
  const l = await GET("/api/logs");
  render(`<h1>Activity logs</h1>
    <p class="lead">Security events recorded by the cloud server and actions recorded by this server.</p>
    <h2>Cloud security log</h2>
    ${table(["Date and time", "Event", "User"], (l.events || []).map(e => [fmt(e.time),
      tag(/REJECT|ALERT|DENIED|BLOCK/.test(e.event) ? "alarm" : "plain", friendly(e.event)),
      esc(e.submittedBy || e.ownerUserId || "")]))}
    <h2>Server log</h2>
    ${table(["Date and time", "Event", "User"], (l.audit || []).map(e => [fmt(e.time),
      tag("plain", friendly(e.event)), esc(e.userId || "")]))}`);
};

// ------------------------------------------------------------------ view page protection
/** A faint tiled watermark with the viewer's name, as an SVG data URL. */
function watermarkTile(v) {
  const line1 = `${v.displayName || v.userId} (${v.userId})`;
  const line2 = `${v.at} · Confidential`;
  const x = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[c]));
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="340" height="190">
    <g transform="rotate(-24 170 95)" font-family="Arial, sans-serif" fill="#1d2733" fill-opacity="0.13" text-anchor="middle">
    <text x="170" y="88" font-size="17" font-weight="700">${x(line1)}</text>
    <text x="170" y="110" font-size="13">${x(line2)}</text></g></svg>`;
  return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg).replace(/'/g, "%27");
}

let guard = null;

function removeViewGuard() {
  if (!guard) return;
  guard.off.forEach(([t, ev, fn, opt]) => t.removeEventListener(ev, fn, opt));
  clearTimeout(guard.timer);
  document.body.classList.remove("guarded");
  guard = null;
}

function installViewGuard(docId) {
  removeViewGuard();
  const g = guard = { docId, off: [], lastSent: {}, timer: null, modifier: false };
  document.body.classList.add("guarded");
  const box = () => document.getElementById("protected");
  const hide = on => { const b = box(); if (b) b.classList.toggle("hidden-doc", on); };
  const send = ev => {
    const now = Date.now(), gap = ev === "WINDOW_LEFT" ? 15000 : 3000;
    if (now - (g.lastSent[ev] || 0) < gap) return;
    g.lastSent[ev] = now;
    POST(`/api/user/documents/${encodeURIComponent(docId)}/view-event`, { event: ev }).catch(() => {});
  };
  const on = (t, ev, fn, opt) => { t.addEventListener(ev, fn, opt); g.off.push([t, ev, fn, opt]); };
  const inside = e => { const b = box(); return b && e.target instanceof Node && b.contains(e.target); };

  // copying
  on(document, "copy", e => { e.preventDefault(); send("COPY_ATTEMPT"); toast("Copying is disabled for this document. The owner has been told.", true); });
  on(document, "cut", e => { e.preventDefault(); send("COPY_ATTEMPT"); });
  on(document, "contextmenu", e => { if (inside(e)) e.preventDefault(); });
  on(document, "selectstart", e => { if (inside(e)) e.preventDefault(); });
  on(document, "dragstart", e => { if (inside(e)) e.preventDefault(); });

  // keys
  on(window, "keydown", e => {
    const k = (e.key || "").toLowerCase();
    if ((e.ctrlKey || e.metaKey) && ["c", "x", "a", "s"].includes(k)) {
      e.preventDefault(); send("COPY_ATTEMPT");
      toast("Copying and saving are disabled for this document. The owner has been told.", true);
    } else if ((e.ctrlKey || e.metaKey) && k === "p") {
      e.preventDefault(); send("PRINT_ATTEMPT");
      toast("Printing is disabled for this document. The owner has been told.", true);
    }
    if (["control", "alt", "meta", "os", "shift"].includes(k)) { g.modifier = true; hide(true); }
    if (k === "printscreen") { hide(true); }
  }, true);
  on(window, "keyup", e => {
    const k = (e.key || "").toLowerCase();
    if (k === "printscreen") {
      hide(true); send("PRINT_SCREEN");
      try { if (navigator.clipboard) navigator.clipboard.writeText("").catch(() => {}); } catch (x) { /* not allowed */ }
      toast("Screenshots are not allowed for this document. The owner has been told.", true);
      clearTimeout(g.timer);
      g.timer = setTimeout(() => hide(false), 4000);
      return;
    }
    if (["control", "alt", "meta", "os", "shift"].includes(k) || !(e.ctrlKey || e.altKey || e.metaKey || e.shiftKey)) {
      g.modifier = false;
      if (document.hasFocus()) hide(false);
    }
  }, true);

  // printing (also covered by the @media print rule)
  on(window, "beforeprint", () => send("PRINT_ATTEMPT"));

  // leaving the window: a snipping tool or another app takes focus
  on(window, "blur", () => { hide(true); send("WINDOW_LEFT"); });
  on(window, "focus", () => { g.modifier = false; hide(false); });
  on(document, "visibilitychange", () => { if (document.hidden) { hide(true); send("WINDOW_LEFT"); } });
  on(document, "mouseout", e => { if (!e.relatedTarget && !e.toElement) hide(true); });
  on(document, "mouseover", () => { if (document.hasFocus() && !g.modifier) hide(false); });
  const b = box();
  if (b) on(b, "click", () => { if (document.hasFocus()) { g.modifier = false; hide(false); } });
}

// ------------------------------------------------------------------ router
const OWNER_PAGES = new Set(["owner", "upload", "requests", "changes", "review", "history", "alerts", "leak"]);
const USER_PAGES = new Set(["user", "search", "results", "view", "edit", "mychanges", "replay", "myrequests"]);
const AUTH_PAGES = new Set([...OWNER_PAGES, ...USER_PAGES, "access", "logs", "trace"]);

async function route() {
  let page = (location.hash.replace(/^#\//, "") || "home").split("?")[0];
  if (!state.status || !state.status.initialized) page = "setup";
  else if (AUTH_PAGES.has(page) && !state.me) { toast("Log in first."); page = "login"; }
  else if (OWNER_PAGES.has(page) && state.me.actingAs !== "owner") { toast("Switch to the data owner role for this page."); page = "user"; }
  else if (USER_PAGES.has(page) && state.me.actingAs !== "user") { toast("Switch to the data user role for this page."); page = "owner"; }
  if (!pages[page]) page = "home";
  removeViewGuard();
  drawChrome();
  try { await pages[page](); }
  catch (e) {
    if (e.status === 401) { state.me = null; drawChrome(); toast("Your session ended. Log in again.", true); go("login"); return; }
    render(`<h1>Something went wrong</h1><div class="panel alarm">${esc(e.message)}</div>
      <div class="actions"><button class="secondary" onclick="history.back()">Go back</button></div>`);
  }
}

async function boot(doRoute = true) {
  try { state.status = await GET("/api/status"); }
  catch (e) { render(`<h1>Server unreachable</h1><div class="panel alarm">${esc(e.message)}</div>`); return; }
  await refreshSession();
  if (doRoute) route(); else drawChrome();
}

window.addEventListener("hashchange", route);
boot();
