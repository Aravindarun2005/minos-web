import { useEffect, useState } from "react";

const API = "http://localhost:5000";

async function api(path, { method = "GET", body, token, isForm } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body && !isForm) headers["Content-Type"] = "application/json";

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined
  });

  const contentType = response.headers.get("content-type") || "";
  if (!contentType.includes("application/json")) {
    if (!response.ok) throw new Error(`Request failed (${response.status})`);
    return response; // caller reads the raw body (file download)
  }

  const data = await response.json();
  if (!response.ok || data.success === false) throw new Error(data.message || "Request failed");
  return data;
}

function Banner({ text, tone = "info" }) {
  if (!text) return null;
  return <div className={`banner banner-${tone}`}>{text}</div>;
}

export default function App() {
  const [session, setSession] = useState(() => {
    const raw = sessionStorage.getItem("minos-session");
    return raw ? JSON.parse(raw) : null;
  });

  const [setupState, setSetupState] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    api("/api/minos/setup").then(setSetupState).catch((e) => setError(e.message));
  }, []);

  function login(data) {
    sessionStorage.setItem("minos-session", JSON.stringify(data));
    setSession(data);
  }
  function logout() {
    if (session) api("/api/auth/logout", { method: "POST", token: session.token }).catch(() => {});
    sessionStorage.removeItem("minos-session");
    setSession(null);
  }

  if (setupState === null) return <div className="page"><p>Loading...</p></div>;

  return (
    <div className="page">
      <header>
        <h1>Minos</h1>
        <p className="tagline">Attribute-based keyword search with accountability and traceability</p>
      </header>

      <Banner text={error} tone="error" />
      <Banner text={notice} tone="success" />

      {!setupState.initialized ? (
        <Setup onDone={() => api("/api/minos/setup").then(setSetupState)} setError={setError} />
      ) : !session ? (
        <AuthForms attributes={setupState.attributes} onLogin={login} setError={setError} setNotice={setNotice} />
      ) : (
        <>
          <div className="topbar">
            <span>
              Signed in as <strong>{session.username}</strong> ({session.role})
            </span>
            <button onClick={logout}>Log out</button>
          </div>
          {session.role === "Owner" ? (
            <OwnerDashboard session={session} attributes={setupState.attributes} setError={setError} setNotice={setNotice} />
          ) : (
            <UserDashboard session={session} setError={setError} setNotice={setNotice} />
          )}
        </>
      )}

      <style>{CSS}</style>
    </div>
  );
}

// --------------------------------------------------
// FIRST-TIME SETUP  (Algorithm 1)
// --------------------------------------------------

function Setup({ onDone, setError }) {
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError("");
    try {
      await api("/api/minos/setup", { method: "POST" });
      onDone();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>First-time setup</h2>
      <p>
        Minos has not been initialized yet. Running setup generates the public parameters (mpk) once, using
        pairing-based cryptography. This can take a few seconds.
      </p>
      <button onClick={run} disabled={busy}>{busy ? "Generating mpk..." : "Run setup"}</button>
    </section>
  );
}

// --------------------------------------------------
// REGISTER + LOGIN
// --------------------------------------------------

function AuthForms({ attributes, onLogin, setError, setNotice }) {
  const [mode, setMode] = useState("login");

  return (
    <div className="grid-2">
      <section className="card">
        <div className="tabs">
          <button className={mode === "login" ? "tab active" : "tab"} onClick={() => setMode("login")}>Log in</button>
          <button className={mode === "register" ? "tab active" : "tab"} onClick={() => setMode("register")}>Register</button>
        </div>
        {mode === "login"
          ? <LoginForm onLogin={onLogin} setError={setError} />
          : <RegisterForm setError={setError} setNotice={setNotice} onDone={() => setMode("login")} />}
      </section>
      <section className="card">
        <h3>Roles in this demo</h3>
        <ul>{attributes.map((a) => <li key={a}>{a}</li>)}</ul>
        <p className="muted">
          An <strong>Owner</strong> encrypts and uploads documents, and decides which of these roles may search them.
          A <strong>User</strong> requests access from an owner, then searches by keyword.
        </p>
      </section>
    </div>
  );
}

function LoginForm({ onLogin, setError }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = await api("/api/auth/login", { method: "POST", body: { username, password } });
      onLogin(data);
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
      <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
      <button disabled={busy}>{busy ? "Logging in..." : "Log in"}</button>
    </form>
  );
}

function RegisterForm({ setError, setNotice, onDone }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("User");
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      // Register runs first, then KeyGen runs automatically on the server.
      await api("/api/auth/register", { method: "POST", body: { username, password, role } });
      setNotice(`Registered ${username}. Your keys were generated and your public key was sent to the CSP. You can log in now.`);
      onDone();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
      <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
      <label>
        Account type
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="User">User (searches documents)</option>
          <option value="Owner">Owner (uploads documents)</option>
        </select>
      </label>
      <button disabled={busy}>{busy ? "Registering..." : "Register"}</button>
    </form>
  );
}

// --------------------------------------------------
// OWNER DASHBOARD
// --------------------------------------------------

function OwnerDashboard({ session, attributes, setError, setNotice }) {
  const [documents, setDocuments] = useState([]);
  const [requests, setRequests] = useState([]);
  const [alerts, setAlerts] = useState([]);

  async function refresh() {
    try {
      const [d, r, a] = await Promise.all([
        api("/api/documents/mine", { token: session.token }),
        api("/api/access/requests", { token: session.token }),
        api("/api/alerts", { token: session.token })
      ]);
      setDocuments(d.documents);
      setRequests(r.requests);
      setAlerts(a.alerts);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => { refresh(); const t = setInterval(refresh, 8000); return () => clearInterval(t); }, []); // eslint-disable-line

  async function decide(requestId, decision) {
    try {
      await api("/api/access/decide", { method: "POST", token: session.token, body: { requestId, decision } });
      setNotice(decision === "approve" ? "Access granted" : "Access denied");
      refresh();
    } catch (e) { setError(e.message); }
  }

  async function revoke(user, tk3) {
    try {
      await api("/api/access/revoke", { method: "POST", token: session.token, body: { username: user, tk3 } });
      setNotice(`Revoked access for ${user}`);
      refresh();
    } catch (e) { setError(e.message); }
  }

  async function trace(documentId) {
    try {
      const result = await api(`/api/documents/${documentId}/trace`, { method: "POST", token: session.token });
      setNotice(result.owned ? "Ownership verified by the CSP." : "The CSP could not verify ownership of this document.");
    } catch (e) { setError(e.message); }
  }

  return (
    <>
      <UploadForm session={session} attributes={attributes} setError={setError} setNotice={setNotice} onUploaded={refresh} />

      <section className="card">
        <h2>Access requests</h2>
        {requests.length === 0 && <p className="muted">No pending requests.</p>}
        {requests.map((r) => (
          <div className="row" key={r.id}>
            <span><strong>{r.user}</strong> <span className="muted">({r.attributes.join(", ") || "no roles"})</span></span>
            <span>
              <button onClick={() => decide(r.id, "approve")}>Approve</button>
              <button className="secondary" onClick={() => decide(r.id, "deny")}>Deny</button>
            </span>
          </div>
        ))}
      </section>

      <section className="card">
        <h2>Security alerts</h2>
        <p className="muted">A trapdoor is one-time use. Reusing one raises an alert here, naming the user it came from.</p>
        {alerts.length === 0 && <p className="muted">No alerts.</p>}
        {alerts.map((a) => (
          <div className="row alert-row" key={a.tk3 + a.timestamp}>
            <span>
              <strong>{a.user}</strong> reused a trapdoor{a.keyword ? ` (keyword "${a.keyword}")` : ""} at{" "}
              {new Date(a.timestamp).toLocaleString()}
              {!a.verified && <span className="muted"> - identity from Algorithm 9 only, Algorithm 11 could not verify it</span>}
            </span>
            <button className="danger" onClick={() => revoke(a.user, a.tk3)} disabled={a.user === "unknown"}>Revoke access</button>
          </div>
        ))}
      </section>

      <section className="card">
        <h2>My documents</h2>
        {documents.length === 0 && <p className="muted">No documents uploaded yet.</p>}
        {documents.map((d) => (
          <div className="row" key={d.documentId}>
            <span>
              <strong>{d.name}</strong>
              <div className="muted">keywords: {d.keywords.join(", ")} - roles: {d.roles.join(", ")}</div>
            </span>
            <button onClick={() => trace(d.documentId)}>Prove ownership</button>
          </div>
        ))}
      </section>
    </>
  );
}

function UploadForm({ session, attributes, setError, setNotice, onUploaded }) {
  const [file, setFile] = useState(null);
  const [name, setName] = useState("");
  const [keywords, setKeywords] = useState("");
  const [roles, setRoles] = useState([]);
  const [busy, setBusy] = useState(false);

  function toggleRole(role) {
    setRoles((prev) => (prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]));
  }

  async function submit(e) {
    e.preventDefault();
    if (!file) return setError("Choose a file to encrypt");
    if (!keywords.trim()) return setError("Give at least one keyword");
    if (roles.length === 0) return setError("Choose at least one role allowed to search this document");

    setBusy(true);
    setError("");
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("name", name || file.name);
      form.append("keywords", keywords);
      form.append("roles", roles.join(","));

      await api("/api/documents/upload", { method: "POST", token: session.token, body: form, isForm: true });
      setNotice("Document encrypted (Algorithm 4) and stored at the CSP.");
      setFile(null); setName(""); setKeywords(""); setRoles([]);
      onUploaded();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <h2>Encrypt and upload a document</h2>
      <form onSubmit={submit}>
        <label>File<input type="file" onChange={(e) => setFile(e.target.files[0])} /></label>
        <label>Display name (optional)<input value={name} onChange={(e) => setName(e.target.value)} placeholder={file?.name || ""} /></label>
        <label>Keywords (comma separated)<input value={keywords} onChange={(e) => setKeywords(e.target.value)} placeholder="loan, mortgage, application" /></label>
        <fieldset>
          <legend>Roles allowed to search this document</legend>
          {attributes.map((a) => (
            <label key={a} className="checkbox">
              <input type="checkbox" checked={roles.includes(a)} onChange={() => toggleRole(a)} /> {a}
            </label>
          ))}
        </fieldset>
        <button disabled={busy}>{busy ? "Encrypting..." : "Encrypt and upload"}</button>
      </form>
    </section>
  );
}

// --------------------------------------------------
// USER DASHBOARD
// --------------------------------------------------

function UserDashboard({ session, setError, setNotice }) {
  const [owners, setOwners] = useState([]);
  const [selectedOwner, setSelectedOwner] = useState("");
  const [keyword, setKeyword] = useState("");
  const [results, setResults] = useState(null);
  const [searching, setSearching] = useState(false);

  async function refreshOwners() {
    try {
      const { owners: list } = await api("/api/owners", { token: session.token });
      setOwners(list);
      if (!selectedOwner && list.some((o) => o.status === "approved")) {
        setSelectedOwner(list.find((o) => o.status === "approved").username);
      }
    } catch (e) { setError(e.message); }
  }

  useEffect(() => { refreshOwners(); }, []); // eslint-disable-line

  async function requestAccess(owner) {
    try {
      await api("/api/access/request", { method: "POST", token: session.token, body: { owner } });
      setNotice(`Access request sent to ${owner}`);
      refreshOwners();
    } catch (e) { setError(e.message); }
  }

  async function search() {
    if (!selectedOwner || !keyword.trim()) return setError("Choose an owner and a keyword");
    setSearching(true);
    setError("");
    setResults(null);
    try {
      // A fresh trapdoor (Algorithm 6) is generated on every search.
      const result = await api("/api/search", { method: "POST", token: session.token, body: { owner: selectedOwner, keyword: keyword.trim() } });
      setResults(result);
      if (result.status === "REPLAY") setNotice("The CSP rejected this trapdoor as a replay and alerted the owner.");
      if (result.status === "SUSPENDED") setNotice("This trapdoor's identity has been suspended by the owner.");
    } catch (e) {
      setError(e.message);
    } finally {
      setSearching(false);
    }
  }

  async function download(documentId, name) {
    try {
      const response = await api(`/api/documents/${documentId}/download`, { token: session.token });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setError(e.message); }
  }

  return (
    <>
      <section className="card">
        <h2>Data owners</h2>
        {owners.length === 0 && <p className="muted">No owners have registered yet.</p>}
        {owners.map((o) => (
          <div className="row" key={o.username}>
            <span><strong>{o.username}</strong> <span className="muted">({o.status})</span></span>
            {["none", "denied", "revoked"].includes(o.status) && (
              <button onClick={() => requestAccess(o.username)}>Request access</button>
            )}
          </div>
        ))}
      </section>

      <section className="card">
        <h2>Search</h2>
        <div className="row">
          <select value={selectedOwner} onChange={(e) => setSelectedOwner(e.target.value)}>
            <option value="">Choose an owner...</option>
            {owners.filter((o) => o.status === "approved").map((o) => <option key={o.username} value={o.username}>{o.username}</option>)}
          </select>
          <input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="keyword" />
          <button onClick={search} disabled={searching}>{searching ? "Searching..." : "Search"}</button>
        </div>

        {results && results.status === "OK" && (
          results.documents.length === 0
            ? <p className="muted">No documents matched.</p>
            : results.documents.map((d) => (
              <div className="row" key={d.documentId}>
                <span>{d.name}</span>
                <button onClick={() => download(d.documentId, d.name)}>Download and decrypt</button>
              </div>
            ))
        )}
      </section>
    </>
  );
}

// --------------------------------------------------
// STYLES
// --------------------------------------------------

const CSS = `
  * { box-sizing: border-box; }
  body { margin: 0; }
  .page { max-width: 900px; margin: 0 auto; padding: 24px 16px 64px; font: 15px/1.5 system-ui, sans-serif; color: #1c2330; }
  header { margin-bottom: 16px; }
  h1 { margin: 0; }
  .tagline { color: #5b6577; margin-top: 4px; }
  .card { border: 1px solid #d8dce3; border-radius: 8px; padding: 16px 18px; margin: 16px 0; background: #fff; }
  .grid-2 { display: grid; grid-template-columns: 1.2fr 1fr; gap: 16px; }
  form label { display: block; margin: 10px 0 4px; font-weight: 600; font-size: 13px; }
  form input, form select { width: 100%; padding: 8px; border: 1px solid #c7cdd6; border-radius: 6px; font: inherit; }
  fieldset { border: 1px solid #c7cdd6; border-radius: 6px; margin: 10px 0; }
  .checkbox { display: inline-flex; align-items: center; gap: 4px; font-weight: 400; margin-right: 14px; }
  .checkbox input { width: auto; }
  button { margin-top: 12px; padding: 8px 14px; border: 1px solid #1c2330; background: #1c2330; color: #fff; border-radius: 6px; cursor: pointer; font: inherit; }
  button.secondary { background: #fff; color: #1c2330; }
  button.danger { background: #b3261e; border-color: #b3261e; }
  button:disabled { opacity: 0.6; cursor: default; }
  .tabs { display: flex; gap: 4px; margin-bottom: 12px; }
  .tab { flex: 1; background: #f1f2f5; color: #1c2330; border: none; margin: 0; }
  .tab.active { background: #1c2330; color: #fff; }
  .row { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 8px 0; border-top: 1px solid #eceff3; flex-wrap: wrap; }
  .row:first-of-type { border-top: none; }
  .row select, .row input { width: auto; margin-top: 0; }
  .alert-row { background: #fdecea; padding: 8px 10px; border-radius: 6px; border-top: none; margin: 4px 0; }
  .muted { color: #5b6577; font-size: 13px; }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .banner { padding: 10px 14px; border-radius: 6px; margin: 10px 0; }
  .banner-error { background: #fdecea; color: #7a1a15; }
  .banner-success { background: #e9f7ef; color: #1b6e3c; }
`;
