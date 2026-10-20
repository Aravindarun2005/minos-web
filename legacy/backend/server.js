const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const multer = require("multer");
const { execFile } = require("child_process");
const { promisify } = require("util");

const app = express();
const execFileAsync = promisify(execFile);

const PORT = 5000;
const CSP_URL = "http://localhost:5001";
const LAMBDA = 160;

const BANK_ATTRIBUTES = ["BankManager", "LoanOfficer", "Auditor", "Accountant", "Customer"];

const ROOT = __dirname;
const JAVA_DIR = path.resolve(ROOT, "../minos-java");
const DATA_DIR = path.join(ROOT, "data");
const PRIVATE_DIR = path.join(DATA_DIR, "private-users");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");

const SETUP_FILE = path.join(DATA_DIR, "minos-setup.bin");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const REQUESTS_FILE = path.join(DATA_DIR, "access-requests.json");
const DOCUMENTS_FILE = path.join(DATA_DIR, "documents.json");
const GRANTS_FILE = path.join(DATA_DIR, "grants.json");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PRIVATE_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 20 * 1024 * 1024 } });

app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json({ limit: "50mb" }));

// --------------------------------------------------
// IN-MEMORY SESSIONS
// --------------------------------------------------

const sessions = new Map();

// --------------------------------------------------
// SMALL JSON STORES
//
// users.json             username -> account (role, attributes, password hash)
// access-requests.json   pending/approved/denied/revoked Authorize requests
// documents.json         document metadata visible to owners and users
// grants.json            per (owner, user) search token TK, kept owner-side
// --------------------------------------------------

function readStore(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}
function writeStore(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

const readUsers = () => readStore(USERS_FILE, {});
const saveUsers = (users) => writeStore(USERS_FILE, users);
const readRequests = () => readStore(REQUESTS_FILE, []);
const saveRequests = (r) => writeStore(REQUESTS_FILE, r);
const readDocuments = () => readStore(DOCUMENTS_FILE, []);
const saveDocuments = (d) => writeStore(DOCUMENTS_FILE, d);
const readGrants = () => readStore(GRANTS_FILE, {});
const saveGrants = (g) => writeStore(GRANTS_FILE, g);
const grantKey = (owner, user) => `${owner}|${user}`;

// --------------------------------------------------
// PASSWORD HASHING
// --------------------------------------------------

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key.toString("hex"))));
  });
}

function makeToken() { return crypto.randomBytes(32).toString("hex"); }

// --------------------------------------------------
// JAVA EXECUTION
//
// Simple commands (setup, register, keygen, encrypt) take their
// arguments on the command line, exactly as in the reference CLI.
// The Algorithm 5-11 commands take one JSON input file, because
// tokens and trapdoors are too large and structured for argv.
// --------------------------------------------------

function runJava(args) {
  return execFileAsync(
    "java",
    ["-cp", `.${path.delimiter}lib/*`, "Main", ...args],
    { cwd: JAVA_DIR, timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
  ).then(
    ({ stdout }) => {
      const output = stdout.trim();
      try { return JSON.parse(output); } catch { throw new Error("Could not parse Java output:\n" + output); }
    },
    (error) => { throw new Error((error.stderr || error.stdout || error.message || "").trim().split("\n")[0]); }
  );
}

async function runJavaJson(command, input) {
  const file = path.join(os.tmpdir(), `minos-${command}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(file, JSON.stringify(input));
  try { return await runJava([command, SETUP_FILE, file]); } finally { fs.rmSync(file, { force: true }); }
}

// --------------------------------------------------
// CSP CLIENT
// --------------------------------------------------

async function csp(pathname, method, body) {
  const response = await fetch(`${CSP_URL}${pathname}`, {
    method,
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined
  });
  const result = await response.json();
  if (!response.ok || result.success === false) throw new Error(result.message || "CSP request failed");
  return result;
}

// --------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// --------------------------------------------------

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "Please log in first" });
  const token = authHeader.substring(7);
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: "Session expired. Please log in again." });
  req.user = session;
  req.token = token;
  next();
}
function requireOwner(req, res, next) {
  if (req.user.role !== "Owner") return res.status(403).json({ success: false, message: "Only the owner can perform this operation" });
  next();
}
function requireUser(req, res, next) {
  if (req.user.role !== "User") return res.status(403).json({ success: false, message: "Only registered Users can perform this operation" });
  next();
}

// --------------------------------------------------
// VALIDATION + FILE HELPERS
// --------------------------------------------------

function validUsername(username) { return typeof username === "string" && /^[a-zA-Z0-9_.-]{3,30}$/.test(username); }
function getDefaultAttributes(role) { return role === "Owner" ? ["BankManager"] : ["Customer"]; }
function getPrivateFile(username) { return path.join(PRIVATE_DIR, `${username}.json`); }
function getOwnerKeyDirectory(username) { return path.join(PRIVATE_DIR, username, "document-keys"); }
function getOwnerMinosKeyFile(username, documentId) {
  return path.join(PRIVATE_DIR, username, "minos-keys", `${documentId.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`);
}
function saveOwnerMinosKey(username, documentId, keys) {
  const file = getOwnerMinosKeyFile(username, documentId);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(keys));
}
function loadOwnerMinosKey(username, documentId) {
  return JSON.parse(fs.readFileSync(getOwnerMinosKeyFile(username, documentId), "utf8"));
}
function readPrivateUser(username) { return JSON.parse(fs.readFileSync(getPrivateFile(username), "utf8")); }

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get("/", (req, res) => res.json({ success: true, message: "Minos backend running", port: PORT }));

// --------------------------------------------------
// SETUP  (Algorithm 1)
// --------------------------------------------------

app.get("/api/minos/setup", async (req, res) => {
  try {
    if (!fs.existsSync(SETUP_FILE)) {
      return res.json({ success: true, initialized: false, attributes: BANK_ATTRIBUTES, lambda: LAMBDA });
    }
    const result = await runJava(["load", SETUP_FILE]);
    res.json({ success: true, initialized: true, attributes: BANK_ATTRIBUTES, lambda: LAMBDA, parameters: result });
  } catch (error) {
    console.error("Setup status error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post("/api/minos/setup", async (req, res) => {
  try {
    if (fs.existsSync(SETUP_FILE)) return res.status(409).json({ success: false, message: "Minos is already initialized" });
    const attributes = [...new Set(BANK_ATTRIBUTES)];
    const result = await runJava(["setup", SETUP_FILE, ...attributes]);
    res.json({ success: true, message: "Minos setup completed", lambda: LAMBDA, attributes, parameters: result });
  } catch (error) {
    console.error("Setup error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// REGISTER  (Register -> KeyGen runs automatically right after)
// --------------------------------------------------

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;

    if (!validUsername(username)) {
      return res.status(400).json({ success: false, message: "Username must be 3-30 characters using letters, numbers, dot, underscore or hyphen" });
    }
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ success: false, message: "Password must contain at least 6 characters" });
    }
    if (!["Owner", "User"].includes(role)) return res.status(400).json({ success: false, message: "Select Owner or User" });
    if (!fs.existsSync(SETUP_FILE)) return res.status(400).json({ success: false, message: "Initialize Minos before registering" });

    const users = readUsers();
    if (users[username]) return res.status(409).json({ success: false, message: "Username already exists" });

    const attributes = getDefaultAttributes(role);
    const salt = crypto.randomBytes(16).toString("hex");
    const passwordHash = await hashPassword(password, salt);

    // Register (Algorithm 2): pk = g^beta, sk = beta.
    const registration = await runJava(["register", SETUP_FILE, username]);
    if (!registration.success || !registration.publicKey || !registration.privateKey) {
      throw new Error("Java registration did not return the required keys");
    }
    if (registration.verified !== true) throw new Error("Java registration verification failed");

    // pk is sent to the CSP; this is Register lines 4-6, R.add(pk).
    await csp("/api/csp/register-public-key", "POST", { userId: username, publicKey: registration.publicKey });

    const privateRecord = {
      username,
      privateKey: registration.privateKey,
      publicKey: registration.publicKey,
      attributes
    };

    // KeyGen (Algorithm 3) is not run here. It needs a non-empty attribute
    // set to build the access-policy matrix M, and at registration time an
    // owner has not chosen any attributes yet - that only happens per
    // document, when a fresh K = (sk1, sk2, k, M, pi) is generated for
    // whatever roles the owner picks on upload (see /api/documents/upload).

    fs.writeFileSync(getPrivateFile(username), JSON.stringify(privateRecord, null, 2));

    users[username] = { username, role, attributes, salt, passwordHash, registeredAt: new Date().toISOString() };
    saveUsers(users);

    res.status(201).json({ success: true, message: "Registration successful", username, role, attributes });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (typeof username !== "string" || typeof password !== "string") {
      return res.status(400).json({ success: false, message: "Username and password are required" });
    }

    const users = readUsers();
    const account = users[username];
    if (!account) return res.status(401).json({ success: false, message: "Invalid username or password" });

    const hash = await hashPassword(password, account.salt);
    if (hash !== account.passwordHash) return res.status(401).json({ success: false, message: "Invalid username or password" });

    const privateRecord = readPrivateUser(username);
    const token = makeToken();
    sessions.set(token, { username, role: account.role, attributes: account.attributes, publicKey: privateRecord.publicKey });

    res.json({ success: true, token, username, role: account.role, attributes: account.attributes, publicKey: privateRecord.publicKey });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post("/api/auth/logout", authenticate, (req, res) => { sessions.delete(req.token); res.json({ success: true }); });

app.get("/api/auth/me", authenticate, (req, res) => res.json({ success: true, user: req.user }));

// --------------------------------------------------
// OWNER: UPLOAD + ENCRYPT  (Algorithm 4)
// --------------------------------------------------

app.post("/api/documents/upload", authenticate, requireOwner, upload.single("file"), async (req, res) => {
  let uploadedFile = req.file;
  try {
    if (!uploadedFile) return res.status(400).json({ success: false, message: "Attach a file to encrypt" });

    const keywords = String(req.body.keywords || "").split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
    const roles = String(req.body.roles || "").split(",").map((r) => r.trim()).filter(Boolean);
    if (!keywords.length) return res.status(400).json({ success: false, message: "Give at least one keyword" });
    if (!roles.length) return res.status(400).json({ success: false, message: "Choose at least one role allowed to search this document" });
    for (const role of roles) if (!BANK_ATTRIBUTES.includes(role)) return res.status(400).json({ success: false, message: `Unknown role: ${role}` });

    const owner = readPrivateUser(req.user.username);
    const documentId = crypto.randomUUID();

    const encrypted = await runJava([
      "encrypt", SETUP_FILE, owner.privateKey, owner.publicKey,
      documentId, uploadedFile.path, keywords.join(","), roles.join(","),
      getOwnerKeyDirectory(req.user.username)
    ]);

    // K (sk1, sk2, k, M, pi) stays with the owner: Authorize, Detect and Trace
    // for this document all need it later.
    saveOwnerMinosKey(req.user.username, documentId, encrypted.keys);

    await csp("/api/csp/documents", "POST", {
      documentId,
      ownerPublicKey: owner.publicKey,
      encryptedDocumentBase64: encrypted.cspPayload.encryptedDocumentBase64,
      documentNonceBase64: encrypted.cspPayload.documentNonceBase64,
      indexEntries: encrypted.cspPayload.indexEntries
    });

    const documents = readDocuments();
    documents.push({
      documentId, owner: req.user.username, ownerPublicKey: owner.publicKey,
      name: req.body.name || uploadedFile.originalname, keywords, roles,
      uploadedAt: new Date().toISOString()
    });
    saveDocuments(documents);

    res.status(201).json({ success: true, documentId, keywords, roles });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ success: false, message: error.message });
  } finally {
    if (uploadedFile) fs.rm(uploadedFile.path, { force: true }, () => {});
  }
});

app.get("/api/documents/mine", authenticate, requireOwner, (req, res) => {
  res.json({ success: true, documents: readDocuments().filter((d) => d.owner === req.user.username) });
});

// --------------------------------------------------
// USER: SEE DATA OWNERS
// --------------------------------------------------

app.get("/api/owners", authenticate, requireUser, (req, res) => {
  const users = readUsers();
  const requests = readRequests();
  const grants = readGrants();

  const owners = Object.values(users).filter((u) => u.role === "Owner").map((o) => {
    const status = grants[grantKey(o.username, req.user.username)]
      ? "approved"
      : (requests.filter((r) => r.owner === o.username && r.user === req.user.username).slice(-1)[0]?.status || "none");
    return { username: o.username, status };
  });

  res.json({ success: true, owners });
});

// --------------------------------------------------
// USER: REQUEST ACCESS  (Authorize, client side: build proof rho)
// --------------------------------------------------

app.post("/api/access/request", authenticate, requireUser, async (req, res) => {
  try {
    const { owner } = req.body;
    const users = readUsers();
    if (!users[owner] || users[owner].role !== "Owner") return res.status(404).json({ success: false, message: "No such owner" });

    const requests = readRequests();
    if (requests.some((r) => r.owner === owner && r.user === req.user.username && r.status === "pending")) {
      return res.status(409).json({ success: false, message: "A request is already pending" });
    }

    const client = readPrivateUser(req.user.username);
    const proofResult = await runJavaJson("authorize-proof", { publicKey: client.publicKey, privateKey: client.privateKey });

    requests.push({
      id: crypto.randomUUID(), owner, user: req.user.username,
      attributes: req.user.attributes, proof: proofResult.proof,
      status: "pending", requestedAt: new Date().toISOString()
    });
    saveRequests(requests);

    res.json({ success: true, message: "Access request sent" });
  } catch (error) {
    console.error("Access request error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/api/access/requests", authenticate, requireOwner, (req, res) => {
  const pending = readRequests().filter((r) => r.owner === req.user.username && r.status === "pending");
  res.json({ success: true, requests: pending.map((r) => ({ id: r.id, user: r.user, attributes: r.attributes })) });
});

// --------------------------------------------------
// OWNER: APPROVE / DENY  (Authorize, owner side -> issues TK for one document at a time)
//
// A search token TK is scoped to one document, because K (M, pi, sk1,
// sk2) belongs to one document. Approving a request issues a token for
// every document this owner marked as readable by the client's roles.
// --------------------------------------------------

app.post("/api/access/decide", authenticate, requireOwner, async (req, res) => {
  try {
    const { requestId, decision } = req.body;
    if (!["approve", "deny"].includes(decision)) return res.status(400).json({ success: false, message: "decision must be approve or deny" });

    const requests = readRequests();
    const request = requests.find((r) => r.id === requestId && r.owner === req.user.username);
    if (!request) return res.status(404).json({ success: false, message: "Request not found" });

    if (decision === "deny") {
      request.status = "denied";
      saveRequests(requests);
      return res.json({ success: true, status: "denied" });
    }

    const owner = readPrivateUser(req.user.username);
    const { publicKeys } = await csp("/api/csp/public-keys", "GET");
    const client = readPrivateUser(request.user);

    const documents = readDocuments().filter((d) => d.owner === req.user.username && d.roles.some((r) => request.attributes.includes(r)));

    const grants = readGrants();
    const tokens = {};
    for (const document of documents) {
      const keys = loadOwnerMinosKey(req.user.username, document.documentId);
      const authorized = await runJavaJson("authorize", {
        publicKey: client.publicKey,
        proof: request.proof,
        registeredKeys: publicKeys.filter((k) => k.status !== "suspended").map((k) => k.publicKey),
        attributes: request.attributes,
        keys,
        ownerPrivateKey: owner.privateKey
      });
      tokens[document.documentId] = { token: authorized.token, indexKey: authorized.indexKey };
    }

    grants[grantKey(req.user.username, request.user)] = { tokens, grantedAt: new Date().toISOString() };
    saveGrants(grants);

    request.status = "approved";
    saveRequests(requests);

    res.json({ success: true, status: "approved", documents: documents.length });
  } catch (error) {
    console.error("Access decision error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// USER: SEARCH  (TrapGen for every granted document, then CSP Search, then Decrypt)
//
// A fresh trapdoor is generated on every search call. The CSP treats
// each trapdoor as one-time use, so simply calling search again already
// produces a trapdoor that has never been seen before.
// --------------------------------------------------

app.post("/api/search", authenticate, requireUser, async (req, res) => {
  try {
    const { owner, keyword } = req.body;
    if (!owner || !keyword) return res.status(400).json({ success: false, message: "owner and keyword are required" });

    const grants = readGrants();
    const grant = grants[grantKey(owner, req.user.username)];
    if (!grant) return res.status(403).json({ success: false, message: "No access to this owner" });

    const client = readPrivateUser(req.user.username);
    const users = readUsers();
    const ownerPublicKey = readPrivateUser(owner).publicKey;
    const w = keyword.trim().toLowerCase();

    const documentResults = [];
    for (const [documentId, { token, indexKey }] of Object.entries(grant.tokens)) {
      // TrapGen (Algorithm 6)
      const trapdoorResult = await runJavaJson("trapgen", { token, keyword: w, privateKey: client.privateKey });
      const trapdoor = trapdoorResult.trapdoor;

      // Search (Algorithm 7), executed by the CSP; one-time-use is enforced there.
      const searchResult = await csp("/api/csp/search", "POST", { ownerPublicKey, trapdoor });

      if (searchResult.status !== "OK") {
        documentResults.push({ documentId, status: searchResult.status });
        continue;
      }

      const ciphertexts = searchResult.matches.filter((m) => m.documentId === documentId).map((m) => m.ct4);
      if (!ciphertexts.length) continue;

      // Decrypt (Algorithm 8)
      const decrypted = await runJavaJson("decrypt", { indexKey, ciphertexts });
      documentResults.push({ documentId, status: "OK", ids: decrypted.ids });
    }

    const documents = readDocuments();
    const found = documentResults
      .filter((r) => r.status === "OK" && r.ids && r.ids.length)
      .map((r) => documents.find((d) => d.documentId === r.documentId))
      .filter(Boolean)
      .map((d) => ({ documentId: d.documentId, name: d.name }));

    const anyReplay = documentResults.some((r) => r.status === "REPLAY");
    const anySuspended = documentResults.some((r) => r.status === "SUSPENDED");

    res.json({
      success: true,
      documents: found,
      status: anySuspended ? "SUSPENDED" : anyReplay ? "REPLAY" : "OK"
    });
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// USER: DOWNLOAD + DECRYPT DOCUMENT
// --------------------------------------------------

app.get("/api/documents/:documentId/download", authenticate, requireUser, async (req, res) => {
  try {
    const document = readDocuments().find((d) => d.documentId === req.params.documentId);
    if (!document) return res.status(404).json({ success: false, message: "Document not found" });

    const grants = readGrants();
    if (!grants[grantKey(document.owner, req.user.username)]) {
      return res.status(403).json({ success: false, message: "Not authorised: search this document before downloading it" });
    }

    const { document: stored } = await csp(`/api/csp/documents/${document.documentId}`, "GET");
    const documentKey = await fs.promises.readFile(
      path.join(getOwnerKeyDirectory(document.owner), `${document.documentId.replace(/[^a-zA-Z0-9_-]/g, "_")}.key`),
      "utf8"
    );

    const outputFile = path.join(os.tmpdir(), `minos-decrypt-${crypto.randomUUID()}`);
    const encryptedFile = path.join(os.tmpdir(), `minos-encrypted-${crypto.randomUUID()}`);
    fs.writeFileSync(encryptedFile, Buffer.from(stored.encryptedDocumentBase64, "base64"));

    try {
      await runJavaJson("decrypt-document", {
        encryptedFile, outputFile,
        documentKeyBase64: documentKey.trim(),
        nonceBase64: stored.documentNonceBase64
      });
      const plaintext = await fs.promises.readFile(outputFile);
      res.setHeader("Content-Disposition", `attachment; filename="${document.name}"`);
      res.send(plaintext);
    } finally {
      fs.rm(outputFile, { force: true }, () => {});
      fs.rm(encryptedFile, { force: true }, () => {});
    }
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// OWNER: ALERTS + DETECT (Algorithm 11, falling back to Algorithm 9) + REVOKE
// --------------------------------------------------

app.get("/api/alerts", authenticate, requireOwner, async (req, res) => {
  try {
    const owner = readPrivateUser(req.user.username);
    const { alerts } = await csp(`/api/csp/alerts/${encodeURIComponent(owner.publicKey)}`, "GET");
    const documents = readDocuments().filter((d) => d.owner === req.user.username);
    const users = readUsers();

    const named = [];
    for (const alert of alerts) {
      let identifiedUser = "unknown";
      let verified = false;
      let keyword = null;

      for (const document of documents) {
        try {
          const keys = loadOwnerMinosKey(req.user.username, document.documentId);
          const result = await runJavaJson("detect", {
            trapdoor: alert.trapdoor,
            ownerPrivateKey: owner.privateKey,
            keys,
            keywords: document.keywords
          });

          const match = Object.values(users).find((u) => {
            try { return readPrivateUser(u.username).publicKey === result.publicKey; } catch { return false; }
          });
          identifiedUser = match ? match.username : "unknown";

          if (result.verified) { verified = true; keyword = result.keyword; break; }
        } catch { /* try the next document's K */ }
      }

      named.push({ tk3: alert.tk3, user: identifiedUser, verified, keyword, timestamp: alert.timestamp });
    }

    res.json({ success: true, alerts: named });
  } catch (error) {
    console.error("Alerts error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post("/api/access/revoke", authenticate, requireOwner, async (req, res) => {
  try {
    const { username, tk3 } = req.body;
    if (!validUsername(username) || typeof tk3 !== "string") return res.status(400).json({ success: false, message: "username and tk3 are required" });

    await csp("/api/csp/revoke", "POST", { userId: username, tk3 });

    const grants = readGrants();
    delete grants[grantKey(req.user.username, username)];
    saveGrants(grants);

    const requests = readRequests();
    for (const r of requests) if (r.owner === req.user.username && r.user === username) r.status = "revoked";
    saveRequests(requests);

    res.json({ success: true, message: `${username} revoked` });
  } catch (error) {
    console.error("Revoke error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// OWNER: TRACE  (Algorithm 10 - prove ownership of a document without revealing its keywords)
// --------------------------------------------------

app.post("/api/documents/:documentId/trace", authenticate, requireOwner, async (req, res) => {
  try {
    const document = readDocuments().find((d) => d.documentId === req.params.documentId && d.owner === req.user.username);
    if (!document) return res.status(404).json({ success: false, message: "Document not found" });

    const owner = readPrivateUser(req.user.username);
    const keys = loadOwnerMinosKey(req.user.username, document.documentId);

    const help = await runJavaJson("trace-help", {
      keyword: document.keywords[0],
      ownerPrivateKey: owner.privateKey,
      ownerPublicKey: owner.publicKey,
      keys
    });

    const result = await csp("/api/csp/trace", "POST", { documentId: document.documentId, helpData: help.helpData });
    res.json({ success: true, owned: result.valid === true });
  } catch (error) {
    console.error("Trace error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// ERRORS
// --------------------------------------------------

app.use((error, req, res, next) => {
  console.error(error);
  res.status(error.status || 500).json({ success: false, message: error.message || "Unexpected error" });
});

app.listen(PORT, () => console.log(`Minos backend running at http://localhost:${PORT}`));