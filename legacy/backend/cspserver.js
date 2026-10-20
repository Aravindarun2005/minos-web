const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { promisify } = require("util");

const app = express();
const execFileAsync = promisify(execFile);

const PORT = process.env.CSP_PORT || 5001;

// --------------------------------------------------
// The CSP shares the Minos setup file (mpk) with the Minos backend,
// because Search and Trace both need mpk to verify pairings. The CSP
// never holds a private key: a trapdoor and Trace's help data are
// both public-safe values, exactly as the paper defines them.
// --------------------------------------------------

const ROOT = __dirname;
const JAVA_DIR = path.resolve(ROOT, "../minos-java");
const SETUP_FILE = path.join(ROOT, "data", "minos-setup.bin");

const DATA_DIR = path.join(ROOT, "csp-data");
const KEYS_DIR = path.join(DATA_DIR, "public-keys");
const INDEX_DIR = path.join(DATA_DIR, "index");
const FILES_DIR = path.join(DATA_DIR, "files");
const TRAPDOORS_FILE = path.join(DATA_DIR, "trapdoors.json");
const ALERTS_FILE = path.join(DATA_DIR, "alerts.json");
const SUSPENDED_FILE = path.join(DATA_DIR, "suspended-trapdoors.json");

for (const dir of [KEYS_DIR, INDEX_DIR, FILES_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json({ limit: "50mb" }));

// --------------------------------------------------
// JAVA EXECUTION (Algorithms 7 and 10 run on the CSP)
// --------------------------------------------------

function runJava(args) {
  return execFileAsync(
    "java",
    ["-cp", `.${path.delimiter}lib/*`, "Main", ...args],
    { cwd: JAVA_DIR, timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
  ).then(
    ({ stdout }) => JSON.parse(stdout.trim()),
    (error) => {
      throw new Error((error.stderr || error.stdout || error.message || "").trim().split("\n")[0]);
    }
  );
}

// Algorithms 7 and 10 take a JSON input file; write it to a temp file
// so we never build shell arguments out of large ciphertext blobs.
async function runJavaWithInput(command, input) {
  const file = path.join(os.tmpdir(), `minos-${command}-${crypto.randomUUID()}.json`);
  fs.writeFileSync(file, JSON.stringify(input));
  try {
    return await runJava([command, SETUP_FILE, file]);
  } finally {
    fs.rmSync(file, { force: true });
  }
}

// --------------------------------------------------
// LOCAL STORAGE HELPERS
// --------------------------------------------------

function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return fallback; }
}

// Write to a temp file and rename, so a crash never leaves a half-written file.
function writeAtomic(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

function writeJson(file, data) { writeAtomic(file, JSON.stringify(data, null, 2)); }

function validUserId(userId) {
  return typeof userId === "string" && /^[a-zA-Z0-9_.-]{3,30}$/.test(userId) && !/^\.+$/.test(userId);
}

// IDs become file names, so only allow characters that cannot escape the folder.
function validDocumentId(documentId) {
  return typeof documentId === "string" && /^[A-Za-z0-9-]{8,64}$/.test(documentId);
}

function validBase64(value) {
  return typeof value === "string" && value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function validIndexEntry(entry) {
  return entry && typeof entry.type === "string" &&
    (typeof entry.row === "number" || typeof entry.row === "string") &&
    typeof entry.ct1 === "string" && typeof entry.ct2 === "string" &&
    typeof entry.ct3 === "string" && typeof entry.ct4 === "string";
}

const keyPath = (userId) => path.join(KEYS_DIR, `${userId}.json`);
const indexPath = (id) => path.join(INDEX_DIR, `${id}.json`);
const filePath = (id) => path.join(FILES_DIR, `${id}.enc`);
const metaPath = (id) => path.join(FILES_DIR, `${id}.meta.json`);

function listJson(dir) {
  return fs.readdirSync(dir)
    .filter((name) => name.endsWith(".json") && !name.endsWith(".meta.json"))
    .map((name) => readJson(path.join(dir, name)))
    .filter(Boolean);
}

function documentExists(id) { return fs.existsSync(indexPath(id)) || fs.existsSync(filePath(id)); }

// Stores one document as three pieces: ciphertext file, metadata, encrypted index.
function storeDocument({ documentId, ownerPublicKey, encryptedDocumentBase64, documentNonceBase64, indexEntries, uploadedAt }) {
  const ciphertext = Buffer.from(encryptedDocumentBase64, "base64");
  const stamp = uploadedAt || new Date().toISOString();

  try {
    fs.writeFileSync(filePath(documentId), ciphertext, { flag: "wx" });
    writeJson(metaPath(documentId), {
      documentId, ownerPublicKey,
      documentNonceBase64: documentNonceBase64 || "",
      sizeBytes: ciphertext.length,
      sha256: crypto.createHash("sha256").update(ciphertext).digest("hex"),
      uploadedAt: stamp
    });
    // The index is written last: a document is searchable only once fully stored.
    writeJson(indexPath(documentId), { documentId, ownerPublicKey, uploadedAt: stamp, entryCount: indexEntries.length, entries: indexEntries });
  } catch (error) {
    for (const f of [filePath(documentId), metaPath(documentId), indexPath(documentId)]) fs.rmSync(f, { force: true });
    throw error;
  }
}

function loadDocument(id) {
  const meta = readJson(metaPath(id));
  const index = readJson(indexPath(id));
  if (!meta || !index || !fs.existsSync(filePath(id))) return null;
  return {
    documentId: id, ownerPublicKey: meta.ownerPublicKey,
    encryptedDocumentBase64: fs.readFileSync(filePath(id)).toString("base64"),
    documentNonceBase64: meta.documentNonceBase64,
    indexEntries: index.entries, sizeBytes: meta.sizeBytes, sha256: meta.sha256, uploadedAt: meta.uploadedAt
  };
}

// A stable fingerprint of a trapdoor: same field values in any key order hash the same way.
function trapdoorFingerprint(trapdoor) {
  const stable = JSON.stringify(trapdoor, Object.keys(trapdoor).sort());
  return crypto.createHash("sha256").update(stable).digest("hex");
}

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Minos CSP server running",
    port: Number(PORT),
    setupAvailable: fs.existsSync(SETUP_FILE),
    stored: {
      publicKeys: listJson(KEYS_DIR).length,
      encryptedDocuments: fs.readdirSync(FILES_DIR).filter((n) => n.endsWith(".enc")).length,
      indexes: listJson(INDEX_DIR).length
    }
  });
});

// --------------------------------------------------
// PUBLIC KEYS  (Register: R.add(pk))
// --------------------------------------------------

app.post("/api/csp/register-public-key", (req, res) => {
  try {
    const { userId, publicKey } = req.body;

    if (!validUserId(userId) || !validBase64(publicKey)) {
      return res.status(400).json({ success: false, message: "Invalid user ID or public key" });
    }
    if (fs.existsSync(keyPath(userId))) {
      return res.status(409).json({ success: false, message: "Public key already registered" });
    }

    writeJson(keyPath(userId), { userId, publicKey, status: "active", registeredAt: new Date().toISOString() });
    return res.status(201).json({ success: true, message: "Public key registered", userId });
  } catch (error) {
    console.error("Public key registration:", error);
    return res.status(500).json({ success: false, message: "Unable to register public key" });
  }
});

app.get("/api/csp/public-keys", (req, res) => res.json({ success: true, publicKeys: listJson(KEYS_DIR) }));

app.get("/api/csp/public-keys/:userId", (req, res) => {
  const key = validUserId(req.params.userId) ? readJson(keyPath(req.params.userId)) : null;
  if (!key) return res.status(404).json({ success: false, message: "Public key not found" });
  res.json({ success: true, publicKey: key });
});

// --------------------------------------------------
// OWNER UPLOADS ENCRYPTED DOCUMENT + ENCRYPTED INDEX  (Encrypt output)
// --------------------------------------------------

app.post("/api/csp/documents", (req, res) => {
  try {
    const { documentId, ownerPublicKey, encryptedDocumentBase64, documentNonceBase64, indexEntries } = req.body;

    if (!validDocumentId(documentId) || !validBase64(ownerPublicKey) || !validBase64(encryptedDocumentBase64) ||
      !Array.isArray(indexEntries) || !indexEntries.every(validIndexEntry)) {
      return res.status(400).json({ success: false, message: "Invalid encrypted document payload" });
    }
    if (documentExists(documentId)) {
      return res.status(409).json({ success: false, message: "Document ID already exists" });
    }

    storeDocument({ documentId, ownerPublicKey, encryptedDocumentBase64, documentNonceBase64, indexEntries });
    return res.status(201).json({ success: true, message: "Encrypted document and index stored", documentId, indexEntryCount: indexEntries.length });
  } catch (error) {
    console.error("Encrypted document upload:", error);
    return res.status(500).json({ success: false, message: "Unable to store encrypted document" });
  }
});

app.get("/api/csp/documents", (req, res) => {
  const documents = fs.readdirSync(FILES_DIR)
    .filter((name) => name.endsWith(".meta.json"))
    .map((name) => {
      const meta = readJson(path.join(FILES_DIR, name));
      const index = meta && readJson(indexPath(meta.documentId));
      return meta && index && {
        documentId: meta.documentId, ownerPublicKey: meta.ownerPublicKey,
        uploadedAt: meta.uploadedAt, sizeBytes: meta.sizeBytes, indexEntryCount: index.entryCount
      };
    })
    .filter(Boolean);
  res.json({ success: true, documents });
});

app.get("/api/csp/documents/:documentId", (req, res) => {
  const document = validDocumentId(req.params.documentId) ? loadDocument(req.params.documentId) : null;
  if (!document) return res.status(404).json({ success: false, message: "Document not found" });
  res.json({ success: true, document });
});

app.get("/api/csp/index", (req, res) => res.json({ success: true, indexes: listJson(INDEX_DIR) }));

app.get("/api/csp/index/:documentId", (req, res) => {
  const index = validDocumentId(req.params.documentId) ? readJson(indexPath(req.params.documentId)) : null;
  if (!index) return res.status(404).json({ success: false, message: "Index not found" });
  res.json({ success: true, index });
});

app.delete("/api/csp/documents/:documentId", (req, res) => {
  const { documentId } = req.params;
  if (!validDocumentId(documentId) || !documentExists(documentId)) {
    return res.status(404).json({ success: false, message: "Document not found" });
  }
  for (const f of [filePath(documentId), metaPath(documentId), indexPath(documentId)]) fs.rmSync(f, { force: true });
  res.json({ success: true, message: "Encrypted document deleted", documentId });
});

// --------------------------------------------------
// SEARCH  (Algorithm 7, run by the CSP)
//
// A trapdoor is accepted once. The CSP fingerprints it, and if the
// same fingerprint is submitted again it is a replay: the search is
// refused and an alert is queued for the data owner instead of being
// run again. A trapdoor bound to a revoked identity is refused outright.
// --------------------------------------------------

app.post("/api/csp/search", async (req, res) => {
  try {
    const { ownerPublicKey, trapdoor } = req.body;
    if (!validBase64(ownerPublicKey) || !trapdoor || typeof trapdoor !== "object") {
      return res.status(400).json({ success: false, message: "Invalid search request" });
    }
    if (!fs.existsSync(SETUP_FILE)) {
      return res.status(400).json({ success: false, message: "Minos is not initialized yet" });
    }

    const suspended = readJson(SUSPENDED_FILE, []);
    if (suspended.includes(trapdoor.tk3)) {
      return res.json({ success: true, status: "SUSPENDED", matches: [] });
    }

    const fingerprint = trapdoorFingerprint(trapdoor);
    const seen = readJson(TRAPDOORS_FILE, []);

    if (seen.some((entry) => entry.fingerprint === fingerprint)) {
      // One-time use violated: queue an alert for the data owner, do not search again.
      const alerts = readJson(ALERTS_FILE, []);
      alerts.push({ ownerPublicKey, tk3: trapdoor.tk3, timestamp: Date.now(), trapdoor });
      writeJson(ALERTS_FILE, alerts);
      return res.json({ success: true, status: "REPLAY", matches: [] });
    }

    seen.push({ fingerprint, tk3: trapdoor.tk3, ownerPublicKey, timestamp: Date.now(), trapdoor });
    writeJson(TRAPDOORS_FILE, seen);

    // Search runs over every document belonging to this owner.
    const documentIds = fs.readdirSync(INDEX_DIR)
      .filter((n) => n.endsWith(".json"))
      .map((n) => n.slice(0, -5))
      .filter((id) => (readJson(indexPath(id)) || {}).ownerPublicKey === ownerPublicKey);

    const matches = [];
    for (const documentId of documentIds) {
      const index = readJson(indexPath(documentId));
      let result;
      try {
        result = await runJavaWithInput("search", { entries: index.entries, trapdoor });
      } catch {
        continue; // trapdoor rows do not apply to this document's attributes
      }
      for (const ct4 of result.matches || []) matches.push({ documentId, ct4 });
    }

    res.json({ success: true, status: "OK", matches });
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// ALERTS  (surfaced to the data owner; cleared once the owner revokes)
// --------------------------------------------------

app.get("/api/csp/alerts/:ownerPublicKey", (req, res) => {
  const alerts = readJson(ALERTS_FILE, []).filter((a) => a.ownerPublicKey === req.params.ownerPublicKey);
  res.json({ success: true, alerts });
});

// --------------------------------------------------
// REVOKE  (owner ran Detect / Algorithm 11; block this trapdoor and this identity)
// --------------------------------------------------

app.post("/api/csp/revoke", (req, res) => {
  try {
    const { userId, tk3 } = req.body;
    if (!validUserId(userId) || typeof tk3 !== "string" || !tk3) {
      return res.status(400).json({ success: false, message: "Invalid revoke request" });
    }

    const record = readJson(keyPath(userId));
    if (!record) return res.status(404).json({ success: false, message: "Public key not found" });

    record.status = "suspended";
    writeJson(keyPath(userId), record);

    const suspended = readJson(SUSPENDED_FILE, []);
    if (!suspended.includes(tk3)) suspended.push(tk3);
    writeJson(SUSPENDED_FILE, suspended);

    writeJson(ALERTS_FILE, readJson(ALERTS_FILE, []).filter((a) => a.tk3 !== tk3));

    res.json({ success: true, message: `${userId} suspended`, userId });
  } catch (error) {
    console.error("Revoke error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// TRACE  (Algorithm 10, run by the CSP against owner-supplied help data)
// --------------------------------------------------

app.post("/api/csp/trace", async (req, res) => {
  try {
    const { documentId, helpData } = req.body;
    if (!validDocumentId(documentId) || !helpData || typeof helpData !== "object") {
      return res.status(400).json({ success: false, message: "Invalid trace request" });
    }

    const index = readJson(indexPath(documentId));
    if (!index) return res.status(404).json({ success: false, message: "Document not found" });

    const result = await runJavaWithInput("trace", { entries: index.entries, helpData });
    res.json({ success: true, valid: result.valid === true });
  } catch (error) {
    console.error("Trace error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// --------------------------------------------------
// ERRORS (bad JSON, oversized bodies)
// --------------------------------------------------

app.use((error, req, res, next) => {
  const status = error.status || 500;
  res.status(status).json({ success: false, message: status === 413 ? "Payload too large" : "Bad request" });
});

app.listen(PORT, () => {
  console.log(`Minos CSP running at http://localhost:${PORT}`);
  console.log("CSP data directory:", DATA_DIR);
  console.log("Shared Minos setup file:", SETUP_FILE, fs.existsSync(SETUP_FILE) ? "(found)" : "(not created yet)");
});
