# Minos – accountable attribute-based keyword search (Java web app)

A working implementation of **Minos: Bringing Accountability and Traceability to
Attribute-Based Keyword Search**. It runs as two Java servers and a browser front end:

```
Browser (HTML/CSS/JS)  ──HTTP──▶  Minos Server :8080  ──HTTP──▶  CSP Server :9090
                                  (owner/user side,              (cloud provider: encrypted
                                   key vault, web app)            index, ciphertexts, replay
                                                                  checks, Search, Trace)
```

All cryptography is in Java. Pairings use JPBC (`minos-java/lib/jpbc-api-2.0.0.jar`,
`minos-java/lib/jpbc-plaf-2.0.0.jar`), and everything else uses the JDK (AES-GCM, SHA-256,
HKDF/HMAC, PBKDF2, SecureRandom). The JDK's built-in `com.sun.net.httpserver`
provides HTTP. No other libraries, no Node.js, and the browser never runs Java
or does any cryptography.

## Requirements and running

- JDK 17 or newer (tested with OpenJDK 21).
- Linux/macOS: `./build.sh`, then in two terminals `./run-csp.sh` and `./run-minos.sh`.
- Windows: `build.bat`, then `run-csp.bat` and `run-minos.bat`.
- Run the scripts from the project root (the folder containing `minos-java/`, `backend/` and `frontend/`).
- Open **http://localhost:8080**. Start the CSP first; the Minos Server checks it is online.

On the first start the app shows the **Setup** page. Setup (Algorithm 1) runs once,
the parameters are saved to `backend/minos-data/config/public-params.bin`, and the public part is sent
to the CSP. Later starts load them and never regenerate them.

Data lives in two folders that survive restarts:

| Folder | Owner | Contents |
|---|---|---|
| `backend/minos-data/` | Minos Server | `config/` (mpk, server settings), `users.json` (public keys, attributes, PBKDF2 password hashes), `documents.json` (catalogue), `revocations.json`, `vault/` (AES-GCM-sealed secret keys), `logs/audit.log` |
| `backend/csp-storage/` | CSP Server | `encrypted-documents/`, `encrypted-index/` (Minos index L), `public-keys/` (registration list R), `metadata/` (wrapped file keys, trapdoor records, alerts, suspensions), `logs/` |

Delete both folders to start from scratch (stop the servers first).

Optional settings:
- `MINOS_VAULT_PASSPHRASE`: the vault key is derived from this passphrase with PBKDF2 instead of the random file `vault/master.key`.
- Arguments `--port`, `--csp`, `--data`, `--web` (Minos) and `--port`, `--storage` (CSP).

## Demo scenario

1. **Setup.** Run Setup with the default attribute universe HR, Manager, Employee, Finance, Admin.
2. **Register accounts.** Create `alice` (Admin, Manager), `bob` (HR, Employee), `carol` (Employee) and `mallory` (Finance).
3. **Upload.** Log in as alice acting as data owner, open **Upload**, choose a file, enter keywords `salary, payroll`, tick HR and Manager, and untick **"Users must ask me first"** (approval is shown in step 7).
4. **Search.** Log in as bob acting as data user (another browser or a private window) and search `payroll`. The document is found, decrypted and downloaded.
5. **Denied search.** Search as carol. Authorize fails, so no trapdoor is generated.
6. **Replay.** As bob, open **Security test**, press **Use the token from my last search** and **Submit**: the search token was already used, so it is refused and alice gets an alert. **Alter the token** shows that a modified copy is also caught. (The same token can be copied from the browser's DevTools → Network → `search` response and submitted by another user.)
7. **Approval and permissions.** As alice, upload a text file with **"Users must ask me first"** ticked. Bob's search lists it under *Waiting for owner approval*. Alice opens **Access requests**, ticks **View** (and optionally **Download** / **Modify**) and clicks **Approve**; bob presses **Search again** and gets only the buttons he is allowed.
8. **Maker-checker.** Give bob **Modify**. Bob clicks **Suggest changes**, edits the text and describes the change. Alice opens **Change requests → Review**, sees the removed/added lines, and approves or rejects. **History** shows every version (the original is always downloadable) and who viewed, downloaded or changed the document.
9. **Detect and block.** As alice, open **Security alerts**. Detect names bob as the account the token belongs to; press **Block bob from my documents**. Bob's next search is denied.
10. **Ownership dispute.** Open **Ownership claims**. Alice's claim verifies. Log in as mallory and claim alice's document: it is recorded as a false claim and alice gets an alert. After 3 false claims mallory is blocked from filing more for 24 hours.
11. **Restart.** Stop and restart both servers. Users, documents, alerts and revocations are all still there. **Restore** gives bob access again.

## Algorithms: paper versus implementation

| # | Algorithm | Class | When the app runs it |
|---|---|---|---|
| 1 | Setup | `minos.core.Setup` | Setup page, once (type-A pairing, 160-bit group order) |
| 2 | Register | `minos.core.Register` | Register page; pk goes to the CSP list R |
| 3 | KeyGen | `minos.core.KeyGen`, `AccessPolicy` | Lines 3–7 right after Register; lines 1–2 (M, π) for each document from its policy |
| 4 | Encrypt | `minos.core.Encrypt` | Upload: builds index L (ct1, ct2, ct3, ct4) |
| 5 | Authorize | `minos.core.Authorize` | Each search, per document: checks R, the Schnorr proof, revocation and (M, π), then issues TK |
| 6 | TrapGen | `minos.core.TrapGen` | Each search, per authorized document |
| 7 | Search | `minos.core.Search` | CSP, on the encrypted index |
| 8 | Decrypt | `minos.core.Decrypt` | Decrypts ct4 to document IDs |
| 9 / 11 | Detect | `minos.core.Detect` | On every replay alert: recovers pkc = tk3^(1/sko²); Algorithm 11 also checks tk5 and tk6 |
| 10 | Trace | `minos.core.Trace` | Ownership claim page; the CSP checks the help data |

### Corrections to the printed paper

`test/PaperEquationCheck.java` checks these numerically.

- **Search (Alg. 7, line 5).** `e(tk3·tk4, ct3)·Δ = 1` with `tk4 = pkc^(sko·H2(w))` never holds for the Alg. 4 ciphertext. The implementation adds `tk7 = e(tk3, sk2)` in Authorize. TrapGen raises tk4 to `1/H2(w)` and tk7 to `−1/H2(w)`, and Search checks `e(tk4, ct3)·Δ·tk7 = 1`.
- **Trace (Alg. 10).** `t1 = e(ct3, pko^(H2(w)+sko))` does not equal t2, even for the real owner. The help data adds `P1 = pko^(1/H2(w))` and `C0 = e(sk2, pko)^(sko/H2(w))`, and `t1 = e(ct3, P1)/C0`. This equals t2 only for the true owner.
- **tk3 = pkc^(sko²)**, so that Detect can divide by sko².
- **Hash functions.** The original code used JPBC `setFromHash` on the raw input, which reads only the first 20 bytes. Long keywords collided, and the Schnorr challenge was constant, so the proof could be forged. H1 and H2 are now SHA-256 with domain-separation tags; H2 is the digest reduced mod p.
- **Access structure.** (M, π) is a real Lewko–Waters LSSS matrix built from an AND/OR policy (with an injective π), not a random matrix. Authorize finds the γ coefficients for the client's attributes.

## Project extensions (not part of Minos)

- **Document bodies.** Minos encrypts only the keyword index. Each file is encrypted with AES-256-GCM under a fresh random key (`minos.ext.DocumentCrypto`). That key is wrapped under `HKDF(k, docId)` and stored wrapped at the CSP. It is never put in a trapdoor. Only a user who passes Authorize obtains k. The CSP releases the ciphertext only for a single-use retrieval ticket issued by a successful search (valid 15 minutes).
- **One-time trapdoors.** Each trapdoor T is wrapped in an envelope (`minos.ext.TrapdoorEnvelope`) containing:
  - a trapdoor ID, the document ID and a 128-bit random nonce;
  - issue and expiry times (10 minutes);
  - the SHA-256 of T;
  - an owner Schnorr signature over all of these.

  The CSP records each trapdoor hash and nonce. It rejects:
  - reuse (`REJECTED_REPLAY`);
  - a bad signature (`REJECTED_INVALID_ENVELOPE`; if T matches a used trapdoor, this also raises an alert);
  - expired envelopes;
  - trapdoors whose tk3 belongs to a suspended user;
  - an inconsistent tk5.

  The algorithm itself is unchanged.
- **Alerts and Detect.** On reuse the CSP stores an alert with the trapdoor hash, first-use time, reuse time, both submitting sessions and the reason "Trapdoor reuse detected". It notifies the Minos Server, which runs Detect with the owner's key and reports the identified user back, so the CSP sets R[pkc] ← tk3. Owners see alerts on their dashboard. **Detect identifies the registered account the trapdoor was issued to, not the physical person who reused it.**
- **Owner approval of access requests.** At upload the owner can tick *"Users must ask me first"* (ticked by default in the web app).
  - For such a document, a user whose attributes pass Authorize is **not** given a trapdoor until the owner approves them. Their first search sends an access request automatically.
  - The owner sees the request under **Access requests** and clicks **Approve** or **Deny**. They can change the decision later; approval is per user and per document.
  - The request shows only the user, their attributes and the document. The owner never sees the keyword, which matches the paper, where the owner's Authorize step does not depend on the keyword.
  - Approval cannot override the policy: a user whose attributes do not satisfy (M, π) is still refused by Authorize.
  - Requests are stored in `backend/minos-data/access-requests.json`.
- **Permissions per user.** When approving an access request the owner chooses **View** (read in the browser only), **Download** and/or **Modify**, and can change them later. Documents that do not require approval give View + Download. Permissions are stored with the request in `backend/minos-data/access-requests.json`.
- **Maker-checker changes and versions.** A user with Modify can only *suggest* a change.
  - The new version is encrypted like an upload (new AES key, wrapped under the owner's k) and signed with the editor's registered key. The CSP verifies the signature and stores it as **PENDING** (`encrypted-documents/<id>.v<n>.bin`).
  - Everyone keeps receiving the current approved version until the owner approves. The owner reviews a line-by-line comparison (`TextDiff`, longest common subsequence) for text files, or downloads both versions for other files.
  - Approval makes it the current version; rejection leaves the document unchanged. Nothing is overwritten: version 1 is always the owner's original and can always be downloaded.
  - The keyword index is not rebuilt on a change; keywords stay as the owner set them.
- **Document access log.** `backend/minos-data/logs/document-access.log` records, per document, who viewed, downloaded, suggested, approved or rejected changes, and when access was granted, with the version and details. The owner sees it on the document's **History** page and on the dashboard.
- **View in the browser.** Text, images and PDFs are shown inside the app. A user with View only gets no download button. For text and images the View page is protected (see Leak tracing).
- **Leak tracing (novelty).** Every copy of a text document given to a user is unique and recorded, so a leaked copy can be traced back to the user who received it. Two techniques work together:
  1. **Hidden signed code** (`Watermark`). A hidden mark of 56 spaces and tabs (space = 0, tab = 1) is added after the last character of every non-empty line. Notepad and other editors draw spaces and tabs as nothing, so the copy looks exactly like the original. (Earlier versions used zero-width characters and then variation selectors, which Windows Notepad draws as purple marks or boxes; those marks are still read and removed.) It carries a random 4-byte copy ID plus a 3-byte HMAC-SHA256 tag made with a key only the Minos Server has. A mark therefore cannot be changed or invented to blame another user; an altered mark is reported as altered. Even two copied lines identify the copy.
  2. **Visible wording differences** (`TextVariation`, a canary trap). At each "change point" the copy randomly uses one of two harmless forms: `2000`/`2,000`, `15-09-2026`/`15/09/2026`, `cannot`/`can't`, `colour`/`color`, `please`/`kindly`, and so on. More change types make short texts such as e-mails traceable too:
     - e-mail header names and MIME values whose case does not matter by the standards (RFC 5322, RFC 2045): `Message-ID`/`Message-Id`, `Mime-Version`/`MIME-Version`, `X-cc`/`X-CC`, `us-ascii`/`US-ASCII`, `7bit`/`7BIT`, `Re:`/`RE:`;
     - a middle initial with or without a full stop (`Phillip K Allen`/`Phillip K. Allen`);
     - a comma after a starting word (`However, we`/`However we`), the serial comma (`A, B and C`/`A, B, and C`), a capital after a colon (`Note: the`/`Note: The`);
     - `&`/`and` between capitalised words, `10%`/`10 percent`, month and day names next to numbers (`5 Oct`/`5 October`, `Thu,`/`Thursday,`), and a full stop at the end of a short sentence line.

     In an e-mail header block only the header-name case and middle initials change; values such as dates, addresses and IDs are never changed. A short Enron e-mail with a three-line body now has about 13 change points (before: 0–2). These survive screenshots, printouts and retyping of exact lines, where the hidden code is lost. The owner types the visible lines, or extracts them from the image with Google Lens or the Snipping Tool, and the system finds the copy with that combination. Matching undoes characters that text recognition changes (curly quotes, long dashes), skips stray characters, and allows one misread difference in every eight.
  - Each copy (copy ID, user, document, version, Download or View, time, chosen forms) is stored in `backend/minos-data/leak-copies.json`. The owner sees them under **History → Traceable copies issued**. The stored original is never changed, and the owner's own download is always the exact original.
  - **Copies are spread apart.** When a copy is made, 64 random patterns are tried and the one that differs most from every earlier copy of that version is kept, so no two users get near-identical copies.
  - **Match percentage and ranking.** Find the leaker lists every downloaded copy of the document with the share of the observed differences it matches (for example meena 100%, next 66.7%; a copy that was not leaked scores about 50% by chance), and shows the chance of an accidental match (1 in 2^n for n differences, adjusted for misreads).
  - **Changes in the leaked text** (`LeakDiff`). Shown like the review of a suggested change: lines removed from the original in red, lines added in the leak in green, unchanged lines folded. Lines are compared by their canonical form, so the per-copy differences, capital letters, spacing and punctuation are ignored and only real edits appear. Text that Google Lens returned as one long line is first matched back onto the original's lines. Long files are handled by pairing equal starts and ends, then a line-level longest common subsequence, and for very long parts splitting at lines that occur only once in both texts (patience alignment); a 3,000-line file takes about 2 seconds.
  - **Find the leaker** (owner page) takes pasted text or an uploaded .txt file and reports: *this is X's copy* (hidden code), *most likely X's copy* (wording), *could be one of N copies* (too short), or *no match*. Each match is written to the document log (`LEAK_TRACED`).
  - Tracing is always on for text uploads in the web app (the API still accepts `leakTracing: false` for a document). If a document has fewer than 8 change points, the owner is warned that a screenshot may match several copies.
  - Suggested changes are cleaned: hidden codes are removed and the user's variant forms are turned back into the original forms, so the review shows only the real edit.
  - **View page protection.** Copying is blocked (selection, Ctrl+C/A/X/S, right-click, drag). Ctrl+P and printing are blocked (the print shows "Printing is disabled"). Print Screen blurs the page. The page also blurs while Ctrl, Alt, Shift or the Windows key is held, when the window loses focus (snipping tool, another app) or when the mouse leaves the page. A faint tiled watermark shows the viewer's name, ID and time. Copy, print and Print Screen attempts raise a **View protection** alert for the owner (repeats within 10 minutes are grouped); leaving the window is only logged. The number next to **Security alerts** counts only alerts the owner has not opened yet; it clears when the alerts page is opened and comes back when a new alert arrives or a grouped alert repeats. The text on the page is itself a traceable copy.
- **Ownership disputes (around Trace).** Any logged-in user can file an ownership claim on any document, with an optional reason, on the **Ownership claims (Trace)** page.
  - The claim is signed with the claimant's registered key. The CSP identifies the claimant from the registration list R, so nobody can file a claim in someone else's name.
  - The CSP runs Trace and records every claim in `backend/csp-storage/metadata/ownership-claims.json`.
  - A **false** claim raises a `FALSE_OWNERSHIP_CLAIM` alert for the real owner. It shows the claimant, their stated reason, and their number of false claims, and offers a Revoke button.
  - After 3 false claims within 24 hours, the claimant's further claims are refused without running Trace until the 24 hours pass. The real owner's own claims are never blocked.
- **Revocation.** The owner revokes a user. Authorize then refuses them, and the CSP suspends their tk3 for that owner. Restore reverses both.
- **Key vault.** β, the KeyGen output K and each document's keyword list are sealed with AES-GCM on the Minos Server. The entry name is bound to the ciphertext as associated data (AAD), so sealed entries cannot be swapped. Secret keys are never sent to the CSP.
- **Accounts and roles.** Passwords are stored as PBKDF2-HMAC-SHA256 hashes (210,000 iterations). Sessions use HttpOnly, SameSite=Strict cookies. One account can switch between acting as data owner and data user.
- **Server link.** Server-to-server calls (Minos ↔ CSP) carry a shared link key, created at Setup.
- **Swappable CSP storage.** CSP storage sits behind the `BlobStore` interface; `LocalBlobStore` is the local-disk version. A cloud store can replace it without other changes.

## Trust model and limitations

- **The Minos Server is a trusted proxy.** It holds every account's secret keys in its vault and runs both sides of Authorize and Detect, following the owner-side service model in the paper (§VIII-A). An attacker who compromises it gets all keys. The CSP is treated as honest-but-curious: it stores no document text, file names, keywords or secret keys.
- **Attributes are self-declared at registration.** No attribute authority vouches for them; a real deployment would need one.
- **Trapdoor cores repeat.** TrapGen and tk3 are deterministic in the paper, and Detect and revocation depend on that. Identical searches by the same user therefore produce the same mathematical trapdoor T. What makes every submission unique and single-use is the envelope: new ID, random nonce, expiry and signature.
- **tk4 has a public transform weakness.** Anyone holding tk4 can raise it to a known power. The envelope signature plus tk5 make altered trapdoors detectable in this app, but this is a property of the scheme.
- **Trace reveals some key material to the CSP.** The help data shows the CSP `sk2^γ` and `sk1^γ` for the document's policy rows.
- **The CSP sees access patterns.** It learns which document a trapdoor targets and whether it matched; this is inherent to the scheme.
- **Demo scale.** Each search runs Authorize per document. That is fine for a demonstration, but slow for thousands of documents.
- **Leak tracing has limits.** It cannot trace text that was paraphrased, lines with no change points, copies combined by several users (reported as "several copies"), phone photos of the screen, captures taken before the page reacts (for example a Print Screen or a delayed snip), documents with tracing switched off, or non-text files. Browser protection can be bypassed by someone who disables JavaScript or uses the developer tools; the page text is still a traceable copy in that case.
- **HTTP only.** The servers serve plain HTTP on localhost. Put them behind TLS before using them over a network.

## Tests

- `./run-tests.sh` (or `run-tests.bat`) builds and runs `PaperEquationCheck`. On Linux/macOS it then starts fresh servers on ports 18080 and 19090, runs `EndToEndTest phase1`, restarts both servers and runs `phase2` (persistence).
- Last run: 133 checks passed, 0 failed (including leak tracing, ranking and change detection).

## Performance evaluation (paper Section VII)

`run-benchmark.bat` (Windows) or `./run-benchmark.sh` runs `minos-java/test/Benchmark.java` and reproduces the paper's graphs for Minos:

- **Fig. 2 (Encrypt), Fig. 3 (TrapGen), Fig. 4 (Search)**, each in four settings: (a) 1 keyword and (b) 10 keywords with 1-100 attributes; (c) 1 attribute and (d) 10 attributes with 1-100 keywords.
- **Fig. 5 (Detect and Trace)** with 100 keywords and 10 attributes, plotting the total time of 1-100 runs.
- **A summary table** with every algorithm at 10 attributes and 10 keywords, plus sizes.

Settings follow the paper: type-A pairing, 160-bit order, AES, SHA-256, and the median of 10 runs after warm-up runs. For n attributes the rule is `A1 AND ... AND An` and the user holds all of them, so all n attributes are used. A trapdoor for m keywords computes the attribute part once and the keyword part m times.

Results go to `benchmark-results/`: `fig2a.csv` … `fig5.csv`, `summary.csv`, and `report.html` with all graphs.

Options:
- `--quick`: 3 runs and fewer points.
- `--runs=10`: number of measured runs per point.
- `--step=10`: distance between x values.
- `--max=100`: largest number of attributes or keywords.
- `--out=folder`: where to write the results.

**Using the Enron email dataset (as in the paper, Section VII-C.4).** Pass `--enron=PATH`. PATH is either:
- the extracted CMU `maildir` folder (`enron_mail_20150507.tar.gz` from https://www.cs.cmu.edu/~enron/), or
- the Kaggle `emails.csv` file.

For example:
```
run-benchmark.bat --enron="C:\data\emails.csv"
```

Each email is one document, identified by its file name. The subject and body words are lower-cased and stop words are removed. The most frequent words become the keywords, and each keyword gets the same number of document identifiers (`--ids=5`). By default the first 20,000 emails are read; change this with `--emails=`. The chosen keywords are saved in `benchmark-results/enron-keywords.csv`.

**Paper-style figures.** `plot-figures.bat` (or `./plot-figures.sh`) runs `plot_figures.py`, which needs Python 3 and matplotlib. It draws `fig2.png` … `fig5.png` (300 dpi, plus PDF), laid out like the paper: four sub-figures (a)-(d) side by side, with the paper's titles, axis labels and captions. Each sub-figure is also saved on its own.

The other schemes in the paper's figures (ABERKS, ABKRS-KGA, ABHBKS) are not implemented here, so only the Minos curve is produced.

## Layout

The folders follow the original project (`minos-java/`, `backend/`, `frontend/`).
The backend is now Java instead of Node.js, and the frontend is plain HTML/CSS/JS
served by the Minos Server instead of a React/Vite app.

```
minos-java/              Minos cryptography (shared library)
  src/minos/core/        the ten Minos algorithms + AccessPolicy (LSSS), HashFunctions, Codec, MinosStorage
  src/minos/ext/         project extensions: DocumentCrypto, TrapdoorEnvelope, SchnorrSignature, KeyVault
  src/minos/common/      JSON, HTTP router/client, crypto helpers, BlobStore / LocalBlobStore
  test/                  PaperEquationCheck.java
  lib/                   JPBC jars
backend/                 the two Java servers (use minos-java)
  src/minos/server/      Minos Server, port 8080 (MinosServer, MinosService, TextDiff)
  src/minos/csp/         CSP Server, port 9090 (CspServer)
  test/                  EndToEndTest.java
  minos-data/            created at runtime (Minos Server data, key vault)
  csp-storage/           created at runtime (CSP storage)
frontend/                index.html, app.js, style.css (plain-language screens; no algorithm details are shown)
legacy/                  your original Node/React/Java CLI sources, for reference only (not used)
build.sh/.bat, run-csp.sh/.bat, run-minos.sh/.bat, run-tests.sh/.bat
```
