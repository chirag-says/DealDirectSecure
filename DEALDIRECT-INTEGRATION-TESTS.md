# DealDirect: Integration Test Foundation

Phase 3A. Built the harness described in §6 of `DEALDIRECT-PHASE3-ARCHITECTURE-PLAN.md`.
No Phase 3 business or architecture change is included.

The existing 471-test unit suite is untouched and still runs on its own command.

---

## 1. What this is for

The unit suite asserts against source text and pure functions. It cannot see the
class of bug that has caused the most damage in this codebase: a value that is
accepted by the API, reported as saved, and silently discarded before it reaches
the database. The whitelist looks correct in isolation, the schema looks correct
in isolation, and the field is gone.

These tests answer a different question: *if a real request goes through the real
middleware chain into a real database, what actually happens?*

Everything runs in-process against a private in-memory MongoDB. Nothing is
mocked at the module level, so the code under test is the code that ships.

---

## 2. Running it

```bash
cd backend && npm run test:integration
```

| Command | Scope | Tests | Wall clock |
|---|---|---|---|
| `npm test` | unit / source-text suite, unchanged | 471 in 92 suites | ~2.6 s |
| `npm run test:integration` | this harness | 134, no todo | ~15 s |
| `npm run test:all` | both, sequentially | 605 | ~18 s |

`npm test` now globs `tests/*.test.js` rather than `tests/**/*.test.js`, so the
integration suites do not run twice or slow the fast loop down. That is the only
change to the existing command.

`NODE_ENV=test` is supplied by `node --env-file=tests/integration/test.env`, which
works the same on Windows `cmd`, PowerShell and POSIX shells and needs no
`cross-env` dependency.

### Timings

| Step | Cost |
|---|---|
| Module import (supertest, setup modules) | ~440 ms |
| Harness boot (mongod replica set + `server.js` import) | ~1.7 s |
| Truncate between tests, with data present | ~35 ms |
| Truncate between tests, warm | ~14 ms |
| Teardown (stop fake provider, close Mongo, stop mongod) | ~360 ms |
| One suite file, end to end | ~2.1 s + its own tests |

Node runs each test file in its own process, so the ~2.1 s boot is paid once per
suite file (seven of them). That is the price of process isolation between suites and is worth it at
this size; if the suite count grows past roughly a dozen files it will be worth
revisiting.

---

## 3. Safety: how database isolation is proved, not asserted

The requirement was that the environment be *provably incapable* of reaching a
real database. Four independent things have to be true, and each is checked.

**1. The guard runs before anything else.** `setup/guard.js` refuses to proceed
unless `NODE_ENV === 'test'`, and refuses outright if it is `production`. This
matters because `server.js` reads `.env` at import time and would otherwise open
a connection to whatever `MONGO_URI` a developer has configured, on this machine,
a shared Atlas cluster.

**2. The target URI is allow-listed, not block-listed.** A URI is accepted only
if it is `mongodb://`, on a loopback host, with a database name containing
`test`. Hosted `mongodb+srv://` is rejected outright.

This shape was chosen deliberately. A block-list of production hostnames is one
new cluster away from being wrong, and it would require putting a production URI
into the repository in order to recognise it, which is worse than the problem it
solves. **No production URI, hostname or credential appears anywhere in this
work.** The guard does not need one: anything that is not provably local fails.

**3. The connection is asserted at runtime.** `isolation.test.js` checks the live
Mongoose connection: host is `127.0.0.1`, database name matches `/test/i`, and
the collections are empty at the start of the run. A harness pointed at real data
would fail on the third check even if it somehow passed the first two.

**4. The guard is tested against unsafe inputs.** Six cases assert it rejects a
hosted cluster, a remote host, a local database not named as a test database, a
URI with no database name, and empty input, and accepts the in-memory URI in use.

### Application-code seams

Three guarded changes were needed in `server.js`. Each is a no-op outside tests:

| Location | Change | Why |
|---|---|---|
| `server.js:131` | `connectDB()` wrapped in `if (process.env.NODE_ENV !== "test")` | The harness owns the connection |
| `server.js:1007` | `httpServer.listen()` wrapped in the same guard | Supertest binds its own ephemeral port; nothing listens on 9000 |
| `server.js:1030` | `export { app, io, httpServer }` | `app` was not exported, so the middleware chain was unreachable |

A fourth change, in `services/hubbleService.js`, is not a test seam but a fix:
its module-level `setInterval` had no `unref()`, so it held the event loop open
forever. In the running server the listening socket keeps the process alive
anyway, so behaviour is unchanged there; in a process with no server handle,
the test runner, nothing could ever exit, and every suite failed on timeout
rather than on its assertions.

---

## 4. Safety: external services

Two independent layers, because either alone can be defeated by an ordinary
mistake.

### Layer 1: credentials neutralised

Every outbound integration in this codebase already has a "not configured, skip"
branch. Blanking its credentials makes the application take its own real skip
path, which is better than a mock: it exercises the code that runs in a
misconfigured production box, and there is no stub to drift out of sync.

| Service | Guard | Result in tests |
|---|---|---|
| Email (SMTP) | `utils/emailService.js:440` | returns `{skipped: true}`, no connection |
| WhatsApp (WAHA) | `services/whatsappService.js:90` | returns not-configured |
| Rewards catalog (RewardPort) | `services/rewardPortService.js:151` | returns not-configured |
| Rewards debit (Hubble) | secret unset | cannot authenticate |
| AI (Gemini) | key unset |, |
| Error reporting (Sentry) | DSN unset | disabled at boot |

The blanking is **driven by the `.env` file itself**, not by a list kept in the
harness. Only key *names* are read; no value is ever read, logged or stored.

This inversion was not the first design, and the reason for it is worth
recording: the first version enumerated the integrations it knew about and
silently let `SENTRY_DSN`, `REWARDPORT_USERNAME` and `REWARDPORT_PASSWORD`
through, because nobody had thought of them. A hand-maintained list is fail-open.
Reading the names off `.env` means a credential added tomorrow is neutralised
without anyone remembering to update this file.

The empty string is load-bearing: `dotenv.config()` does not overwrite a key that
already exists in `process.env`, so pre-setting to `""` stops the real `.env`
from repopulating live credentials when `server.js` is imported. Deleting the
keys instead would let `.env` win.

`isolation.test.js` asserts that `residualConfiguredKeys()` is empty, that is,
no key which could reach a live service still holds a value.

### Layer 2: network egress blocked

Layer 1 depends on every integration having a config guard, now and after future
edits. Layer 2 does not depend on the application at all: it wraps
`http.request`, `https.request` and `fetch`, and refuses anything not bound for
loopback. A new integration added next month that calls a hard-coded URL is still
stopped.

The block surfaces as an asynchronous `error` event, which is how Node reports an
unreachable host. Throwing synchronously looked stricter and was wrong: the
Cloudinary SDK calls `https.request` inside a promise executor and only handles
the async event, so a synchronous throw escaped as an uncaught exception and
`server.js`'s crash handler tore the process down, every suite then failed for
that reason instead of its own.

Blocked attempts are recorded, so tests assert on them directly rather than
trusting a claim in a document.

### Two services that cannot simply be switched off

**SMS.** `registerUser` (`userController.js:315`) returns 500 when
`isSmsConfigured()` is false. With SMS disabled there is no way to reach the OTP
path at all, and the most security-relevant flow in the product would go
untested.

So the SMS client is *redirected*, not disabled: `setup/fakeProviders.js` runs a
real HTTP server on `127.0.0.1` and points `EQUENCE_BASE_URL` at it. The
application builds a genuine request, sends it, and parses a genuine
provider-shaped reply, none of which a module mock would exercise. The traffic is
provably local, because the egress blocker permits nothing else.

It also means the OTP tests read the code out of the delivered message rather
than planting one in the database, which is how a real user gets it. The
assertion "the stored value is not the OTP" stays meaningful, because nothing in
the test recomputes the stored hash.

**Image upload.** `validateAndUploadToCloudinary` (`upload.js:379`) returns 503
for *any* request on a route it guards, whether or not that request carries a
file. Owner property create and update both sit behind it, so with Cloudinary
disabled even a title-only JSON update is refused, and the two most important
authorisation paths could not be tested.

The harness therefore supplies a synthetic `CLOUDINARY_URL`
(`...@integration-test-cloud`). No outbound call happens on a file-less request.
The one call this does trigger is the startup `cloudinary.api.ping()`, which the
egress blocker refuses and the module's own `.catch` swallows. That refusal is
the proof these credentials reach nothing.

> Worth flagging for Phase 3: an image service being down should not stop an owner
> editing a description. The 503 is unconditional.

### Test data

Synthetic only. Emails are `test-*@example.com` (RFC 2606, reserved and
undeliverable), phones are in the `99999xxxxx` / `98765xxxxx` fixture range, names
are obviously fake. No production identifier, customer record, or exported
document is used anywhere.

The synthetic secrets in `setup/externals.js` (`integration-test-jwt-secret-...`)
are fixed literals, not secrets: nothing outside the in-memory process ever
validates a token signed with them.

---

## 5. Layout

```
backend/tests/integration/
  test.env                    NODE_ENV=test, committed, no secrets
  isolation.test.js           Suite 0: proves the harness is safe
  auth.test.js                Suite 1: registration, OTP, login, sessions
  authorization.test.js       Suite 2: cross-tenant access
  property-contract.test.js   Suite 3: field round-trip and mapping
  notifications.test.js       Suite 4: read endpoints, and no re-sent email
  upload-unavailable.test.js  Suite 5: edits while image storage is down
  upload-validation.test.js   Suite 6: magic bytes, storage configured
  setup/
    guard.js                  refuses unsafe NODE_ENV / database targets
    db.js                     in-memory replica set, truncation, teardown
    externals.js              credential neutralisation + egress blocking
    fakeProviders.js          loopback SMS, synthetic Cloudinary, email watch
    fixtures.js               synthetic image bytes for upload tests
    app.js                    Supertest against the real app; rate-limit isolation
    factories.js              synthetic users, properties, leads, notifications
```

### Why a replica set

`addProperty` opens a session and runs a transaction for the one-listing-per-owner
check, and MongoDB refuses transactions on a standalone. A standalone harness
would fail every property-creation test for a reason unrelated to the code under
test. `isolation.test.js` asserts transactions are available, so this cannot
regress silently.

### Why truncation rather than dropping the database

| Strategy | Cost | Problem |
|---|---|---|
| **truncate** (chosen) | 14–35 ms | none |
| `dropDatabase` | 50 ms+ | destroys indexes; Mongoose only rebuilds on model init, so later tests run without the constraint they mean to exercise |
| restart mongod | 2–5 s | correct but far too slow per test |

Indexes surviving is the point, not a side effect: two of them (the pending
verification partial-unique index, campaign membership) *are* the concurrency
guards under test.

### Rate-limit isolation

The auth limiter allows 5 requests per 15 minutes per IP, and every Supertest
request comes from `127.0.0.1`. A login suite would exhaust the budget after five
requests and the rest would fail with 429 for reasons unrelated to what they
assert. Worse, a test could appear to pass because a 429 is also "not 200".

Outside production the app sets `trust proxy = 1`, so `X-Forwarded-For` decides
`req.ip` and therefore the limiter key. Each request gets its own synthetic IP.
No application code was changed and nothing reaches into the limiter's private
store. Tests that mean to exercise rate limiting reuse one IP deliberately, and
one does, asserting a 429 arrives within 8 attempts and that a different IP is
unaffected.

### Password hashing in factories

Fixture users are hashed explicitly at cost 12, matching
`userController.js:276`. This is not an optimisation, the `User` model has **no
password-hashing pre-save hook**; every hash in the application is produced by a
controller. Assigning a plain string to `password` and saving stores it in clear,
which is how the first version of this factory produced users that could not log
in. Anything writing a password outside a controller has to hash it itself.

---

## 6. What the suites cover

**Suite 0 (isolation), 22 tests.** Section 3 and 4 above, all checked.

**Suite 1 (authentication), 31 tests.** Registration stores a bcrypt hash and an
unverified user; the OTP is delivered to the registered number, is not returned in
the response, and is not stored in recoverable form; the delivered OTP verifies,
a wrong one does not, an expired one does not, and an OTP issued for one account
cannot verify another. Login issues an HttpOnly session cookie, never returns the
password hash, refuses wrong passwords, unverified accounts and blocked accounts,
and gives an unknown email exactly the same answer as a wrong password so it
cannot be used to enumerate accounts. Logout invalidates the session
**server-side**, the original cookie is replayed afterwards, which is the check
that distinguishes a real invalidation from merely clearing the browser's copy.

**Suite 2 (authorization), 19 tests.** Two owners, two buyers, and the question
of whether one can reach the other's records: property read, update and delete;
lead listing, per-property leads and status changes; notification listing and
read-marking. Every anonymous path is checked too.

Assertions are about the **outcome**, not the status code. A cross-owner update
returning 403 or 404 are both fine; returning 200, or returning 403 while writing
anyway, is not. So each test asserts the response was a refusal *and* that the
stored document is unchanged. A test that only checked the status would pass
against a controller that rejects and mutates.

**Suite 3 (property field contract), 21 tests.** The highest-value suite. It
posts 55 whitelisted fields with collision-proof sentinel values, reads the stored
document, and asserts every one arrived, including `priceUnit`, whose loss made
the price filter read a monthly rent as lakhs. It checks mass assignment is
refused (`owner`, `isApproved`, `status`, `views`, `builder`, `_id`), that no name
appears in both the allowed and admin-only lists, and that undeclared fields and
prototype-pollution attempts are discarded. Update round-trips are covered
separately, including that an owner cannot approve their own disapproved listing.

Sentinels matter: an earlier version searched the stored document for small
integers and booleans and reported fields as persisted when the value it matched
belonged to something else entirely. Booleans and enum-constrained fields are
excluded from the generated sweep for the same reason and covered individually.

---

**Suite 4 (notifications), 17 tests.** The mark-all endpoint and the
single-notification endpoint, side by side, because the route reorder that fixed
one could have broken the other. Beyond access control it asserts that neither
path re-sends email: notifications email from a `post("save")` hook and marking
one read IS a save, so "mark read" and "send email" are one keystroke apart. The
first test in the file is a control that proves a creation DOES email, without
which every "sent no email" assertion below it would pass vacuously.

**Suite 5 (upload unavailable), 14 tests.** Runs in a process where Cloudinary
was never configured. Text-only edits succeed, in JSON and in multipart; a
request carrying a file is refused with 503 and nothing is half-applied.

**Suite 6 (upload validation), 10 tests.** The mirror, with storage configured,
so magic-byte and extension checks actually run. Assertions are on the reason for
rejection, not just its presence: a disguised file must be refused as
`INVALID_FILE`, never as `STORAGE_NOT_CONFIGURED`.

---

## 7. Do the tests actually catch anything?

Nine invariants were broken one at a time, the suite run, and the change
reverted. `git diff` confirmed each file was restored byte-identical every time.

Phase 3A, the original harness:

| Mutation | Result |
|---|---|
| Remove `'priceUnit'` from `PROPERTY_ALLOWED_FIELDS` | 5 failures across 3 independent tests |
| `findOne({_id, owner})` to `findOne({_id})` in `updateMyProperty` | caught |
| Delete the `isVerified` gate in `loginUser` | caught |

Phase 3A.1, one per fix plus the invariants they depend on:

| Mutation | Result |
|---|---|
| Restore the original route order in `notificationRoutes.js` | 8 failures |
| Remove the `$locals.wasNew` guard in the notification post-save hook | 2 failures |
| Break the `carpetArea` to `area.carpetSqft` mapping | 2 failures |
| Re-add `'waterSupply'` to the whitelist | 2 failures |
| Drop `'availableFrom'` from the whitelist | 2 failures |
| Move the Cloudinary check back above the "no files" return | 5 failures |
| Let a file through when storage is down (`if (false && ...)`) | 3 failures |
| Restore `data.hasOwnProperty(field)` | 5 failures |

The suite also caught a bug in its own construction before any of this: the first
factory stored passwords in clear text, and the login tests failed immediately
rather than silently testing nothing.

---

## 8. Findings, and what Phase 3A.1 did about them

Building the harness surfaced three defects, all since fixed in a Phase 3A.1
corrective pass. Investigating them turned up two more. Each entry records what
was wrong, what changed, and what now guards it.

### 8.1 `PATCH /api/notifications/mark-all/read` was unreachable (FIXED)

`routes/notificationRoutes.js` declared `PATCH "/:id/read"` one line before
`PATCH "/mark-all/read"`. Express matches in declaration order, so the wildcard
won and `markNotificationRead` received `id = "mark-all"`, failing the ObjectId
cast with a 500. Mark-all-as-read had never worked.

Fixed by declaring the literal path first. Both handlers were already correct.

Guarded by `notifications.test.js` (17 tests): the endpoint succeeds, marks every
unread notification the caller owns, is idempotent, never touches another user's,
and sends no email. Single-notification read is covered alongside it so the
reorder cannot regress it. Reverting the order fails 8 of them.

### 8.2 Twenty-two whitelisted property fields never persisted (RESOLVED)

The Phase 3A note recorded these as accepted-but-discarded. That was true of the
create path and wrong as a diagnosis: it tested one path and generalised, and it
mislabelled `availableFrom`, which had been persisting correctly all along and
only looked dropped because the check compared a `Date` to an ISO string.

The full matrix (form payload, whitelist, controller transformation, schema path,
stored value) put each name in one of three buckets:

| Bucket | Count | Fields | Action |
|---|---|---|---|
| Transient input, translated on update | 12 | `landmark` `expectedPrice` `expectedDeposit` `bhkType` `builtUpArea` `carpetArea` `superBuiltUpArea` `plotArea` `parkingCovered` `parkingOpen` `reraId` `propertyCategory` | none; now covered |
| Intended persisted field | 1 | `availableFrom` | moved to `MUST_PERSIST` |
| Obsolete | 9 | `floor` `age` `availability` `possessionDate` `waterSupply` `ownershipType` `buildingName` `buildingType` `seatCapacity` | removed from the whitelist |

The twelve are real. The edit form serialises its whole state flat
(`EditPropertyContent.jsx:636`), so it sends `carpetArea` where the schema wants
`area.carpetSqft`, and `updateMyProperty` translates. That mapping was invisible
from either side alone, which is why it read as a defect.

The nine were removed rather than wired up: no form sends them, they match no
schema path, and no property code reads them. Removing them changes no behaviour,
because an unlisted field is dropped exactly as silently as a listed one with no
mapping. What changes is that the list now describes what the API accepts.

Guarded by `property-contract.test.js`: each transient input is asserted to land
at its exact path, the removed names are asserted absent from the whitelist and
unstored on both paths, and `availableFrom` sits in the create round-trip.

### 8.3 An unconfigured image service blocked text-only edits (FIXED)

`validateAndUploadToCloudinary` returned 503 before checking whether the request
carried a file, so an image-service outage also stopped an owner correcting a
price or a description.

Fixed by moving the configuration check below the "no files" early return. A
file-carrying request still fails fast with 503, before magic-byte validation and
before any upload, because the one outcome that must never happen is accepting a
listing whose photos silently went nowhere.

Guarded by two suites, deliberately split across processes because `upload.js`
reads `CLOUDINARY_URL` once at import: `upload-unavailable.test.js` (14 tests, no
storage) and `upload-validation.test.js` (10 tests, storage configured). The
second exists to prove the relaxation cost nothing: a disguised file is still
refused as `INVALID_FILE`, not as `STORAGE_NOT_CONFIGURED`.

### 8.4 Property editing returned 500 for every multipart request (FIXED)

Found while testing 8.3, and the more serious of the two. Multer 2 builds
`req.body` with `Object.create(null)` (`lib/make-middleware.js:29`), and
`sanitizePropertyData` called `data.hasOwnProperty(field)`, which throws on a
prototype-less object.

The edit form posts multipart and sends no `features` key, so `data` was never
rebuilt by the spread at `propertyController.js:1499` and reached the sanitizer
without a prototype. **Every save from the edit screen returned 500.** Creation
escaped only because the add form does send `features`, and that spread happens
to produce an ordinary object.

Fixed with `Object.prototype.hasOwnProperty.call(data, field)`, which is also the
correct form for a security filter: it keeps working if a request supplies its own
`hasOwnProperty` field. The old 503 had been masking it whenever storage was
unconfigured, which is why 8.3 had to be fixed before this became visible.

### 8.5 Two issues left open

**A failed Cloudinary upload leaks an unhandled rejection.**
`cloudinary.uploader.upload_stream` returns a Q promise the SDK never settles on
the failure path (`uploader.js:595-607`), so any upload failure produces an
unhandled rejection beside the correctly handled callback. Noisy rather than
fatal: `errorHandler.js:471` logs and reports without exiting, and the HTTP
response is still a correct `500 UPLOAD_FAILED` with no image recorded. It is
also why that path cannot be asserted from `node:test`; see the note in
`upload-validation.test.js`.

**Five models cannot build their indexes.** `models/Role.js` declares `name` as
`unique: true` and then adds `roleSchema.index({ name: 1 })` at line 57, so two
specs compete for the auto-generated name `name_1`. `Admin`, `User`,
`UserSession` and `AdminSession` have the same shape. The harness reports them at
boot and continues; in production the index that loses is simply not created.

---

## 9. Scope

**Phase 3A (harness):** `server.js` (3 guarded seams),
`services/hubbleService.js` (one `unref()`), `package.json` (test scripts),
`.gitignore` and `backend/.gitignore` so the suite is committable, plus the new
files under `backend/tests/integration/`.

**Phase 3A.1 (corrective pass):** four application changes, all small:

| File | Change |
|---|---|
| `routes/notificationRoutes.js` | literal route declared before the wildcard |
| `middleware/upload.js` | configuration check moved below the "no files" return |
| `controllers/propertyController.js` | `Object.prototype.hasOwnProperty.call`; nine dead names removed from the whitelist |

**Not changed:** no schema, no model, no migration, no business rule, no
production infrastructure. The two open issues in §8.5 are reported, not fixed.

**Not present:** no `.env` file, credential, API key, database dump, production
identifier or real customer data entered the repository. The committed non-source
files are `test.env` (one line, `NODE_ENV=test`), the synthetic image fixtures in
`setup/fixtures.js`, and this document.
