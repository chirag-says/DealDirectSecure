# DealDirect: Development Database Separation Plan

Phase 3B.0 follow-up. **Plan only. Nothing here has been executed.** No database
was contacted while writing it, no data was copied, no environment file was
modified, and no migration was run.

No production URI, hostname, username, password or connection string appears
below. Placeholders are written as `<dev-cluster-host>`.

---

## 1. The problem

Confirmed externally: Hostinger's backend `MONGO_URI` points at the same MongoDB
environment this repository is configured to use. **One database serves both
development and production.**

What that means in practice:

- Every taxonomy migration rehearsal would write to live customer data.
- Every schema experiment, rollback test and destructive trial would run against
  production.
- The four scripts in `backend/scripts/` all read the single `MONGO_URI`, so any
  of them, run casually, hits production.
- `server.js` falls back to `.env.production` when `.env` is absent, so even
  deleting the local config reconnects to the same place rather than failing.
- The integration harness is the only safe writable database in the project, and
  it is in-memory and ephemeral.

Phase 3B cannot proceed until this is fixed. The taxonomy migration is designed
to be additive and reversible, but "reversible" is a property of the script, not
a substitute for an environment you are allowed to break.

---

## 2. Target architecture

```
Atlas project: DealDirect Production          Atlas project: DealDirect Development
  cluster: production                           cluster: development (M0)
  database: Deal-Direct                         database: dealdirect_dev
  user: prod-app  (readWrite, prod only)        user: dev-app  (readWrite, dev only)
  IP allowlist: Hostinger egress only           IP allowlist: developer machines only
        |                                                 |
        | mongodump, read-only, one direction             |
        +---------------> anonymise ----------------------+
                                                          |
                                              backend/.env  ->  dev only
                                                          |
                                              local DealDirect repository

  backend/.env.production  ->  placeholder template, no live values, never read at runtime
  integration harness      ->  in-memory replica set, unreachable from either
```

Three environments, three databases, three sets of credentials, and no path by
which a developer machine can reach production.

---

## 3. Atlas setup

### 3.1 Separate cluster, not a separate database on the same cluster

**Recommendation: a separate cluster in a separate Atlas project.**

| Option | Isolation it actually gives | Verdict |
|---|---|---|
| Separate **database** on the existing cluster | Naming only. Same cluster users, same IP allowlist, same connection string minus one path segment. A database user with `readWrite` on the cluster reaches both, and a mistyped or omitted database segment lands in production | **Rejected** |
| Separate **cluster**, same project | Distinct connection string and distinct cluster, but project-level users and allowlists can still span both | Acceptable, not preferred |
| Separate **cluster in a separate project** | Distinct credentials, distinct network allowlist, distinct connection string. A mistake fails to connect rather than succeeding against the wrong data | **Recommended** |

The control that matters is credentials and network reachability, not the
database name. A separate database on the same cluster leaves the failure mode
intact: one wrong string and the write lands on production, silently and
successfully. A separate project makes the same mistake produce an
authentication or network error, which is the outcome you want.

### 3.2 Recommended configuration

| Setting | Value | Why |
|---|---|---|
| Project | new, e.g. `DealDirect Development` | Separate users and allowlists |
| Tier | **M0 free** | 512MB is ample for a 47-property corpus |
| Topology | 3-node replica set (M0 default) | **Required.** `addProperty` opens a transaction, which MongoDB refuses on a standalone. This is the one Atlas property that is not optional |
| Database name | `dealdirect_dev` | Visibly different from the production name, so a wrong target is obvious in any log |
| Database user | `dev-app`, `readWrite` on `dealdirect_dev` only | Not `atlasAdmin`, not cluster-wide |
| IP allowlist | developer machines only | Must **not** include Hostinger egress |
| Backups | none needed on M0 | The dev database is disposable by design; it is rebuilt from the export |

### 3.3 Production-side hardening, same sitting

Two changes on the production project, neither touching data:

1. **Remove developer machine IPs from the production cluster's IP allowlist.**
   This is the single strongest control in this plan. If a developer machine
   cannot reach the production cluster at the network layer, no configuration
   mistake, stale file or mistyped script can reach it either.
2. **Confirm the production database user is scoped to the production database**
   and is not reused anywhere else.

Do these *after* the dev database is working, so nobody is locked out mid-task.

---

## 4. Data-copy strategy

One direction only: production to development, read-only at the source.
`mongodump` reads; it never writes to the source. Nothing in this plan modifies
production data.

### 4.1 What to copy

Chosen to make the taxonomy migration rehearsal realistic and nothing more. The
cheapest anonymisation is not copying.

| Collection | Copy | Why |
|---|---|---|
| `propertytypes` (3) | **Full** | The migration subject |
| `categories` (19) | **Full** | The migration subject, including the intents and the case duplicate |
| `subcategories` (48) | **Full** | Needed to rehearse D9 retirement |
| `properties` (47) | **Full** | The migration corpus. Both ref states must survive: 25 stale, 22 null |
| `users` | **Anonymised** | Properties reference owners; the owner feed is unusable without them |
| `leads` | **Anonymised** | Exercises the owner feed and the `userSnapshot` PII path |
| `builders`, `projects`, `unittypes` | **Anonymised** | The one builder-feed property needs its chain |
| `roles`, `permissions` | **Full** | Configuration, no PII |

### 4.2 What to exclude entirely

| Collection | Reason |
|---|---|
| `usersessions`, `adminsessions`, `passwordresettokens` | Live session and reset tokens. Never copy |
| `admins` | Contains TOTP secrets. Create fresh dev admins instead |
| `agreements` | Signed documents: HMAC signatures, content hashes, party PII, IP addresses |
| `projectbookings`, `transactionverifications` | Payment UTR numbers and screenshot URLs |
| `rewards`, `referrals` | Real balances; a dev environment must not imply anyone is owed anything |
| `messages`, `conversations` | Private chat content |
| `notifications` | Contain message bodies and action URLs carrying recipient emails |
| `auditlogs`, `logintrackers` | IP addresses and behavioural history |
| `contactinquiries`, `reports`, `savedsearches` | PII with no bearing on taxonomy |
| `blogs`, `groupbuycampaigns`, `campaignmembers` | Not needed; campaign members carry PII |

Excluding a collection is safe for this work: nothing in the taxonomy migration
reads any of them. If a later phase needs one, it can be added to the copy with
its own anonymisation rule.

### 4.3 Mechanism

```
mongodump   --uri <production>  --collection <each included collection>  --out ./dump
   |
   v
anonymise offline, on the dump files, before any restore
   |
   v
mongorestore --uri <development> --nsFrom 'Deal-Direct.*' --nsTo 'dealdirect_dev.*'
```

Three rules:

1. **Anonymise between dump and restore, never after.** Restoring raw data with
   the intention of scrubbing it later means real PII exists in the dev database,
   however briefly, and a failed scrub leaves it there.
2. **Never point `mongorestore` at production.** It takes a `--uri` like any
   other tool and will happily write wherever it is aimed.
3. Delete the intermediate dump when the restore is verified. It is a plaintext
   copy of production.

---

## 5. Anonymisation strategy

Applied to the four collections copied with data. Values follow the conventions
the integration harness already uses, so dev data and test fixtures look alike.

### `users`

| Field | Treatment |
|---|---|
| `name` | Replace: `Dev User <n>` |
| `email` | Replace: `dev-user-<n>@example.com`, RFC 2606, undeliverable |
| `phone` | Replace: `99999<5 digits>` |
| `password` | Replace **all** with one known bcrypt hash so any dev user can be logged into |
| `otp`, `otpExpires`, `resetPasswordOtp`, `resetPasswordOtpExpires` | Drop |
| `security.*` (`failedLoginAttempts`, `lockoutUntil`, `lastLoginIp`, `passwordChangedAt`) | Drop |
| `address` | Drop |
| `referralCode` | Regenerate; it is unique-indexed |
| `_id`, `role`, `isVerified`, `isBlocked` | **Preserve.** Referenced by properties and drive feed behaviour |

### `leads`

| Field | Treatment |
|---|---|
| `userSnapshot.name` / `.email` / `.phone` | Replace, matching the anonymised user |
| `property`, `propertyOwner`, `user`, `status`, `source` | Preserve |
| `contactHistory[].notes` | Drop; free text written by owners about real buyers |

### `builders`, `projects`

| Field | Treatment |
|---|---|
| `name` | Replace: `Dev Builder <n>` / `Dev Project <n>` |
| `email`, `phone`, `address` | Replace or drop |
| `_id` and all refs | Preserve |

### Properties: what must NOT be anonymised

`properties` is copied verbatim. Its `title`, `description`, `city`, `locality`
and `address` are public listing content, already visible to anyone browsing the
site, and the migration's correctness depends on the exact values of
`categoryName` and `propertyTypeName`. Changing them would invalidate the
rehearsal.

`address.latitude` / `longitude` are property locations, not personal
addresses, and are likewise public.

### Verification after anonymisation, before restore

Assert on the dump, not on trust:

- Zero email addresses outside `@example.com`
- Zero phone numbers outside the `99999` fixture range
- Zero bcrypt hashes other than the single known dev hash
- Zero non-empty `otp`, `resetPasswordOtp`, `lastLoginIp`, `ipAddress` fields
- Collection counts match the intended include list exactly, with no extras

---

## 6. Environment configuration

### `backend/.env` (developer machines)

```
NODE_ENV=development          # add: currently absent, so environment is inferred from silence
MONGO_URI=<dev cluster, dealdirect_dev, dev-app credentials>
```

Every other key keeps its current shape. External services should stay
unconfigured or point at sandboxes: the existing "not configured, skip" branches
mean a dev environment sends no email, no SMS and no WhatsApp by default, which
is the correct posture.

### `backend/.env.production` (isolation)

**Reduce to a placeholder template with no live values.**

Now that hPanel is confirmed to supply the backend's runtime variables, this file
has no runtime role. Keeping live credentials in it creates a specific hazard:
`server.js:34-43` falls back to `.env.production` whenever `.env` is missing. So
a developer who renames, deletes or mistypes `.env` gets silently connected to
production instead of an error. After separation that becomes the main way the
isolation could regress.

Two options:

| Option | Effect |
|---|---|
| **Placeholder values** (recommended) | The fallback still fires but connects nowhere; the app fails fast with a clear error |
| Delete the file | Fallback cannot fire at all, but the documented deploy procedure references it |

Either way, **live production credentials should not sit in the working tree**.
The file is gitignored, which prevents committing them, not reading them.

### `backend/tests/integration/test.env`

Unchanged. It contains one line, `NODE_ENV=test`, and no database configuration.

---

## 7. Safety guards

Layered, strongest first. The first two are guarantees; the rest are defence in
depth.

| # | Guard | Layer | What it stops |
|---|---|---|---|
| 1 | Developer IPs removed from the production cluster allowlist | Network | Everything. A mistake cannot connect |
| 2 | Production credentials never present on a developer machine | Credentials | Everything, independently of code |
| 3 | `.env.production` holds no live values | Configuration | The `server.js` fallback reaching production |
| 4 | Startup assertion: refuse to boot when `NODE_ENV !== 'production'` and the resolved database name is the production one | Code | A pasted URI, a stale file |
| 5 | `config/db.js` logs the resolved **database name** at startup | Observability | Silent wrong-target connections; makes the target visible without exposing the URI |
| 6 | Existing harness guard | Tests | Already in place, see below |

Guards 4 and 5 are the only code changes this plan proposes, and both are
deferred to implementation. Neither is a substitute for 1 and 2: code guards live
in the same repository as the mistake they are guarding against.

### Integration tests need no change

`tests/integration/setup/guard.js` is allow-list shaped: it accepts only a
loopback host with a database name containing `test`, and rejects
`mongodb+srv://` outright. A new Atlas cluster is rejected by exactly the same
rule that rejects the current one, so introducing the dev database changes
nothing about test isolation. This is what the allow-list design was for, and the
isolation suite already asserts it.

---

## 8. Verification checklist

**Before any copy**

- [ ] Dev Atlas project created, distinct from production
- [ ] Dev cluster is a replica set (M0 default); confirm transactions are available
- [ ] `dev-app` user scoped to `dealdirect_dev` only
- [ ] Dev cluster allowlist contains developer machines; production allowlist does not

**After the copy**

- [ ] Collection list matches the include table exactly; no excluded collection present
- [ ] `properties` count matches production (47 at last reading)
- [ ] Ref state preserved: 25 properties with stale refs, 22 with null refs
- [ ] `categories` = 19, `propertytypes` = 3, `subcategories` = 48
- [ ] Anonymisation assertions from §5 all pass
- [ ] The intermediate dump has been deleted

**Environment**

- [ ] `.env` points at `dealdirect_dev` and sets `NODE_ENV=development`
- [ ] `.env.production` contains no live credentials
- [ ] Backend boots and logs the **dev** database name
- [ ] A write in dev is visible in dev and **absent from production** (check via the Atlas UI, not by connecting to production from the repository)

**Tests**

- [ ] `npm test` 471 pass
- [ ] `npm run test:integration` 164 pass, including the isolation suite
- [ ] The harness still refuses the dev URI, proving tests are isolated from both environments

**Negative checks, the ones that matter**

- [ ] With `.env` renamed, the backend fails to start rather than connecting to production
- [ ] With production credentials pasted in, the connection is refused at the network layer

---

## 9. Rollback plan

**Production rollback is a no-op.** Every operation in this plan reads from
production and writes only to the new dev cluster. There is nothing to undo on
the production side, which is the main reason to do the separation this way
around.

| Situation | Rollback |
|---|---|
| The copy is wrong, incomplete, or anonymisation failed | Drop `dealdirect_dev` and re-run. The dev database is disposable by design; this is not an incident |
| The dev cluster is unusable | Restore the previous `backend/.env` from a local backup taken before editing. Keep that copy outside the repository until the separation is verified |
| A developer is locked out of production unexpectedly | Re-add the specific IP to the production allowlist deliberately, with a note on why. Do not widen the allowlist as a reflex |
| The whole separation needs reverting | Point `.env` back and delete the dev project. No production state changed at any point |

One instruction that is part of the rollback plan rather than a footnote: **take a
copy of the current `backend/.env` before editing it**, store it outside the
repository, and delete it once the dev environment is confirmed. It is currently
the only record of the working configuration.

---

## 10. Sequence

1. Create the dev Atlas project, cluster, user and allowlist.
2. Back up the current `backend/.env` outside the repository.
3. Dump the included collections from production, read-only.
4. Anonymise the dump offline; run the §5 assertions against it.
5. Restore into `dealdirect_dev`.
6. Verify per §8.
7. Repoint `backend/.env`; reduce `.env.production` to placeholders.
8. Re-run both test suites.
9. Remove developer IPs from the production allowlist.
10. Delete the intermediate dump.
11. Only then resume Phase 3B and rehearse the taxonomy migration against
    `dealdirect_dev`.

Steps 1 to 10 involve no schema change, no taxonomy change and no write to
production.

---

## 11. Confirmation

- **Nothing in this plan has been executed**
- Database writes: **0**
- Data copied: **0**
- Taxonomy or property records modified: **0**
- Schema changes: **0**
- Environment files modified: **0**
- No database was contacted while preparing this document
- No production URI, hostname, username, password or connection string recorded
- No secrets are proposed for copying into the development environment: the dev
  database gets its own credentials, and external service keys stay unset
