# Deletion Policy and Admin RBAC — Decision Analysis

Phase 3C. **Analysis only. No application behaviour was changed, no migration
run, production untouched.**

Built by reading the source at `129e2a9`. Two audit claims did not survive the
re-check and are corrected below.

**Revision 2026-08-18.** Part 2 (RBAC) was rewritten after querying production.
The original version reasoned from the repository alone and reached the opposite
conclusion; §2.6 records the error. Part 1 and Part 3 are unchanged.

---

## Part 1 — Deleted-user PII

### 1.1 The starting point is not a blank sheet

`deleteAccount` in `controllers/userController.js:1245` already implements an
explicit hard-delete cascade across twelve collections, gated behind a
re-authentication check, with the unresolved collections listed in a comment and
a response message written to match what actually happens.

So the question is not "what should the policy be". It is **"should the six
deliberately-retained collections stay retained as-is, and is retaining them
with full PII intact the right call"** — because today they keep the deleted
user's name, email and phone in snapshot fields.

### 1.2 Inventory

Every collection carrying a `ref: "User"`, traced from the model files.

**Group A — hard-deleted today**

| Collection | User ref | Purpose | PII | Financial/legal | Counterparty | Audit | Verdict |
|---|---|---|---|---|---|---|---|
| `Property` | `owner` | listings | indirect | no | no | no | delete (+ Cloudinary assets) — correct |
| `UserSession` | `user` | live sessions | no | no | no | no | delete — correct, security-critical |
| `PasswordResetToken` | `user` | reset flow | no | no | no | no | delete — correct |
| `LoginTracker` | `userId` | login history | IP | no | no | weak | delete — defensible |
| `ContactInquiry` | `user` | enquiry form | yes | no | weak | no | delete — correct |
| `SavedSearch` | `user` | saved filters | no | no | no | no | delete — correct |
| `Report` | `reportedBy` | abuse reports | yes | no | **yes** | **yes** | **questionable, see 1.4** |
| `Notification` | `user` | in-app notices | some | no | no | no | delete — correct |
| `Message` | `sender` | chat | yes | no | **yes** | no | **questionable, see 1.4** |
| `Conversation` | `participants` | chat threads | no | no | yes | no | `$pull` then delete-if-empty — correct |
| `Reward` | `user` | points wallet | no | **yes** | no | **yes** | **questionable, see 1.4** |
| `Referral` | `referrer`, `referred` | referral credit | no | **yes** | **yes** | yes | **questionable, see 1.4** |

**Group B — deliberately retained, PII intact**

| Collection | User ref | PII held | Financial/legal | Counterparty | Audit | Current behaviour |
|---|---|---|---|---|---|---|
| `Lead` | `user`, `propertyOwner` | `userSnapshot.{name,email,phone}` | no | **yes** — the owner's lead list | yes | retained whole |
| `Agreement` | 4 refs | `ownerSnapshot`, `buyerSnapshot` (name/email/phone) | **yes** — HMAC-signed | **yes** | **yes** | retained whole |
| `TransactionVerification` | 2 refs | Cloudinary proof documents | **yes** — deal proof | **yes** | **yes** | retained whole |
| `CampaignMember` | `user` | `userSnapshot.{name,email,phone}` | **yes** — `tokenStatus: paid`, `paymentReference`, `paymentProofUrl` | **yes** | **yes** | retained whole |
| `ProjectBooking` | `client` | `clientName`, `clientPhone`, `clientEmail` (required fields, not a snapshot) | **yes** — UTR number, payment screenshot | **yes** | **yes** | retained whole |

`RedemptionRequest` is named in the code comment but **is not a model**. Redemption
lives inside `Reward.transactions[].metadata` as `Mixed`. The comment is stale;
worth correcting whichever way the decision goes.

### 1.3 The orphan the current policy creates

`Property.deleteMany({ owner: userId })` runs, but `Lead` is retained. A `Lead`
references both the buyer and `property`. So closing a buyer's account leaves the
owner holding leads that point at listings which still exist, while closing an
**owner's** account leaves retained leads pointing at deleted properties.

This is not hypothetical. Phase 3B.2 found **2 production properties referencing
deleted users** and 6 with neither owner nor builder.

### 1.4 Where the current split looks wrong

Four Group A deletions destroy things the Group B rationale says to keep:

- **`Reward`** is a points ledger with a transaction array. Deleting it erases
  the accounting for points that were awarded, spent, and reversed. If any of
  that touched money or a fulfilled redemption, this is the one deletion most
  likely to be regretted.
- **`Referral`** is deleted for both sides at once, so the *other* user's
  referral credit disappears with it. That is a counterparty record by the
  document's own definition.
- **`Report`** is an abuse report. Deleting it lets a reported party erase the
  complaint by closing their account — and deleting `reportedBy` reports removes
  the reporter's, not the reported party's.
- **`Message`** deletes one side of a conversation, leaving the other participant
  with a thread full of gaps rather than a clean record.

None of these is an engineering judgement I can settle. They are the decision.

### 1.5 The three options

**Option A — hard delete.** Extend the existing cascade to the six retained
collections. Cleanest data-protection story, and simplest to reason about.
Destroys signed agreements, payment evidence and the counterparty's records.
For `Agreement` this is close to unusable: it is HMAC-signed precisely so it can
be shown to be unaltered later, and half of it belongs to someone else.

**Option B — anonymise.** Keep the document and its relationships, null the ref,
strip the snapshot to a tombstone (`"Deleted user"`). Every Group B collection
already has a snapshot field designed for exactly this, which is the strongest
signal in the data model about original intent. `ProjectBooking` is the
exception: its client fields are `required`, so anonymising means writing
placeholders that satisfy a regex, not clearing them.

**Option C — retain.** Status quo. Legally safest for financial and signed
records, and the weakest position under a deletion request, because the person's
name, email and phone stay in five collections indefinitely with no defined
retention period.

### 1.6 Recommendation

> **This is a product and legal decision, not an engineering fact.** What follows
> is what the data model appears designed for. It is not legal advice and should
> be confirmed against the obligations DealDirect actually operates under.

**Recommended: B for counterparty records, C with a retention clock for
financial and signed records, and move two Group A items out of hard delete.**

| Collection | Recommended | Why |
|---|---|---|
| `Lead` | **B** anonymise | The owner's record. Snapshot field exists for this |
| `CampaignMember` | **B** anonymise, keep payment fields | Campaign counts must stay correct; the payment reference is evidence |
| `Agreement` | **C** retain | HMAC-signed, two-party, its whole purpose is later provability |
| `TransactionVerification` | **C** retain | Deal proof; also gates reward claims |
| `ProjectBooking` | **C** retain | UTR + payment screenshot; `required` fields resist anonymising |
| `Reward` | **move to C or B** | Currently hard-deleted. A financial ledger should not vanish on account closure |
| `Referral` | **move to B** | Currently deletes the counterparty's credit too |
| `Report` | **move to C** | Currently lets a closing account erase abuse history |
| `Message` | keep A, or B | Judgement call; A is defensible if chat is disposable |

The rest of Group A stays as-is.

**Why not blanket A:** it destroys the other party's records, and three
collections hold payment evidence with no gateway behind them — the UTR number
and the uploaded screenshot *are* the receipt.

**Why not blanket C:** it keeps name, email and phone forever in five
collections, which is the weakest possible answer to a deletion request.

**Retention period is unset and must be decided.** "Retain" without a clock is
"keep forever", which is a different policy than the one anyone intends.

---

## Part 2 — Admin RBAC

> **Rewritten 2026-08-18 after querying production.** The first version of this
> section reasoned from the repository alone and got the conclusion backwards. It
> is corrected in full below; §2.6 records what was wrong and why, because the
> mistake is repeatable.

### 2.1 Product role vs internal representation

These are not the same thing and conflating them is what produced the first
error.

| Layer | Reality |
|---|---|
| **Product** | One role: **Admin**. A DealDirect admin has full administrative powers. There is no product concept of a super admin, a manager, or a viewer |
| **Database** | Four `Role` documents exist: `super_admin`, `admin`, `manager`, `viewer`, with levels 100/80/50/10 |
| **In use** | **All admins hold `super_admin`. The other three are held by nobody** |

The four-tier hierarchy is seeded scaffolding, not a product model. It is
described below as data, and no product meaning is inferred from the names.

### 2.2 Three parallel mechanisms

| Mechanism | Routes | Depends on | Works in production? |
|---|---|---|---|
| `protectAdmin` | 93 | session + `Admin.isActive` | yes |
| `requireSuperAdmin` | 1 | `Admin.role.level >= 100` | yes |
| `requirePermission` | 8 | `Role.permissions[] → Permission.code` | yes — but see §2.4 |

`requireRoleLevel` is exported and parameterised, but the only live use is
`requireSuperAdmin` on `GET /admin/audit-logs`. A second import is commented
"REMOVED: No longer needed (admin registration removed)".

### 2.3 Verified production state

Read-only queries, 2026-08-18.

**Q1 — what role value does each Admin user hold?**

```
3 admin accounts, all with an ObjectId role resolving to `super_admin`
  admin[0]  super_admin   isActive = false
  admin[1]  super_admin   isActive = true
  admin[2]  super_admin   isActive = false
```

Only **one admin account is active**. Zero legacy string roles.

**Q2 — what does `Role.level` mean in the implementation?**

It is a single integer used in exactly three places:

| Consumer | Effect |
|---|---|
| `requireRoleLevel(min)` / `requireSuperAdmin` | gates `GET /admin/audit-logs` at level 100 |
| `adminController.js:109` | a creator cannot create an admin at `level >= own level` |
| `adminController.js:682` | a check for `level < 100` |
| `adminController.js:329/353/534` | echoed to the client as `roleLevel`, display only |

It is **not** a permission source. `getPermissions()` never reads it. So "level"
means "rank for three specific checks", nothing more.

**Q3 — which role owns 45/30/15/5?**

```
super_admin  level=100  permissions=45  isSystem=true   admins using it = 3
admin        level=80   permissions=30  isSystem=true   admins using it = 0
manager      level=50   permissions=15  isSystem=true   admins using it = 0
viewer       level=10   permissions=5   isSystem=true   admins using it = 0
```

**Q4 — is `super_admin` an actual product role?**

No. It is the internal name of the only Role document any admin actually holds.
In product terms it *is* "Admin". `admin`, `manager` and `viewer` are seeded
definitions used by **zero** accounts — scaffolding that has never been adopted.

**Q5 — do all current Admin users effectively have full permissions?**

**Yes, completely.**

```
total Permission documents in the database        = 45
permissions granted to every current admin        = 45
full coverage                                     = YES
```

Every admin holds every permission that exists.

### 2.4 What this means for the 8 guarded routes

Since every admin holds all 45 permissions, **`requirePermission` currently
passes for every admin on every one of the 8 routes**. It is not access control
in practice; it is a lookup that always succeeds.

That has two consequences, and the second is the one that matters:

1. **No route is protected by it today.** Removing it would change no admin's
   effective access. Adding a 9th guarded route would also change nothing.
2. **It is a latent outage mechanism.** The check only ever *fails*, and it fails
   closed and site-wide. That is precisely what happened in `79ae3ab`: the codes
   `verifications:read` / `verifications:approve` were required, and re-verified
   today they **do not exist** in production — `verifications` is not among the
   12 resources present. Every admin got 403, the Deal Verifications page
   rendered "No pending verifications found", deal closures piled up unapproved,
   and no user could claim a deal reward. The shipped fix was to remove the
   guards.

So the layer's only observable effects to date are zero access control and one
production outage.

### 2.5 Options and recommendation

> A product decision. The engineering input is the data in §2.3.

**A. Complete it.** Add the missing resources to the enum, seed the new codes,
and split the single Admin role into real tiers. **This requires a product
decision that does not exist yet:** there is only one kind of admin today, and
all three accounts are identical. Building tiers before anyone needs tiers is
how the current scaffolding got here.

**B. Retire the permission layer**, keeping `protectAdmin` and `requireSuperAdmin`.
Removes 8 no-op checks and the outage mechanism with them. Effective access for
every current admin is unchanged, because they already hold everything.

**C. Leave it.** Zero effort, keeps the latent outage.

**Recommended: B**, on different evidence than the first version of this
document gave.

The original argument was "it cannot work because it was never seeded". That was
wrong — it is seeded and it works. The correct argument is stronger:

- It provides **no access control today**, verified: all admins, all permissions.
- Its resource enum cannot describe builders, projects, unit types, campaigns,
  bookings, verifications or agreements, so it could not cover the newer surface
  even if tiers were wanted.
- Its one production effect was a site-wide 403.
- The product has one admin role, so per-resource permissions model a
  distinction that does not exist.

**Reconsider if** a second class of admin is actually planned — an outsourced
moderation team, say. Then A becomes worth its cost, and the 45 seeded
permissions are a genuine head start rather than dead weight. That is a product
question, not an engineering one.

**Do not delete the `permissions` and `roles` collections as part of B.** See
§2.6: how they were populated is unknown, so they may not be reproducible.

### 2.5a RESOLVED — option B implemented, 2026-08-18 (Phase 3F)

Product assumption verified against the repository before any change. **No
near-term requirement for multiple admin classes exists.** Searched: admin
pages (no role or permission management screen), the Admin frontend (nothing
consumes `context.permissions`; `Sidebar` reads `roleName`/`roleLevel` only to
print a badge), feature flags (none), and the docs.

The only thing resembling a requirement is `adminfixes.md`, which lists
"Role-based UI gating: Missing (all admins see all menus)" and imagines "a
junior admin". That is an inference from the unused scaffolding, not a product
need — exactly the reasoning this decision was told not to accept.

**What was removed:** `requirePermission` from its five routes and from
`middleware/authAdmin.js` entirely, plus `hasPermission`, `hasAnyPermission`
and `hasAllPermissions` on the Admin model, all three of which had zero callers.

Deleted rather than left unused: a middleware that exists is one somebody
reattaches, and reattaching it with a code outside the closed enum is precisely
the `79ae3ab` outage.

**What was kept:** `protectAdmin` on every admin route. `requireSuperAdmin` on
the audit log. `getPermissions()`, which is the only code that knows how a role
resolves to codes and which the cleanup migration will need. The `Role` and
`Permission` models. **The production collections — 45 permissions, four roles —
are untouched**, and stay that way until the separate cleanup migration, which
should follow only after this code change has been stable.

`scripts/seedRbac.js` stays deleted. It is recoverable at `68ebab2` and §2.7
records how; there is no reason to reintroduce a seeding dependency for a layer
the code no longer uses.

**Correction to §2.2:** the count is **five** routes, not eight. Eight was a
grep total that included the import line and two comment lines.

### 2.5b A second guard was found broken shut

Implementing the above surfaced that `requireSuperAdmin` **denied everyone**,
including the three production accounts that genuinely are level 100.

`Admin.role` is declared `Mixed`, because it must hold either a legacy string or
an ObjectId. Mongoose cannot infer a populate target from a Mixed path, so the
`.populate('role')` in `protectAdmin` silently did nothing: `req.admin.role`
stayed an ObjectId, `role.level` was `undefined`, and `requireRoleLevel` read
`|| 0` for every admin alive. The audit log was unreachable by anybody.

Same failure class as the permission layer — a guard that only ever says no —
and it had been invisible for the same reason: nothing tested it.

Fixed by naming the model explicitly in the populate. **This opens a route that
was closed to everyone**, which is a real behaviour change: all three production
admins are level 100, so after deployment they gain access to the audit log.
That is the intended design, the data is read-only, and the alternative is
keeping a security control that silently does nothing. Flagged here rather than
buried because it is the one part of this change that widens access.

### 2.6 What the first analysis got wrong, and the open risk

The first version of this section concluded the permission layer was
"deterministically unusable — all 8 guarded routes unreachable by every admin".

That was reasoned entirely from the repository: no file creates a `Permission`
document, and no file writes to `Role.permissions`. Both statements are still
true. The conclusion did not follow, because production was configured by
something outside this repository.

**The open risk that replaces it.** 45 permissions and four populated roles exist
in production, and nothing in version control can recreate them. Consequences:

- A restore from backup, or a new environment, comes up with **no permissions**,
  and then the 8 guarded routes fail closed for everyone — the `79ae3ab` outage,
  reproduced by disaster recovery.
- `dealdirect_dev` does not have this configuration, so dev and production
  disagree about whether those 8 routes work.
- Nobody can review the permission model, because it is not in the repository.

This is worth recording regardless of which option is chosen. Under A it must be
fixed first. Under B it disappears along with the layer.

### 2.7 Resolved: where the 45 permissions came from

Investigated 2026-08-18. **They were not configured by hand.**
`backend/scripts/seedRbac.js` existed, was committed, and was **deleted from the
repository** in commit `f9420d1` ("production"). It is recoverable in full at
`68ebab2` — 313 lines.

The match is exact, which is what makes this conclusive rather than likely:

| | Script defines | Production has |
|---|---|---|
| permission documents | 45 | 45 |
| resources covered | the same 12 | the same 12 |
| `super_admin` | `"*"` → all 45 | 45 |
| `admin` | 30 codes | 30 |
| `manager` | 15 codes | 15 |
| `viewer` | 5 codes | 5 |

It also explains the `79ae3ab` outage exactly: the script defines **no**
`verifications` permission, so `verifications:read` and `verifications:approve`
never existed to be granted.

Recover it with:

```bash
git show 68ebab2:backend/scripts/seedRbac.js > backend/scripts/seedRbac.js
```

**Verdicts:**

```
reproducible from repository (as it stands)  = NO
reproducible from git history               = YES, exactly
reproducible from external documented process = NO — no runbook, no ops doc
likely manual production configuration      = NO
```

**What this changes.** The disaster-recovery risk in §2.6 is smaller than
stated: a restore can be repaired by recovering one file from git and running
it. It is not gone, though, because nothing in the current repository, its
documentation or its deployment process says that file exists or that it must be
run. Someone rebuilding the environment would find an empty `permissions`
collection and no indication why the admin panel 403s.

**It does not change the recommendation.** §2.5 rests on the layer granting every
admin every permission and therefore protecting nothing, which is unaffected by
where the seed came from. If option A is ever chosen, this script is the
starting point rather than a blank page. If option B is chosen, restoring the
file first is still worth doing so the deletion is a reviewable diff against
something.

---

## Part 3 — Cascade design (no code)

### 3.1 Two audit claims corrected

**"Zero cascade hooks across 31 models" — true but misleading.** There are no
Mongoose delete hooks. There *is* an explicit twelve-collection cascade in
`deleteAccount`, which is the shape the roadmap recommends. The pattern already
exists in this codebase.

**"Deleting a Builder strands Project → UnitType → GroupBuyCampaign →
CampaignMember" — not correct as written.** Verified:

| Operation | Behaviour | Guard |
|---|---|---|
| delete Builder | **soft** — `isActive = false` | refuses if active approved properties exist |
| delete Project | hard | refuses if `UnitType.countDocuments > 0` |
| delete UnitType | hard | refuses if `unitType.activeCampaignCount > 0` |
| delete GroupBuyCampaign | **no endpoint exists** | n/a |

A builder is never hard-deleted, and each level below refuses when children
exist. The chain is better defended than the audit says.

### 3.2 Where it is actually thin

Two real holes, both narrower and sharper than the audit's claim.

**Hole 1 — the UnitType guard counts the wrong thing.**

`activeCampaignCount` is a **denormalised counter** (`models/UnitType.js:178`)
that counts only campaigns in state `active`. A campaign in `completed`,
`paused`, `expired` or `cancelled` does not count. So a unit type whose campaign
has completed — with `CampaignMember` documents at `tokenStatus: paid` — has
`activeCampaignCount === 0` and **deletes cleanly**, stranding the campaign and
every paid member.

Being denormalised, counter drift alone also opens the gate. Nothing checks
`paidMemberCount`. Confirmed: no reference to `paidMemberCount` or
`tokenStatus` in `unitTypeController.js` or `projectController.js`.

**Hole 2 — `ProjectBooking` is a barrier to nothing.**

`ProjectBooking` references `Project`, `UnitType` and `Builder`, and carries the
UTR number and payment screenshot. It is **never consulted by any delete path**.
A project with zero unit types but live bookings passes the `unitTypeCount`
guard and deletes.

### 3.3 Dependency graph

```
User ──┬── Property ──┬── TransactionVerification ── (gates Reward claim)
       │              └── Lead ── propertyOwner (another User)
       ├── Reward (ledger)          ├── Agreement (2 parties, HMAC-signed)
       ├── Referral (2 parties)     └── SavedSearch, Notification, Message …
       ├── CampaignMember ── GroupBuyCampaign
       └── ProjectBooking

Builder ──┬── Project ──┬── UnitType ──┬── GroupBuyCampaign ── CampaignMember [PAID]
          │             │              └── ProjectBooking     [UTR + screenshot]
          │             └── ProjectBooking
          └── Property
```

### 3.4 Proposed refusal / cascade matrix

Refusal preferred wherever deletion would destroy money, payment evidence,
verified deal evidence, counterparty history or audit-relevant data. Explicit
named aggregate-root functions, not Mongoose middleware.

| Root | Dependent | Rule | Reason |
|---|---|---|---|
| **UnitType** | `CampaignMember` with `tokenStatus: paid` | **REFUSE** | money paid, no gateway to refund through |
| **UnitType** | `GroupBuyCampaign` in **any** state | **REFUSE** | replaces the active-only counter check |
| **UnitType** | `ProjectBooking` in any non-cancelled state | **REFUSE** | UTR + screenshot are the receipt |
| **Project** | `UnitType` | REFUSE | already implemented, keep |
| **Project** | `ProjectBooking` | **REFUSE** | currently missing |
| **Builder** | approved `Property` | REFUSE | already implemented, keep |
| **Builder** | anything else | soft-delete | already implemented, keep |
| **Property** | pending `TransactionVerification` | **REFUSE** | orphaning it breaks admin approve *and* reject, and the buyer's reward becomes permanently unclaimable |
| **Property** | approved `TransactionVerification` | **REFUSE** | verified deal evidence |
| **Property** | `Lead` | **ANONYMISE**, do not delete | belongs to the owner's pipeline |
| **Property** | `Agreement` | **REFUSE** | signed legal document |
| **Property** | images | cascade | already implemented via `deletePropertyAssets` |
| **User** | `Agreement`, `TransactionVerification`, `ProjectBooking` | **RETAIN** | §1.6 |
| **User** | `Lead`, `CampaignMember` | **ANONYMISE** | §1.6 |
| **User** | `Reward`, `Referral`, `Report` | **decision pending** | currently hard-deleted; §1.4 |
| **User** | sessions, tokens, saved searches, notifications | cascade | already implemented, correct |
| **GroupBuyCampaign** | — | no delete endpoint | leave it that way |

**Counter integrity, separately.** Every guard that reads a denormalised counter
(`activeCampaignCount`, `unitTypeCount`, `memberCount`, `paidMemberCount`)
should read `countDocuments` instead when used as a *safety* check. A cached
number is fine for display and wrong for a gate.

---

## Part 4 — Unresolved product and legal decisions

Ordered by what blocks the most work.

| # | Decision | Blocks | Who |
|---|---|---|---|
| 1 | Deleted-user policy per collection (§1.6 table) | all cascade implementation | product + legal |
| 2 | Retention period for "retain" collections | §1 | legal |
| 3 | RBAC: complete or retire (§2.5) — turns on whether a second class of admin is planned | all admin-surface work | product |
| 3a | Who seeded the 45 production permissions, and is it reproducible? (§2.6) | disaster recovery, dev/prod parity | ops |
| 4 | Is `Reward` a financial record for retention purposes? | §1.4 | product + finance |
| 5 | Group buy: build or withdraw | how much the campaign chain matters | product |
| 6 | Are chat messages disposable? | `Message` deletion | product |
| 7 | Refund path for a paid `CampaignMember` | whether REFUSE is a dead end for support | product + ops |

Decision 7 matters more than its position suggests. Refusing to delete a unit
type with paid members is right, but with no refund flow it leaves support with
no way to unwind a campaign at all. REFUSE without an escape hatch becomes a
support ticket nobody can close.

---

## Part 5 — Proposed implementation order

Nothing below is started.

**Step 0 — two read-only production queries. DONE 2026-08-18.**

```
production permissions count   = 45
legacy string-role admin count =  0
```

Both answers inverted the RBAC conclusion; §2 is rewritten. The layer is seeded
and functioning, and grants every admin every permission, so it protects
nothing. A new risk replaced the old one: that configuration exists only in the
production database and cannot be recreated from version control (§2.6).

**Step 1 — refusal guards only.** Close holes 1 and 2. No deletion behaviour
changes, no data moves; some deletes that used to succeed start returning 409.
Same shape as the `TAXONOMY_IN_USE` guard already shipped in `ef0da6e`, so the
pattern and its tests exist. This is the whole unrecoverable half of the risk
and it needs no product decision.

**Step 2 — RBAC**, once decision 3 is made. Independent of everything else.

**Step 3 — anonymisation**, once decisions 1, 2 and 4 are made. Needs a
migration for existing orphans (the 2 known production properties referencing
deleted users), and by Rule 8 that migration needs a dry run, a deterministic
mapping, a backup, UP, idempotency, DOWN, verification and a production gate.

**Step 4 — named aggregate-root delete functions.** `deleteBuilderAggregate`,
`deleteProjectAggregate`, `deleteUnitTypeAggregate`, `deletePropertyAggregate`,
`deleteUserAggregate` — the last one adopting the existing `deleteAccount` body.
Dry-run each against `dealdirect_dev`.

**Step 5 — counter integrity.** Replace cached counters in safety checks with
`countDocuments`.

Step 1 is the recommended next piece of work: highest risk closed, no product
decision required, and it is reversible in a way that deletion is not.
