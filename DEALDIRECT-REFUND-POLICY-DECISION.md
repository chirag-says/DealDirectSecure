# Paid CampaignMember — Refund / Unwind Decision

Phase 3. **Analysis only. No code changed, no refund mechanism built, production
read-only.** The refusal guards from `a1651e9` are untouched.

Traced from source and confirmed against production data on 2026-08-18.

---

## 1. Existing refund / unwind capability

**There is no refund mechanism, and no code can safely unwind a paid campaign
member today.** But the shape of the problem is different from "nothing exists".

### What exists

| Capability | State |
|---|---|
| `CampaignMember.tokenStatus: "refunded"` | **in the enum, written by no code, anywhere** |
| `CampaignMember.status: "exited"` + `exitReason` + `exitedAt` | written by `exitCampaign` |
| `ProjectBooking` cancellation | **works** — transition table, status history, inventory restore |
| `ProjectBooking.payment.status: "rejected"` + `rejectionReason` | exists |
| Reward reversal for campaigns | **not applicable** — campaigns award no points (§3) |
| Payment gateway | **none anywhere in the codebase** |

### Defect 1 — a paid member can self-exit, and nothing records the debt

`exitCampaign` (`controllers/campaignController.js:321`) filters on
`status: "active"` only. It does **not** check `tokenStatus`. So a user who has
paid can exit their own campaign, and:

- `status` becomes `exited`, `paidMemberCount` drops via the post-save hook
- `tokenStatus` stays `"paid"` — it never becomes `"refunded"`
- the response says *"Refund (if applicable) will be processed manually"*
- **no refund obligation is recorded in any collection**

The only trace that money is owed is a document with `tokenStatus: "paid"` and
`status: "exited"` together, and nothing surfaces that combination.

Production currently has **0** documents in that state. It is a live hole, not a
live liability.

### Defect 2 — the admin tools for this are unreachable

`campaignApi.getMembers`, `getPendingPayments` and `verifyPayment` exist in
`Admin/src/api/adminApi.js` with **zero call sites** in any page or component.
There is no admin screen that lists campaign members or verifies a payment.

So the documented flow in the model header — *"Admin verifies in admin panel →
sets tokenStatus: paid"* — **does not exist as a UI**.

### Defect 3 — the sync is one-directional

`syncBookingToCampaign` (`controllers/bookingController.js:30`) is how a member
actually becomes paid. It fires from three places, all forward transitions, and
auto-creates or marks a member `paid` when a booking's payment is verified or
the booking reaches `completed`.

**Cancelling a booking does not reverse it.** The cancel path restores unit
inventory and appends to `statusHistory`, and never touches `CampaignMember`. So
the one unwind path that does work, booking cancellation, leaves the derived
paid member behind, still counted in `paidMemberCount`.

---

## 2. Is the payment model real or proof-based?

**Proof-based. There is no gateway and therefore no possibility of an automated
refund.**

`grep` for razorpay, stripe, payu, cashfree, paytm, instamojo across controllers,
services, models, config and middleware returns nothing, and `package.json`
carries no payment SDK. Both model headers say so explicitly: *"admin-mediated,
no payment gateway"*.

What the system actually records:

| Field | On | Meaning |
|---|---|---|
| `payment.tokenAmount` | ProjectBooking | amount shown on the UPI QR screen |
| `payment.utrNumber` | ProjectBooking | client-typed UTR / reference |
| `payment.screenshotUrl` | ProjectBooking | Cloudinary screenshot |
| `payment.verifiedAt` / `verifiedBy` | ProjectBooking | which admin accepted it |
| `paymentReference` | CampaignMember | **copied from the booking's UTR** |
| `paymentProofUrl` | CampaignMember | screenshot, may be empty |
| `tokenPaidAt` / `paymentRecordedBy` | CampaignMember | when and by whom |

**No amount is stored on `CampaignMember` at all.** The token amount lives on the
booking and on `project.financials.bookingAmount`. A paid member document does
not say how much was paid.

### The authoritative record is the booking, not the member

The one paid member in production shares its UTR with **2 ProjectBooking
documents**. The member is a projection of a booking payment, created by the
sync, carrying a copy of the reference and no amount.

That reframes the whole decision: **the campaign member is not the payment
record. The booking is.** Unwinding the money means cancelling a booking, which
already works. Unwinding the *membership* is the missing half.

### Production exposure

```
campaignmembers total     = 1   (tokenStatus: paid, status: active)
groupbuycampaigns         = 1
projectbookings total     = 6   — 2 enquiry, 2 payment_submitted, 2 completed
payment.status verified   = 2
bookings with a UTR       = 4
paid AND exited members   = 0
```

Small, and real. The delete guards are currently protecting one paid member and
six bookings.

---

## 3. Reward reversal implications

**None.** Verified: `controllers/campaignController.js` and
`controllers/bookingController.js` contain no reference to `awardPoints` or
`rewardService`. Joining a campaign, paying a token, and completing a booking
award no reward points.

So a refund would have no reward ledger consequence, and no reversal is needed.
`services/rewardService.js` has no generic reversal function in any case;
`adminAdjustPoints` (capped at 50,000) is the only manual correction path, and it
is unrelated to campaigns.

This removes the largest complication a refund flow would normally carry.

---

## 4. Options

### Option A — never delete paid campaign structures

Keep the guards exactly as shipped. Paid members block deletion permanently.

- **Cost:** nothing to build.
- **Consequence:** a campaign created by mistake, with one paid member, can
  never be removed. Support has no path at all. That is the current state and it
  is why this decision is open.

### Option B — build an admin cancellation / refund workflow

An explicit refund state on `CampaignMember`, an audit trail, and reversal of
the sync.

Realistically:
1. Block `exitCampaign` for paid members, or make it record a refund obligation.
2. An admin action setting `tokenStatus: "refunded"` with who, when, why, and
   the outbound reference — the enum value already exists.
3. Make booking cancellation propagate to the derived member.
4. Build the missing admin member screen — the three API helpers already exist
   and are already dead code.
5. A "refunds owed" view: `tokenStatus: paid` + `status: exited`.

The refund itself stays manual. No gateway means the workflow records that a
refund was made out-of-band; it cannot issue one.

### Option C — mark closed and retain, no deletion

An archival state on the campaign (`cancelled` / `closed`) that hides it from
users and admin lists while keeping every member document. Deletion stays
refused forever.

- **Cost:** small — a status filter and a list view.
- **Consequence:** support can get a bad campaign out of the way without
  destroying evidence, but nothing tracks refunds owed.

---

## 5. Recommendation

> **Product and ops decision, not an engineering fact.** What follows is what the
> data model and the production numbers support.

> **Superseded in part, 2026-08-18.** Group Buy is deferred to a dedicated build
> after Phases 3, 4 and 5. That settles the open question this recommendation
> hinged on, and it answers it in the direction that favoured waiting: option B
> is not worth building for one paid member in a feature nobody is shipping yet,
> and the refund workflow folds into that later build.
>
> What that leaves for now is neither B nor a formal C, but the status quo plus
> the integrity guards already shipped: deletion of paid campaign structures is
> refused, a paid member cannot self-exit, and a cancelled booking reverses the
> membership it created. Support has no self-service unwind path, which remains
> true and remains recorded — the one paid member in production is the whole
> exposure.
>
> The two defect fixes below (§5, "worth doing regardless") were shipped in
> `b14ecf1`, so only the workflow half is deferred.

**Original recommendation: C now, B when group buy is confirmed as a product.**

Reasoning from the actual state rather than the general principle:

- **The money is already unwindable.** Booking cancellation works, with a
  transition table and history. The gap is that the *derived* member record is
  not reversed. That is a sync bug, not a missing refund system.
- **Volume is one member and one campaign.** Building a refund workflow for a
  single record is disproportionate, and group buy is itself an open product
  decision — the roadmap records it as held (D4), and no code applies
  `discountPerBuyer` to any price.
- **C is cheap and closes the support dead end,** which is the actual complaint
  that opened this decision.
- **B is wasted if group buy is withdrawn.** Its five items only pay off if the
  feature ships.

**Two fixes worth doing regardless of the option chosen,** because both are
defects rather than missing features:

1. **`exitCampaign` must not silently drop a paid membership.** Either refuse for
   paid members, or record the refund obligation. Today it promises a manual
   refund in a response string and writes nothing.
2. **Booking cancellation should reverse the member it created.** The sync is
   one-directional, so cancelling leaves a paid member inflating
   `paidMemberCount`.

Neither is a refund system. Both are small, and both are in scope for a later
pass once the option is chosen.

**Keep the refusal guards unchanged.** Nothing here justifies weakening them, and
a `completed`, `expired` or `cancelled` campaign is exactly the case that used to
let paid money be deleted.

---

## 6. Product / ops decisions required

| # | Question | Needed for |
|---|---|---|
| 1 | Option A, B or C? | closing the support dead end |
| 2 | ~~Group buy: build or withdraw?~~ **DECIDED 2026-08-18: deferred to a post-Phase-5 build** | resolves this table's dependency — see below |
| 3 | When a refund is paid out-of-band, what must be recorded — reference, amount, who authorised? | any refund state design |
| 4 | Should a paid member be allowed to self-exit at all? | fixing `exitCampaign` |
| 5 | Who is accountable for a refund actually reaching the payer? | there is no gateway; this is a human process |
| 6 | Is one UTR shared by two bookings expected, or a duplicate to investigate? | production data question |

Question 6 is a fact worth checking: `payment.utrNumber` has a non-unique index,
so duplicates are permitted, and the one paid member's reference matches two
booking documents.

---

## 7. Separate engineering task: `Builder.email` index drift

Recorded here, **not fixed in this pass**.

```
schema  (models/Builder.js:86) : builderSchema.index({ email: 1 }, { sparse: true })
                                 → NOT unique, sparse
deployed (dealdirect_dev AND production Deal-Direct):
                                 email_1  unique = true, sparse = false
```

Both databases already hold exactly one builder with `email: null`. Because the
deployed index is unique and not sparse, **creating a second builder without an
email fails today** with:

```
E11000 duplicate key error collection: builders index: email_1 dup key: { email: null }
```

`email` is not a required field, so the admin builder form permits leaving it
blank and the create then dies on a raw duplicate-key error.

Found incidentally while writing `backend/scripts/verify-delete-guards-dev.mjs`,
which had to give every fixture a unique email to run.

**Notes for whoever fixes it:**

- The schema's own declaration is probably also wrong: `{ sparse: true }` with no
  `unique` means no uniqueness at all, so two builders could share an email. The
  likely intent is `{ unique: true, sparse: true }`, or better a partial index on
  `{ email: { $type: "string" } }`, which covers null *and* absent.
- Mongoose does not alter an existing index. The old `email_1` has to be dropped
  and recreated, which is a production index change and belongs in the deferred
  index-cleanup stage in §9 of the taxonomy cutover plan, alongside
  `propertytypes.name_1` and `categories.name_1_propertyType_1`.
- Worth sweeping the other 30 models for the same declared-vs-deployed drift
  while in there. `models/Role.js` is already known to declare `name` unique and
  then re-index it.

Production is under a change freeze until the taxonomy cutover; do not touch the
index before then.
