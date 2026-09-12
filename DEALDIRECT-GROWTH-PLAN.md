# DealDirect: Proposed Improvements & Running Costs

August 2026

This is a proposal for your consideration. Nothing here is decided; every item goes ahead only with your approval, and in whatever order you prefer. I have added my suggested sequence and honest cost estimates to make the decision easier.

---

## What we run on today

| Component | Current setup | Status |
|---|---|---|
| Hosting | Hostinger Cloud Startup (4 CPU, 4 GB RAM, 100 GB storage, rated ~200,000 visitors/month) | Sufficient for this entire plan |
| Database | MongoDB Atlas, free 512 MB tier | Sufficient to start; see costs |
| Images | Cloudinary | No change needed |
| Agreements AI | Gemini | Already paid, no change |
| Email | Basic SMTP (few hundred emails/day limit) | Needs a cheap upgrade |
| WhatsApp | Unofficial method (WAHA) | I would suggest switching to Meta's official service: Meta has begun banning unofficial senders, and losing our number mid-deals would hurt us badly |

---

## Suggested work plan: what, how, when

My suggestion is one feature per week, maximum: each goes live and gets observed before the next starts. The sequence below is only my recommendation; please feel free to reorder, drop, or add items.

| Week | What | How |
|---|---|---|
| 1 | Groundwork: fix the three broken reward payouts, auto-cleanup of old notifications, usage tracking so every later change is measured. Switch email to a proper service. Start Meta's WhatsApp business verification (runs in parallel, needs business documents once). | Code fixes + one email provider signup |
| 2 | **Shortlist**: buyers save unlimited homes privately; owner is contacted only when the buyer chooses. Plus "continue where you left off" on return visits. | New saved-homes list, separated from the enquiry system |
| 3 | **Saved searches + new-match alerts**: "2BHK in Wakad under ₹30L," WhatsApp/email message the moment a match is listed, with a direct link. | Matching already half-built; wire it to alerts |
| 4 | **Price-drop alerts** on shortlisted homes and saved searches. | Track every price change, notify watchers |
| 5 | **Owner weekly report**: views, enquiries, pending replies, one email per week. | Automated weekly summary |
| 6 | **Deal page**: one private page per buyer-owner pair showing progress (contacted → visit → agreement → done), visible to both sides. | Built on the existing lead records |
| 7 | **Site visit booking + reminders** (day before, 2 hours before) + one-tap post-visit feedback. | Visit flow already part-built; complete and connect reminders |
| 8 | **Messaging on the deal page**, with automatic warnings against token-advance scams. | Chat system already built in code; mount it inside the deal page only |
| 9 | **Agreement inside the deal** (free, one tap at the right moment) + **response-speed display** on listings ("usually replies within X hours"). | Agreement generator already built; add placement + timing stats |
| 10 | **Rewards adjustment (for your approval)**: small rewards at confirmed visit and completed agreement; fixed guaranteed payout at verified close with shagun draw as bonus; points-only until close; anti-fraud checks (same-device/same-account detection, account age, 30-60 day payout hold, both parties confirm separately). | Reward tables + verification checks; total cost per deal stays at today's ~₹273 or less. I will present the exact numbers to you before touching anything |
| 11 | **Verified-deal reviews**: only parties of an admin-verified deal can review each other; published after both submit. | New review flow gated on verified closes |
| 12 | **Verification badges** for owners with checked identity/papers + **buyer seriousness card** on leads (search activity, budget fit). | Badge on existing admin verification; lead card enrichment |
| 13 | **Locality price pages**: typical asking price by area and home type, supply, quarterly trend, from our own listings. Google-indexable. | One nightly automated calculation + public pages |
| 14 | **Price intelligence on listings**: price history, days listed, "asks 8% below locality average," price guidance for owners at listing time. | Reuses week-13 data |
| 15 | **EMI calculator + compare homes side by side.** | Client-side tools, no server load |
| 16 | **Rental clock + referrals + expiry nudges**: month-10 renewal reminders to owner and tenant (we know every verified rental's date); referral bonuses fixed and offered at reward-claim moment; "your ₹X points expire in 14 days" reminders. | Scheduled reminders on existing data |

Later, if you wish (each ≤1 week): society/project pages, locality reviews from verified residents, a monthly price report we could send to the press under the DealDirect name, agreement as a paid service for outside customers.

---

## Running costs

My development charges are covered by the existing monthly arrangement. The only question is infrastructure.

**Nothing above needs a bigger server.** Every feature runs on the current Hostinger plan. All new data (shortlists, alerts, deal pages, price stats) is text: kilobytes per record, a few hundred MB per year even with strong growth, against 100 GB available.

| Item | Cost now | Cost as we grow |
|---|---|---|
| Hostinger Cloud Startup | No change | Upgrade only past ~150,000 visitors/month: next tier is roughly ₹300-1,300/month more |
| MongoDB Atlas (512 MB free) | ₹0 | When the free 512 MB fills (realistically later this year as messages and alerts accumulate), next tier is ~₹800/month. Auto-cleanup of old notifications (week 1) delays this |
| Cloudinary | No change | No change; these features add no images |
| Email service | ₹0 (free tier, ~300/day) | ~₹9 per 1,000 emails beyond that; a few hundred ₹/month |
| WhatsApp official | ~₹0.12 per message | ~₹700-800/month at 1,000 active users; scales only with actual users messaged |
| Gemini | Existing usage | Unchanged |

**Total new spend now: under ₹1,000/month. At ~10,000 active users: roughly ₹8,000-10,000/month, nearly all of it WhatsApp messages, which only occur because users exist.**

No new machines, no software subscriptions, no hidden costs.

---

## What I would need from you, if you approve

1. Business documents for Meta's WhatsApp verification (one time; I will handle the whole process)
2. Your decision on the rewards adjustment (week 10; exact numbers will be shown to you first)

Please go through the list and mark whatever you feel is right for the platform. I will proceed only on the items you approve, at whatever pace you are comfortable with.
