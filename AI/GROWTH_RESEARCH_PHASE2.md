# DealDirect Growth Research, Phase 2

Date: 2026-08-18. Prepared from three parallel research tracks (portal histories, cross-vertical marketplaces, behavioral science + notification economics + fraud), two earlier research rounds (India portals, disintermediation, reward breakage, NAR buyer-journey data), and a full codebase inventory. Companion to the phase-1 roadmap discussion; supersedes it where marked.

Evidence tags used throughout:
- **[V]** VERIFIED: directly supported by a cited source.
- **[I]** INFERENCE: reasoned conclusion from verified evidence.
- **[H]** HYPOTHESIS: should be tested, not assumed.

---

## 1. Competitor evolution (Part 1)

### India (from rounds 1-2 + this round)

| Company | Year 0-2 product | Retention anchor | Leakage stance | Monetization | Verdict for DealDirect |
|---|---|---|---|---|---|
| NoBroker (2014) | Bangalore-only rentals, C2C, broker-ban verification algorithm [V] | Free chat + contact credits; later Forum (SEO) | Gates contact (9 free), chat free | Subscriptions = 99% of FY24 revenue ₹803cr; loss ₹411cr; services ≈ ₹5cr [V, RoC via Entrackr] | Copy: verification moat, single-city density, forum-SEO. Don't copy: burn (₹1.62 spent per ₹1 earned), services mirage |
| Housing.com (2012) | Map search, verified listings, data quality bar [V] | Map/verification UX | n/a | Burned on brand (₹120cr campaign era), valuation ₹1,500cr → ₹450cr, merged 2017 [V] | Spending on reach without retention is fatal. Product data quality was the real asset |
| 99acres (2005) | Broker/builder listings | Price trends, locality insights, resident reviews, registry records, alerts | Ignores (monetizes supply side) | Broker/builder subscriptions + ads | Best engagement metrics of Indian portals: 33.7% bounce, 3m33s, 4.32 pages/visit [V]. The data-as-destination playbook is cheap and copyable |
| Magicbricks (2006) | Same category | Price trends, locality reviews, calculators, "full-stack" services push | Ignores | Listings + ads + services | Same playbook, confirms it |
| CommonFloor (2007) | NOT search: society management + resident forums; 700 societies in 6 months by word of mouth [V] | The society itself (notices, dues, forums) | n/a | Builder CPL + vendor ads; ₹2cr revenue on 50k communities; distressed exit to Quikr 2016, founders gone in a year [V] | The most India-proven cold-start/retention wedge here, and the clearest proof that engagement without a payer is a feature, not a company |

### International (this round)

| Company | Year 0-2 | Retention anchor | Leakage stance | Key failure | Transfer |
|---|---|---|---|---|---|
| Zillow (2006) | Zestimate on 40M homes from public county records, no listings needed; crashed on launch, 1M users in ~3 days [V] | Homeowners checking their own number monthly | Immune: sells agent ads, not transactions | iBuying: >$540M write-down, 2,000 jobs, dead in 3.5 years [V] | Mechanism transfers; data substrate (US county records) does not exist in India. No honest AVM is buildable here [I] |
| Redfin (2006) | Map-based MLS search + commission refunds ($1M refunded in 8 months) [V] | Map + refund | Converts leakage to revenue via Partner Agents (30-35% referral at close) [V] | 19 years, zero GAAP-profitable years, distressed sale to Rocket 2025 [V] | Owning the transaction with your own workforce is a capital furnace. Verify the close, never perform it |
| Rightmove (2000) | Founded by agency incumbents; free listings until 2002 [V] | Saved-search alerts (instant on price cuts ≥2%) + monthly House Price Index from own asking-price data, published to press since 2002 [V] | Irrelevant: per-branch subscriptions | £1.5B abuse-of-dominance suit (scale-era problem) | The alert spine and the HPI are the two cheapest, best-proven retention machines in portal history |
| Zoopla (2008) | Coverage of all 27M UK homes via public sold-price data + claim-your-home UGC [V] | Free estimates on every home | Irrelevant | Lost ~25% of agents in months to OnTheMarket's exclusivity rule 2015 [V] | #2's supply is rented; demand-side anchors are what let a #2 survive. TemptMe/Make Me Move latent-supply gimmicks faded on both platforms [I] |
| PropertyGuru (2007) | Freemium agent listings vs newspaper classifieds; single-market depth [V] | Inventory depth (weakest data-hook story in the set) | Irrelevant | SPAC at $1.8B, fell ~70%, taken private $1.1B [V] | ~90% Singapore share before regional spread: density before geography |
| Realtor.com (1996) | MLS aggregation via trade association | Listing completeness | Success-fee model (Opcity 30-38% at close) polices under-reporting via licensing [V] | #1 for 11 years, lost to Zillow: completeness without an owner-side loop is defensible only until someone gives consumers a between-transactions reason to visit [I] | The strategic warning that matters most |

**Cross-cutting [I]:** every durable winner monetizes agents/developers, the constituency DealDirect abolished. Their retention playbooks (alerts, indexes, owner data hooks, communities) are the transferable half; their revenue playbooks are not. The one aligned revenue mechanic: success-fee-at-close, of which DealDirect's verified-close + reward flow is already a lightweight analog.

---

## 2. Outside real estate (Part 2)

Leakage regimes and what each platform's experience proves:

| Platform | Regime | Documented result |
|---|---|---|
| Airbnb | Fight: escrow + contact masking + off-platform policy bans [V] | Academic: masking alone shows no significant effect on disintermediation [V, BU Platform Strategy 2022]. Hosts report silent blocking costs bookings [V] |
| Uber | Fight (deactivation), but Bangladesh: 0% fee subscription to remove the incentive [V] | Reduce the tax rather than police it |
| eBay | Fight: contact-info bans, fee-avoidance charges [V] | Works because eBay has billing hooks over repeat sellers. Reputation RCT: established seller identity earns 7.6% price premium [V, Resnick et al. 2006] |
| Upwork | Fight (24-month non-circumvention) + sells a legal exit (conversion fee) [V] | 2023 flat-fee change doubled costs for the most-trusted relationships, the exact accounts most likely to leak [V]; active clients fell |
| Fiverr | Strictest: NLP contact detection, permanent bans [V] | 2024 opaque Success Score caused seller revolt and departures [V] |
| OLX | Tolerate: monetizes attention | Fraud lives in the gap: organized scam rackets, 15M+ daily chats with ML fraud screening bolted on later [V] |
| FB Marketplace | Tolerate: monetizes reach | ProPublica: scanning missed scams, banned victims, trust erosion [V]. The strongest cautionary case for tolerated leakage without trust investment |
| Etsy | Fight fee avoidance | 2022 fee hike on locked-in supply → strike, union talk [V] |

**The academic anchor [V]:** Gu & Zhu (Management Science 2021, RCT): raising trust between the two sides increases good matches AND increases disintermediation past a threshold. Trust substitutes for the platform once established. **Implication [I]: DealDirect cannot win by containing the transaction. It must win by being the only place the deal gets *recorded*, verified, and rewarded.**

Transfers, ranked: Airbnb wishlists → shortlists (1.2B wishlists; 80%+ of bookings are group decisions → shared shortlists) [V]; saved-search alerts; eBay reputation premium → verification badges; transaction-gated two-sided reviews with simultaneous reveal [V, Fradkin 2021] → close-gated reviews (DealDirect advantage: only admin-verified closes unlock review rights, structurally killing fake reviews); transparent supply-side tiers (eBay TRS arc: volume badges inflate and die, quality-gated badges with concrete perks persist) for builders/multi-property owners only.

Does NOT transfer: escrow/contact masking as defense (no payment to escrow; masking demonstrably fails); ToS bans/FOKO (no leverage over a one-shot buyer; carrot-only is the only available mechanism, not a compromise); buyer-side loyalty subscriptions (frequency mismatch); opaque composite scores (JSS "invisible cage", Fiverr revolt: any DealDirect metric must be arithmetic the owner can recompute) [V/I].

---

## 3. Retention loops (Part 3)

**A. Search loop** (return while searching): saved searches (built, flags ignored today); shortlists decoupled from leads (today: cap 5, every save fires a lead — actively punishes the core searcher behavior); shared shortlists with spouse/parents (group-decision evidence); price-cut alerts (Rightmove ≥2% instant); new-match alerts (built); locality price pages; compare tray; search-history resume ("pick up where you left off"); budget-flexibility suggestions (Airbnb flexible-dates analog: "₹5L over your budget unlocks 14 more homes") [H].

**B. Property loop** (one listing → many interactions): price-change history on the listing; days-on-platform freshness; locality median vs this asking price ("this 2BHK is 8% below the Wakad median": from own data, no AVM claim); similar/nearby properties (restored recently); owner verification badge; owner responsiveness display; visit scheduling; commute time (Mappls key exists in env; per-request costs, evaluate free tier) [H]; society page linkage.

**C. Deal loop** (keep the transaction observable): deal room per lead: chat + visit + progress tracker (endowed progress: grant "step 1 verified" at entry with stated reason [V mechanism]) + document exchange + agreement generation + two-sided close reporting. The close reward is the subsidy for disclosure: both sides get points, so both have standing to nag the other to report [I].

**D. Return loop** (tomorrow/next week/next month): alert triggers (price cut, new match, owner replied, visit reminder, agreement step); owner weekly digest (views, leads, response prompt); monthly locality index; points expiring; draw-entry held ("your shagun entry is reserved 14 days" — loss-aversion framing, zero cash risk) [H].

**E. Post-deal loop**: close-gated review (simultaneous reveal, fixed window); referral milestones (code exists, milestones 2-3 never fire); rental renewal calendar: Indian rent agreements run 11 months; DealDirect knows every verified rental close date → month-10 reminder to owner (relist or renew) and tenant (renew or new search). Rentals are the recurrence engine; sales are episodic [I]. Owner relist flow; "your home's locality, one year later" email [H].

---

## 4. Why would a person open DealDirect tomorrow? (Part 4)

Concrete answers with precedent, not "notifications increase engagement":

1. "3 new 2BHKs in Wakad under ₹30L since yesterday" (Rightmove spine) [V mechanism]
2. "The Baner flat you shortlisted dropped ₹2L" (price-cut alert; Rightmove fires instant alerts on cuts ≥2%) [V]
3. "The owner replied" / "Owner confirmed Saturday 11am visit" (deal-room events)
4. Owner: "Your listing got 41 views and 3 leads this week; 1 lead is waiting on your reply" (Zestimate psychology adapted: watch your own number) [I]
5. "Wakad prices moved +1.8% this quarter" (monthly index; Rightmove HPI made this a press machine from a single aggregation query) [V]
6. "Your spouse added 2 homes to your shared shortlist" (Airbnb group-decision evidence) [V mechanism]
7. "Your ₹120 in points expires in 14 days" (redemption urgency, practitioner-grade evidence) [V-weak]
8. Month 10 of a rental: "Your agreement ends in 6 weeks: renew in 2 clicks or relist" [I]

---

## 5. Content/data products evaluated (Part 5)

| Product | Retention | SEO | Conversion | Data needed | Cost | Verdict |
|---|---|---|---|---|---|---|
| Locality price pages (median asking by BHK/type, supply counts, QoQ trend) | Med | **High** | Med (anchors negotiation) | Own listings only | One cron aggregation | **Build** |
| Monthly city price index + press release | Med (email) | High (backlinks) | Low | Own listings | Same cron | **Build** (needs ~2 quarters of data credibility) |
| Price history per listing | Med | Low | **High** (Zillow: well-priced sells faster) | Own price-change log | Trivial | **Build** |
| EMI / affordability calculator | Low-Med | Med | Med | None (static math) | Client-side only | **Build** (cheap) |
| Rent-vs-buy tool | Low | Med | Low | Static + own rent medians | Client-side | Later |
| Locality reviews | Med | High | Med | Verified closes (source of truthful reviewers) | Moderation time | **Build after close-gated reviews exist** |
| AVM ("fair price estimate") | High if credible | High | High | Sold-price registry India lacks; asking-price AVM would be dishonest | High | **Do not build** [V substrate, I conclusion] |
| Commute/schools/hospitals overlay | Low-Med | Low | Med | Mappls/Google APIs, per-request fees | Recurring API cost | Defer; free-tier experiment only [H] |
| Market reports (PDF) | Low | Med | Low | Own data | Writing time | Later; the index email covers it |

---

## 6. Rewards economics (Part 6)

**Current state (computed from `rewardService.js`):** expected value per draw: property_sale ≈ 2,728 pts (₹136), most likely outcome 1,000 pts (₹50, 60%); ₹2,100 tier probability 0.24%. Enquiry ≈ ₹1.82, listing ≈ ₹5.60. Expected cost per verified close, both sides: ≈ ₹273 before tier multipliers. The founder-feared ₹2,100 is a jackpot perception, not the unit cost.

**Structure comparison:**

| Structure | Evidence | Cost profile | Abuse surface | Verdict |
|---|---|---|---|---|
| One large reward at close (current) | Lotteries showed no advantage over fixed pay for one-off events [V, RCTs] | Known EV ₹273/deal | Collusion target (pays both sides) but rare + manually reviewed | Keep as the anchor, make it **fixed and predictable** (trust framing), with the draw as a bonus layer if the shagun branding matters |
| Milestone drip (visit, agreement, close) | Goal-gradient + endowed progress: causal RCTs (Kivetz 2006; Nunes & Drèze: 19%→34% completion from endowed head start) [V] | Small if points-only | **High if cash-equivalent pre-close** [V pattern] | Build, but milestones pay **non-transferable points/draw entries only**; cash-equivalence exclusively at verified close |
| Small variable draws at frequent behaviors | Regret-lottery RCTs: adherence 32%→50% at expected value under $1 [V, Volpp et al.] | Tiny EV per draw | Farming risk if behaviors are free to fake | Attach only to counterparty-confirmed events (visit confirmed by both) |
| Non-cash (vouchers/catalog) | Standard | Face value discount + breakage 20-30% [V] | Lower | Prefer for redemption |
| Platform credits / fee waivers (featured listing, agreement fee waiver) | Standard | Fraction of face value, feeds the loops | Lowest | **Strongest ₹-for-₹ option** |
| Featured-listing benefits for owners | Portal-standard | Near-zero marginal | Low | Use as milestone perk for owners |

**Anti-abuse (lean, no SaaS) [V components, I assembly]:** DealDirect's pay-both-sides verified close is the textbook collusion pattern (DataVisor). Stack: (1) FingerprintJS v5 (MIT) device hash + IP + phone + payout VPA stored per account, flag any payout where buyer and seller share a node; (2) velocity rules: account age < N weeks at close, first-ever action = the closed property, deals per owner per quarter; (3) 30-60 day payout holding period framed as registry confirmation, risk-tiered; (4) two-sided independent attestation, mismatches auto-flag; anchor verification on registered deed / stamp-duty receipt numbers, not photos of agreements; (5) silent holds, not bans; (6) manual review is affordable precisely because closes are rare (~₹290/review vs ₹273 payout, and only at this scale); (7) the structural safeguard: milestone rewards non-cashable, so pre-close farming yields nothing liquid.

---

## 7. Disintermediation verdict (Part 7)

**Question: prevent WhatsApp, or accept it and be the system of record? Answer: accept it. Evidence:**
- Contact masking alone does not measurably prevent disintermediation even where payments are captive [V, BU 2022].
- Trust-building itself increases leakage past a threshold [V, Gu & Zhu]: the better DealDirect gets at matching, the less the parties need it at close. Containment is a losing arms race.
- Punitive regimes require leverage (eBay's billing hooks, Upwork's income dependence). DealDirect has none over a once-per-years buyer [I].
- Tolerated leakage without trust investment destroys the brand (OLX scam rackets, FB Marketplace/ProPublica) [V]. Verification IS the product; chat-layer scam detection (payment-lure patterns, token-advance warnings) is retention infrastructure, not a side project.
- DealDirect's reward-at-verified-close is structurally unique among all platforms studied: it *subsidizes disclosure* of the off-platform close instead of taxing the transaction [I]. Double down: the close reward is the price paid for the deal record, the review unlock, and the renewal calendar.

**One narrow gate stays:** owner contact behind login + interest (already the case), so the *match* is always observed. That's what makes close attribution and reward claims provable. Never escalate to masking numbers in chat.

---

## 8. Notification channels (Part 8)

| Channel | Open/CTR | India cost | Deep link | DealDirect use |
|---|---|---|---|---|
| WhatsApp official API | ~95%+ open, 45-51% CTR (vendor ceiling) [V] | Utility ₹0.115-0.12/msg; marketing ₹0.86 [V] | Yes (buttons) | Journey-critical events only (owner replied, visit, price cut on shortlist, agreement, close). ~30-50 msgs per 10-week journey ≈ ₹4-6/user |
| WAHA (current) | same | "free" | Yes | **Migrate away for user-facing sends.** Meta enforcement against unofficial clients since Jan 2026; permanent bans, ~2.2% appeal success; the business number mid-pipeline is the asset at risk [V]. Keep at most for internal admin alerts |
| Email (SMTP) | 21-30% open, 4-7% CTR [V] | Near-free; **current Gmail-style SMTP caps ~500/day, will not survive 10k users; move to SES (~$0.10/1k) or Brevo** [I] | Yes | Digests, documents, agreements, index email |
| In-app | CTR 8.6-17.9% by format [V] | Free | Yes | Everything; immune to opt-in decay. Already built |
| App push | 4.9-10.7% reaction [V] | Free | Yes | N/A: no mobile app yet (Expo is scaffolding). Not a reason to build the app |
| Web push | 0.84% campaign CTR, declining opt-ins, Chrome throttling, Indian OEM suppression [V] | Free | Yes | Skip |
| SMS | 90%+ read [V] | ₹0.10-0.20 + DLT | Weak | OTP only (current use is correct) |

Fatigue: >5 pushes/week demonstrably destructive; 2-5/week already lossy for a non-daily product [V-weak]. Rule: per-user weekly caps, journey-critical events exempt.

---

## 9. Infrastructure end-to-end (Part 9)

Computed from actual schemas (Message, Conversation, Notification, Lead, SavedSearch) with BSON field-name overhead, indexes, and WiredTiger Snappy compression (~2-3x on text) + index prefix compression.

**Per-feature marginal cost:**

| Feature | Storage | DB load | CPU/mem | Third-party | Ops complexity |
|---|---|---|---|---|---|
| Favorites (new collection) | ~100B/doc compressed + 2 indexes; 100k favorites ≈ 15MB | Indexed point reads | nil | none | Trivial |
| Price-cut alerts | Price-change log ~80B/event | One cron scan/15min over changed properties | nil | WhatsApp ₹0.115/send | Low |
| Saved-search matching | Exists | Existing fan-out on property create | nil | as above | None new |
| Chat (mounted) | ~250-300B/msg all-in; 100k msgs ≈ 30MB | Indexed by conversation | Socket.IO ~10KB RAM/conn; 500 concurrent ≈ 5MB; single node fine to ~5-10k concurrent | none | In-process Maps = single-instance constraint (acceptable now; Redis adapter only when adding node #2) |
| Deal room / progress | Fields on Lead (exists) | nil | nil | none | Trivial |
| Locality aggregates | A few thousand docs, <5MB | One nightly cron aggregation | Seconds/night | none | Trivial |
| Analytics events | ~200B/event compressed; 10k MAU × 150 events/mo ≈ 300MB/yr → monthly rollups + TTL raw after 90d | Insert-only, TTL cleanup | nil | none (self-host; do NOT buy analytics SaaS yet) | Low |
| Notifications | Already grows unbounded → **TTL index on read+90d, self-cleaning** | nil | nil | none | Trivial |
| Close-gated reviews | ~500B/review; rare events | nil | nil | none | Moderation time |
| Anti-abuse linkage | 4 extra indexed fields on User + one aggregation | nil | nil | FingerprintJS MIT | Low |

**Scaling tiers (realistic, not hyperscale):**
- **1k MAU (now):** Atlas M0/Flex, one VPS. Everything above fits in <200MB total. Monthly infra delta: ₹0 beyond WhatsApp sends.
- **10k MAU:** Atlas Flex/M2 (~$9-30/mo). Email must move to SES/Brevo (SMTP daily caps are the first real wall, not MongoDB). WhatsApp ≈ 60k utility msgs/mo ≈ ₹7k/mo (the largest new line item; control with channel hierarchy: in-app → email → WhatsApp). Socket.IO still one node.
- **100k MAU:** Atlas M10-M20 ($57-150/mo), SES ₹2-5k/mo, WhatsApp ₹50-70k/mo unless tiered down, second app node → Redis (self-host or Upstash free tier) for Socket.IO adapter + shared presence. Events need the rollup discipline from day one to stay cheap.
- **1M MAU:** queue for notification dispatch (BullMQ), read replicas, CDN on images (already Cloudinary). Budget ₹1-2L/mo. No sharding, no microservices. Decisions deferred until 100k is real.

**The honest headline: no feature in this document requires new infrastructure before ~100k MAU. The first two real costs are a transactional email provider and official WhatsApp API messages.**

---

## 10. Mechanisms we hadn't discussed (Part 10, evaluated)

| Mechanism | Evidence | Verdict |
|---|---|---|
| Shared/collaborative shortlists | Airbnb: 80%+ group decisions, shared wishlists flagship 2024 [V] | **Build** (P1). Also a viral loop: each share recruits a user |
| Owner responsiveness score (visible "responds in ~4h") | Redfin 5-min SLA, Opcity 4-sec calls tied to conversion [V]; opaque-score revolts [V] | **Build** as transparent arithmetic (median first-response time, recomputable by the owner). Never a composite score |
| Listing freshness / days-on-platform + price-history on listing | Portal standard; Zillow pricing research [V] | **Build** (cheap, honest) |
| Close-gated two-sided reviews, simultaneous reveal | Fradkin 2021 [V]; eBay premium 7.6% [V] | **Build** (P1). DealDirect's structural edge: fake-review-proof by construction |
| Society/project pages (CommonFloor wedge) | 700 societies in 6 months, word of mouth [V]; monetization trap [V] | **Build lightweight pages as SEO + supply surfaces; do NOT build society-management software** (MyGate won that; CommonFloor died monetizing it) |
| Rental renewal calendar (11-month cycle) | India rental norm; DealDirect holds close dates + agreements [I] | **Build** (P1). The only true LTV loop available; nobody else holds the verified close date |
| Buyer intent signals shown to owner ("3 weeks active, 12 shortlists in your locality, budget fits") | Lead-quality standard [I] | Build small version in lead card (P2). Privacy: aggregate, not browsing history |
| Endowed-progress deal tracker | Nunes & Drèze 19%→34% [V] | **Build** inside deal room (P1); pre-stamp with stated reason |
| Milestone regret-draws ("you'd have won ₹X") on confirmed visits | Volpp RCTs [V] | Build (P2), counterparty-confirmed events only |
| Negotiation assistance / price intelligence | Locality median anchor is honest; "negotiation AI" is not evidenced | Median anchor only (comes free with locality pages); no AI negotiator [H] |
| Moving checklists / post-close content | Thin evidence for retention | Skip; renewal calendar beats it |
| Market-timing / "good deal" alerts | Requires AVM-grade confidence India data can't support | Skip (dishonest risk) |
| Latent supply (Make Me Move / TemptMe) | Both faded on their home platforms [V/I] | Skip |
| Expert Q&A / forum | NoBroker Forum works for SEO at scale [V] but needs moderation liquidity | Defer to year 2; locality pages first |
| Chat scam detection (token-advance lures, QR patterns) | OLX/FB failures [V]; NCDRC held a classifieds liable where reasonable verification could have prevented fraud [V-weak] | **Build minimum heuristics + report endpoint (already half-built) when chat mounts.** Trust is the product |

---

## 11. Challenging the phase-1 roadmap (Part 11)

| Phase-1 item | Challenge result |
|---|---|
| Chat as the headline | **Demoted.** NoBroker's "25% transaction increase" is a chat-vendor customer story: correlational, promotional [V-weak]. Chat survives as one wall of the deal room because the deal needs a documented channel, not because chat retains. It also imports scam surface (OLX/FB) → ships only with report endpoint + basic lure detection |
| Login streaks (was "fix the broken payout") | **Reversed: delete, don't fix.** Streak evidence is daily-habit-dependent and correlational; property search is bursty and finite. Remove both half-implementations (`LoginTracker` model + `monthlyLoginDays` path) rather than completing them |
| Milestone rewards | **Upgraded with a constraint.** Causal RCT support (goal-gradient, endowed progress, regret lotteries), but milestone value must be non-cashable; cash-equivalence only at verified close (fraud surface) |
| Shagun draw at close | **Restructured.** Lotteries beat fixed pay for frequent behaviors, not one-off events [V]. Close payout becomes fixed and predictable (trust anchor); small draws move to mid-journey confirmed milestones. Shagun branding stays (cultural framing is real value) |
| Price-drop alerts | **Survives strongly** (Rightmove, 25 years) |
| Locality intelligence | **Survives**; 99acres numbers are correlational but Rightmove HPI + SEO mechanics are verified; cost is one cron |
| WhatsApp via WAHA | **Reversed.** Migrate user-facing sends to official API (₹0.115/utility msg); WAHA ban risk (permanent, ~2.2% appeal) against the business number is unacceptable [V] |
| Deal room | **Survives, re-founded.** Justified by endowed-progress/goal-gradient RCTs and system-of-record strategy, not by chat |
| Weekly digest for owners | **Survives** (Zestimate psychology; supply-side responsiveness is where conversion dies) |
| "5 free interests" cap + save-fires-lead | **Confirmed harmful**; separating shortlist from lead is the single highest-priority product change |

---

## 12. Priority matrix (Part 12)

Effort: S <1wk, M 1-3wk, L >3wk. Evidence: A causal/multi-source, B correlational/single-source, C inference/hypothesis.

| # | Mechanism | Problem solved | Segment | Engage | Retain | Convert | Txn | Effort | Infra ₹ | Ops | Abuse | Depends on | Ev. | Competitors | DD advantage | Pri |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Favorites decoupled from leads (remove cap-5 coupling) | Punished core behavior | Buyers | High | High | Med | Med | S | nil | nil | nil | — | A | All | Currently negative vs all | **P0** |
| 2 | First-session saved search + alert opt-in | No captured intent | Buyers | Med | High | Med | Med | S | nil | nil | nil | 1 | A | All | — | **P0** |
| 3 | Price-cut + new-match alerts, deep-linked | No return trigger | Buyers | Med | High | High | Med | M | WhatsApp ₹/msg | Low | Low | 2, official WA | A | Rightmove et al. | — | **P0** |
| 4 | Official WhatsApp API migration | Ban risk on business number | All | — | High | — | — | M | ₹4-6/user/journey | Low | nil | — | A | n/a | — | **P0** |
| 5 | Funnel instrumentation + TTL + broken-reward cleanup (incl. deleting streaks) | Flying blind; silent failures | Platform | — | — | — | — | S-M | nil | nil | nil | — | A | n/a | — | **P0** |
| 6 | Owner weekly digest + visible response time | Supply-side conversion killer | Owners | Med | High | High | High | M | email | Low | nil | 5, SES | B | Zillow-adapted | Owner-direct = owner IS the agent | **P1** |
| 7 | Deal room: progress tracker + chat + visits + agreement | Deal invisible to platform | Both | High | Med | High | High | L | nil | Med | Med | 3, scam heuristics | A (progress) / B (chat) | None in India in this form | Verified-close position | **P1** |
| 8 | Close-gated two-sided reviews | Trust content; fake-proof | Both | Med | Med | High | Med | M | nil | Moderation | Low | verified closes | A | None (structural edge) | Only verified closes review | **P1** |
| 9 | Shared shortlists | Group decisions | Buyers | High | Med | Med | Low | M | nil | nil | Low | 1 | B | Airbnb | Viral loop | **P1** |
| 10 | Locality price pages + monthly index | SEO + research destination | All | Med | Med | Med | Low | M | cron | Low | nil | 5 | B | 99acres/Rightmove | Zero-brokerage data neutrality | **P1** |
| 11 | Reward restructure: fixed close anchor + non-cash milestones + anti-abuse stack | Timing + fraud | Both | Med | Med | Med | High | M | nil | Review time | Managed | 7 | A | None | Unique subsidize-disclosure model | **P1** |
| 12 | Rental renewal calendar (month-10 hooks) | Zero LTV loop today | Both | Low | High | Med | High | S-M | nil | nil | nil | verified closes | C (strong) | None | Only holder of close dates | **P1** |
| 13 | Listing price guidance vs locality median | Mispricing slows closes | Owners | Low | Low | High | Med | S | nil | nil | nil | 10 | B | Zillow research | — | P2 |
| 14 | Buyer intent signals in lead card | Owner can't triage leads | Owners | Low | Low | Med | Med | S | nil | nil | Privacy care | 5 | C | — | — | P2 |
| 15 | Milestone regret-draws on confirmed visits | Mid-journey motivation | Both | Med | Med | Med | Med | S | tiny EV | Low | Managed | 7, 11 | A (mechanism) | None | Shagun brand | P2 |
| 16 | Society/project SEO pages | Supply acquisition | Owners | Low | Med | Low | Low | M | nil | Low | nil | 10 | B | CommonFloor | — | P2 |
| 17 | EMI/affordability calculators | Session depth | Buyers | Med | Low | Low | Low | S | nil | nil | nil | — | B | All | — | P2 |
| 18 | Builder/owner quality tiers | Repeat supply retention | Builders | Low | Med | Med | Med | M | nil | Low | Med | 8 | B | eBay TRS | — | P2 |
| 19 | Forum / expert Q&A | SEO at scale | All | Med | Med | Low | Low | L | nil | High | Med | liquidity | B | NoBroker | — | P3 (year 2) |
| 20 | Commute overlays | Research depth | Buyers | Low | Low | Med | Low | M | API fees | Med | nil | Mappls budget | C | Big portals | — | P3 |
| 21 | AVM / fair-price estimate | — | — | — | — | — | — | L | High | High | Trust risk | No data substrate | A (against) | Zillow (US only) | — | **P3 avoid** |
| 22 | Streaks / daily-login rewards | — | — | — | — | — | — | S | nil | nil | Farming | — | A (against fit) | Duolingo (wrong domain) | — | **P3 avoid** |
| 23 | Contact masking / number blocking | — | — | — | — | — | — | M | nil | High | UX damage | — | A (against) | Airbnb (fails anyway) | — | **P3 avoid** |
| 24 | Mobile app build-out | — | — | — | — | — | — | XL | High | High | — | — | C | — | — | P3 (web first) |

---

## 13. The ideal journey (Part 13)

**FIRST VISIT** (often SEO/locality page): see honest data + verified-listing markers. Do: browse without login walls. Capture: locality + budget from browsing (anonymous session). Return reason: none yet, so the exit ask is one thing only: save a search / shortlist (soft prompt, not a gate). No: forced signup to view listings, no popup carpet-bombing.

**FIRST SESSION → FIRST PROPERTY**: see price vs locality median, price history, freshness, owner verification badge, owner response time. Do: shortlist (no owner notified), compare. Capture: shortlist composition (the real preference signal). Notification: none yet. No: "interest" firing a lead from a casual save.

**SHORTLIST**: shareable with family. Capture: co-searcher emails (viral). Return: price-cut + status alerts on every shortlisted home. Reward: first saved search = small points + endowed progress ("your search profile is 2 of 6 steps complete, since we already verified your phone").

**RETURN** (day 2-70): alert → deep link → listing → adjacent discovery (similar homes, locality page). Learn: which alert types convert to sessions (per-user channel tuning). No: more than ~2-3 outbound touches/week per user, ever.

**CONTACT** (intent moment): explicit "contact owner" converts shortlist → lead (cap fine here); owner gets buyer context card (active weeks, locality focus, budget fit). Notification: owner via WhatsApp utility + in-app; SLA clock starts (median response time is public). Reward: enquiry points (existing).

**DEAL ROOM** (auto-created at mutual contact): progress tracker pre-stamped (step 1-2 done, with reason), chat, visit scheduler, document checklist. Both parties see the same room. Learn: stage transitions + drop-off points = the platform's conversion funnel. No: opaque scores of people; no unremovable nagging.

**VISIT**: schedule in room; reminders T-1d/T-2h (WhatsApp utility); both parties confirm afterward → milestone draw entry (non-cash). Post-visit: 2-tap feedback (interested / not / thinking) → auto lead-status update, owner sees honest signal. Learn: visit completion + post-visit intent, the strongest conversion predictor [H, instrument to verify].

**NEGOTIATION**: neutral anchor visible (locality median trend). No AI negotiator. Capture: nothing invasive; status only.

**AGREEMENT**: Gemini generation in the room; both e-review; HMAC-signed record. Reward: milestone points (non-cash). This step converts "conversation elsewhere" back into the record; the agreement is the bridge product, free inside a deal room (paid standalone later for outsiders).

**VERIFICATION**: owner uploads registry/stamp artifacts; two-sided independent attestation; anti-abuse checks (linkage, velocity, account age); admin review. Holding window framed as registry confirmation.

**REWARD**: fixed, predictable close payout (both sides) + shagun bonus draw on top; redemption menu leads with platform credits/fee waivers/vouchers (breakage + in-kind economics). Expiry: activity-based lapse (~90-180d inactive), never punitive calendar cliffs.

**REVIEW**: simultaneous-reveal, 14-day window, process-focused (accuracy, responsiveness, seriousness). Published on listing/owner profile. This is the trust flywheel competitors structurally cannot copy without a verified-close event.

**REFERRAL**: at the reward-claim high point: "gift a friend a head start" (endowed-progress framing for the invitee, milestones 2-3 finally wired).

**SECOND SEARCH** (the loop): rentals: month-10 renewal hook (renew agreement or relist/search again); sales: locality "one year later" email + points still alive. Owner side: relist flow with history pre-filled.

---

## 14. Six-month roadmap (Part 14)

| Month | Build (few things) | Explicitly NOT | Success criteria |
|---|---|---|---|
| **M1: Repair + see** | Funnel events (Mongo events collection + rollup cron); Favorites decoupled (model + UI swap); fix `upload_5_photos` mapping, referral milestone wiring; DELETE streak code; TTL on notifications; SES/Brevo for email; start official WhatsApp API verification (Meta business verification takes weeks: start now) | Chat mounting; any new reward spend | Baseline dashboard live: shortlist rate, D7 return, response times measurable |
| **M2: Return spine** | Saved-search prompt in first session; price-change log + price-cut alerts; deep links; honor notify flags; per-user weekly notification caps; owner weekly digest (email) | Locality pages (data not ready); reviews (no flow to gate) | Saved-search creation ≥25% of new active buyers [H target]; alert→session CTR >15% email / >35% WhatsApp [H]; D7 new-buyer return +30% relative [H] |
| **M3: Deal room v1** | Room shell on Lead; progress tracker (endowed pre-stamp); mount chat inside room only (with report endpoint + token-advance lure warnings); visit scheduler + reminders + both-confirm | Floating site-wide chat widget; milestone draws (next month); video anything | Lead→room conversation ≥40% [H]; visit-scheduled per lead ≥15% [H]; owner median first response < 12h |
| **M4: Trust layer** | Close-gated reviews (simultaneous reveal); listing verification badges; reward restructure (fixed close anchor + non-cash milestones) + anti-abuse fields (device hash, linkage query, velocity rules, holding window) | Owner tiers; forum | First reviews published; zero payout to linked accounts; verified-listing share rising |
| **M5: Data products** | Nightly locality aggregation; locality pages (SEO); price guidance at listing creation; price vs median on listings; EMI calculator; first monthly index email (internal dry run) | Public press push (credibility needs 1-2 more months of data); AVM anything | Organic impressions on locality pages; % new listings priced within guidance band; digest CTR |
| **M6: LTV + referral** | Rental renewal calendar (month-10 hooks); referral revamp at reward-claim moment; shared shortlists; points expiry + redemption nudges; first public index release | Agreement-as-a-service for outsiders (quarter 3 experiment); mobile app; multi-city marketing | Renewal-hook open/action rate; referral invites per close; repeat-owner relist rate |

---

## 15. Metrics (Part 15)

Full set: DAU/WAU/MAU + stickiness (WAU/MAU); D1/D7/D30 by cohort AND by journey stage (searcher cohorts measured within their 10-week window, not calendar-blind); sessions/user/wk; properties viewed/session; shortlist rate (first session); saved-search rate; alert CTR→session; interest (lead) rate; owner first-response median + % <24h; room conversation rate; messages/lead; visit-scheduled rate; visit-completion rate; post-visit intent rate; agreement generation rate; agreement completion rate; verified closes/mo; reward ₹ per verified close; review submission rate; referral invites/close + K-factor; CAC (≈0 today, organic); LTV (rentals: renewal-cycle revenue potential; sales: referral value).

**The 8 that matter now:**
1. First-session activation: % of new buyers who shortlist or save a search
2. D7 searcher return rate
3. Owner median first-response time (the supply-side conversion killer)
4. Lead → visit-scheduled rate
5. Alert → session CTR by channel
6. Verified closes per month (the north star; everything else is upstream of it)
7. Reward + review cost per verified close
8. WAU/MAU stickiness

Experiments (sequenced): saved-search prompt placement (soft vs exit-intent); alert channel per event type (email vs WhatsApp holdout); endowed pre-stamp vs empty tracker (the Nunes & Drèze replication on your own funnel); fixed vs draw milestone reward framing; digest weekly vs biweekly.

---

*Full evidence trail in the three research-track reports (session transcripts) and phase-1/2 conversation. Where a number carries [H], it is a target to calibrate after M1 instrumentation, not a promise.*
