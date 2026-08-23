# Semantic search for DealDirect Mobile — investigation and recommendation

Date: 2026-08-24. Status: **investigation complete, nothing implemented in the app.**
Nothing in `dealdirect-mobile/` was changed. No dependency was added. The backend was read
(public GET endpoints only) and not modified.

Benchmark harness in this folder: `parse.mjs`, `queries.mjs`, `run.mjs`, `ablate.mjs`,
`corpus-2026-08-24.json` (the live corpus as fetched). To reproduce:
`npm i @xenova/transformers && node run.mjs && node ablate.mjs`.

---

## The finding that decides this

**Every property description in the live corpus is machine-generated from the structured fields.**

All 31 listings. Every description is `<title> | <sqft>`, and the title is itself
`<BHK> <propertyType> for <Rent|Sale> in <locality>` — composed by
`AddPropertyContent.generateTitle()`. Median description length is 56 characters. There is no
free text anywhere in the consumer corpus:

```
 1. Showroom for Rent in Lake Town              → "Showroom for Rent in Lake Town | 375 sq.ft"
 5. 5+ BHK Villa for Sale in Pune City Center   → "5+ BHK Villa for Sale in Pune City Center | 3000 sq.ft"
15. 1 BHK Apartment / Flat for Rent in Koramangala → "1 BHK Apartment / Flat for Rent in Koramangala | 555 sq.ft"
```

A semantic index is a way of finding meaning that structured fields do not capture. **There is
no such meaning in this corpus.** Embedding these documents produces a vector representation of
the same six fields the filters already query directly. That is not an argument about model
quality; it is an argument about information content.

The one exception is builder projects, which have genuine hand-written text (4 of 5 describe
connectivity, developers and amenities in prose) — but there are 5 of them.

---

## 1. Current search architecture

Free text reaches the server in exactly one form: `params.search`, a case-insensitive regex over
`title, description, address.city, address.area, address.locality`
(`src/features/search/filters.ts:16-18`). There is no relevance score anywhere in the system —
`PagedEnvelope` is `{data, total, page, pages}`, and `sort` offers only
`newest | priceAsc | priceDesc`.

**`SearchFilters`** (`filters.ts:138-173`) splits cleanly in two:

| Sent to the server (`toSearchParams`, :218-230) | Applied client-side (`matchesClientFilters`, :379-391) |
|---|---|
| `search`, `sort`, `listingType`, `priceFrom`/`priceTo` | `city`, `categoryName`, `furnishing`, `constructionStatus`, `bhk` |

The client-only half exists because the server's equivalents are unusable, and the file documents
each rejection with measurements taken against production on 2026-08-03: `category`/`propertyType`
are ObjectId matches against refs that are "null on 15 of 36 live listings and wrong on the rest";
`city` is an exact case-sensitive match against a column holding both "Bangalore" and "Bengaluru";
`buildingType` and `size` "do not exist on the schema".

**The bounded-fetch pattern** (`hooks.ts:123-162`) is the important precedent. When any client-only
filter is active, the app fetches **one page of 100** from `/properties/search` and filters it in
memory — no pagination, `total` becomes the post-filter count. The whole corpus fits in that page
today. Two hand-written client-side scorers already run over the same shape of pool
(`related.ts:120-138`, `:229-240`).

**The binding constraint is the rate limiter**: `/properties/search` and `/properties/suggestions`
share **20 requests per minute, keyed on IP**, which on Indian carrier NAT is shared with strangers.
This is why suggestions are debounced 450ms with a 2-char floor, why the filter sheet commits on
Apply rather than per tap, and why any design that issues a request per keystroke is dead on arrival.

**What the list views can actually see**: `PropertySummary` — the type every card renders from —
carries **no `description`, no `amenities`, no `landmark`, no `nearby`**. Those exist only on
`PropertyDetail`, fetched one listing at a time. The raw `/search` response does contain them; the
adapter drops them.

---

## 2. Where semantic understanding could help — and where it cannot

I split the 59-query benchmark by kind. Current search, measured:

| Query kind | n | returns nothing | recall@5 |
|---|---|---|---|
| exact (`3 bhk`, `HSR Layout`, `showroom`) | 10 | 0/10 | 100% |
| synonym (`flat`, `home`, `godown`) | 8 | 3/8 | 51% |
| shorthand (`2bhk`, `1 cr`, `ready to move`) | 10 | **10/10** | **0%** |
| intent (`good family home`, `investment property`) | 10 | **10/10** | **0%** |
| natural language (full sentences) | 10 | **10/10** | **0%** |
| mixed (`3 bhk in Yelahanka under 1.5 crore`) | 9 | 7/9 | 25% |

**The current search works only for literal queries.** Everything else returns an empty screen.
Verified live against production: `"home"` → 0 results, despite 22 residential listings, because
no title contains the word "home" — they say "Apartment / Flat" or "Independent House".
`"2bhk"` → 0, purely for the missing space.

But look at *why* each failure happens. They are lexical and numeric, not semantic:

- `"home"` → a synonym the vocabulary does not contain.
- `"2bhk"` → a tokenisation problem.
- `"1 cr"`, `"under 80 lakhs"` → money that is never parsed into `priceFrom`/`priceTo`.
- `"3 bhk near metro under 1.2 crore"` → the whole sentence is sent as one regex, so it matches
  nothing; the three extractable constraints are never extracted.

Every one of these is fixed by **understanding the query**, not by embedding the documents.

---

## 3. Recommended model

**For the corpus: none, yet.** See §10.

Had the corpus justified it, the research (full write-up available separately) points at
**Sentence Transformers static embedding models** rather than a transformer, because they change
the integration cost completely:

| | |
|---|---|
| `minishlab/potion-base-8M` | 256-dim, ~7.5 MB int8, MIT, 92% of all-MiniLM-L6-v2 on MTEB |
| `sentence-transformers/static-retrieval-mrl-en-v1` | 1024-dim truncatable to 256, Apache-2.0, 87% of all-mpnet-base-v2 |

These are an embedding-bag lookup plus mean pooling — **no transformer forward pass, no ONNX, no
WASM, no native module**. Paired with `@huggingface/tokenizers` (pure JS, zero deps, Apache-2.0),
a query encoder is roughly twenty lines running in Hermes in under a millisecond. Mozilla ships
this exact pattern in Firefox.

What is **not** viable here: stock Transformers.js in the RN runtime (Hermes on RN 0.81 has no
`WebAssembly`, and the library uses `import.meta.url`); `@tensorflow/tfjs-react-native` (last
published 2023, peer-depends on packages removed in Expo SDK 50); `cactus-react-native` (peer
`react-native-nitro-modules ^0.33.9` conflicts with the `0.36.4` this app ships for MMKV v4).

The credible native option, if ever needed, is **`react-native-executorch` 0.9.3** (MIT, Software
Mansion — the Reanimated team) with `all-MiniLM-L6-v2`: 384-dim, **21 ms and 95 MB peak on a
flagship Snapdragon 8 Gen 3**, so plausibly 60-100 ms and the same memory on the mid-range Android
this app targets. It needs a prebuild and a dev-client rebuild.

---

## 4. Architecture — what I would actually build

The insight that makes this cheap: **the parser's output is a `SearchFilters` object, and the app
already knows how to execute one.** No new retrieval machinery, no index, no vector store.

```
"3 bhk family home near metro under 1.2 crore in whitefield"
                          │
                 parseQuery()  ← deterministic, ~200 lines, no model
                          │
        ┌─────────────────┴──────────────────┐
        │                                    │
  HARD constraints                    SOFT signals
  bhk: 3                              ["family", "metro"]
  maxPrice: 12_000_000                        │
  category: residential                       │
  locality: whitefield                        │
        │                                     │
        ▼                                     ▼
  EXISTING SearchFilters              ranking hint only,
  → existing feed, existing           never gates a result
    server params, existing
    matchesClientFilters
        │
        ▼
  results, or a labelled relaxation
```

Two additive changes to `SearchFilters`, both mobile-only and both backward compatible:

1. `priceMin` / `priceMax` as exact rupee bounds alongside the existing five bands. The server
   already accepts arbitrary `priceFrom`/`priceTo` (verified), so `"under 1.2 crore"` can be sent
   exactly rather than snapped to a band that does not exist.
2. `propertyType` as a **client-only** filter matched against the denormalised `propertyTypeName`
   string — the field the codebase already establishes as reliable, never the corrupt ObjectId ref.

Everything else the parser produces maps onto fields that exist today.

---

## 5. Hybrid ranking strategy

Hard constraints **filter**. Soft signals **order**. They never trade off against each other, and
no similarity score can promote a listing that fails a constraint.

```
candidates = existing feed (server params applied)
eligible   = candidates.filter(satisfies HARD constraints)
ranked     = eligible.sort(by soft score, then existing sort)
```

The soft score uses only information present in the data — amenities, locality, construction
status, furnishing, price relative to the stated ceiling. It never infers rental yield or
appreciation, because the backend records neither.

---

## 6. Hard constraints — never overridable

`bhk` · `priceMin`/`priceMax` · `listingType` (rent vs sale) · `city` · `locality` (when resolvable
against known inventory) · `categoryName` (residential vs commercial) · `propertyType` ·
`constructionStatus` (when explicitly stated).

The benchmark measures exactly this. **Semantic-only ranking violates a stated constraint in 55%
of the results it shows** — it returns 5 apartments for `"warehouse"`, and ranks a 4 BHK above
valid results for a 2 BHK query. That arm is disqualified on evidence, not on principle.

---

## 7. Performance

| | Measured here (desktop) | Expected on mid-range Android |
|---|---|---|
| Deterministic parse | < 0.1 ms | < 1 ms |
| Corpus embed, 31 docs (MiniLM) | 323 ms (10.4 ms/doc) | ~2-4 s, once |
| Query embed (MiniLM) | 2.4 ms | 60-100 ms |
| Cosine over 31 × 384 | microseconds | microseconds |
| Model load | 157 ms warm / 5.4 s cold | 1-3 s, plus a 23 MB download |

The parser costs nothing and can run on every commit. Anything model-based must be lazy-loaded
behind the existing search, which is exactly the fallback the brief requires.

---

## 8. Benchmark — 59 queries, live corpus, three arms

Corpus: the 31 live listings, fetched 2026-08-24. Model: `Xenova/all-MiniLM-L6-v2`, quantized,
384-dim. Ground truth is hand-labelled per query, independent of the parser, so parser accuracy is
measured rather than assumed.

| metric (top-5) | A: current | B: semantic-only | C: hybrid |
|---|---|---|---|
| queries returning nothing | **42/59** | 0/59 | 20/59 |
| hard-constraint violations | 22 | **161** | 20 |
| violation rate of shown results | 46% | **55%** | **12%** |
| mean recall@5 | 21% | 80% | **87%** |
| answerable queries missed entirely | **32/41** | 0/41 | **3/41** |

Parser agreed with the hand label on 52/59.

### The ablation that matters

All three arms below use the **same** deterministic gate; only the ranker differs.

| arm | recall@5 | violations |
|---|---|---|
| C — gate + **semantic ranking (the model)** | 87% | 20 |
| E — gate + **BM25 lexical ranking (no model)** | **87%** | **20** |
| D — gate + newest-first (**what the app already does**) | 83% | 24 |

**The embedding model buys nothing over BM25, and four points of recall over no ranking at all.**
The result *set* is identical in all three arms on every query — the gate decides membership, the
ranker only decides order. The entire 21% → 87% improvement comes from the deterministic parser.

That is the whole finding, and it follows directly from §0: you cannot retrieve meaning from
documents that contain none.

### A correction worth recording

My first run reported 94% recall for the hybrid arm. It was wrong: my type canonicaliser tested
`/house/` before `/warehouse/`, so every warehouse and penthouse was silently classified as a
house. The numbers above are after the fix. I mention it because it is exactly the class of bug
that makes a benchmark flatter the thing being sold.

---

## 9. Risks

**Accuracy** — the parser is the whole system, so its failures are the product's failures. All 9
disagreements in the run are lexicon bugs, not architecture: `"flats"` and `"bungalow"` missing
from the residential word list; `"rental income"` read as *rent* when it means *buy for rental
income*; `"close to office"` triggering the commercial category. Each is a line in a table.

**Over-constraining** — my naive gate returns nothing on 20 of 59 queries. Only 3 of those are
wrong (the rest have genuinely no matching inventory), but it proves the gate must relax
*explicitly and visibly*, never silently: show the constraint that emptied the screen, then offer
"closest matches" with the relaxed constraint named.

**Data freshness** — embeddings would need invalidation on every listing edit. The parser has no
such coupling; the only thing it must track is the locality lexicon, derivable from the corpus.

**Corpus growth** — the entire client-side design rests on the 100-row bounded pool. At ~500 live
listings that ceiling breaks for search the same way it already breaks for city counts, and the
honest fix is a backend aggregation, not a bigger page.

**Memory / bundle / Expo** — all zero for the parser. For a model: 23-95 MB peak, a native rebuild
for ExecuTorch, and Expo Go stops working. This is the main reason not to take it on speculatively.

**Licensing** — clean for everything considered (MIT / Apache-2.0). EmbeddingGemma is the one
exception, under Gemma Terms of Use rather than an OSS licence.

---

## 10. Recommendation

**B — build the POC, but not the one that was asked for.**

Specifically: **build the query-understanding layer, and do not ship an embedding model.**

The measured case for query understanding is overwhelming: it takes the app from answering 9 of 41
answerable queries to answering 38, and from a 46% constraint-violation rate to 12%. It needs no
model, no native module, no rebuild, no backend change, no new dependency, and it degrades to
today's behaviour by deleting one function call.

The measured case for embeddings, on this corpus today, is that they perform identically to BM25
and return the same set of results as sorting by date. That is not a reason to call semantic search
a bad idea — it is a reason to say the corpus is not ready for it. Two things would change that:

1. **Real descriptions.** The listing form should encourage or require prose. The moment owners
   write "quiet lane, walking distance to the metro, south-facing", there is meaning to retrieve
   and this decision should be revisited immediately.
2. **Builder projects in search.** They already have hand-written descriptions, connectivity notes
   and amenities. They are absent from `/properties/search` by design, and they are the one part of
   the inventory where semantic retrieval would work today — on 5 documents.

My recommendation is therefore to ship the parser as the pilot, instrument it, and treat the
embedding question as **deferred pending corpus quality** rather than rejected. The parser is also
the part that transfers to the website unchanged: it is pure functions over a query string, with no
React Native dependency of any kind, which is exactly the "extractable search intelligence" the
long-term architecture calls for.

**What I would not do:** ship an embedding model now to be able to say the app has semantic search.
It would add a native dependency, a model download, a cold-start penalty and a memory ceiling on
low-end Android, in exchange for a reordering of results that the benchmark cannot distinguish from
sorting by date.
