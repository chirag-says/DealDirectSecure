# DealDirect mobile: what the app collects, and what to declare

Date: 2026-09-05. Derived by reading the code, not by recalling the design. This is the input to three separate forms that must agree with each other and with the app:

1. **Google Play Data safety** (Play Console)
2. **Apple App Privacy** nutrition label (App Store Connect)
3. The **privacy policy** at `dealdirect.in/privacy`, which both stores require to be reachable and current

They must agree. A mismatch between the form and the app's behaviour is one of the two most common causes of a rejected or pulled listing, and it is the kind of mistake that is found after launch.

Phases 0, 3 and 5 of the upgrade plan added four data flows that did not exist when the checklist was first written. **The existing privacy policy predates all of them.** They are marked NEW below.

---

## 1. What the app actually collects

| Data type | Where it comes from | Purpose | Linked to the account? | Used for tracking? |
|---|---|---|---|---|
| Name, email, phone | Registration (`POST /users/register`) | Account, and the owner sees a buyer's contact when they enquire | Yes | No |
| Password | Registration and login | Authentication. Hashed with bcrypt, never returned by any endpoint | Yes | No |
| Date of birth, gender, address, bio, profile photo | Profile screen, all optional | Profile | Yes | No |
| Property photos | Camera and photo library, listing wizard | The listing itself, public once approved | Yes | No |
| Approximate location | `expo-location`, foreground only, on demand from the city picker | Preselecting a city and showing nearby homes. Never stored as coordinates against the account; used to resolve a city name | No | No |
| Property coordinates | Typed or picked by the owner on the listing map | Shown on the public listing | Yes (to the listing) | No |
| Messages | The deal room chat, when enabled | Buyer-owner conversation about one property | Yes | No |
| Identity and ownership documents | Deal-closure verification upload | Admin verification of a closed deal | Yes | No |
| **Push token** NEW | `expo-notifications`, after the OS permission is granted | Delivering the notifications the person asked for (price drops, visits, deal events) | Yes | No |
| **Installation id** NEW | Generated once on the device (`src/analytics/installationId.ts`) | Two uses: attributing usage events before sign-in, and the fraud check below | Partly | No |
| **Device hash** NEW | The same installation id, posted to `POST /users/device` | Detecting one person operating both sides of a "deal" to claim both rewards | Yes | No |
| **Usage events** NEW | `POST /events`, a closed list of 16 names with whitelisted properties | Product analytics: which parts of the journey work. Raw rows expire after 90 days; only daily counts survive | Partly | No |
| Crash reports | Sentry, only when a DSN is configured | Diagnosing crashes. `sendDefaultPii: false`; the payload carries the account id and role and nothing else | Yes | No |

**Nothing here is used for tracking in either store's sense.** There is no advertising identifier, no third-party ad SDK, no cross-app or cross-site profiling, and no data broker. Both forms should answer "no" to tracking. Say so plainly and it stays true only as long as nobody adds an ad SDK.

---

## 2. What is shared, and with whom

Every recipient below is a processor doing a job for DealDirect, not a party that gets to keep or sell anything.

| Recipient | What reaches them | Why |
|---|---|---|
| Cloudinary | Listing photos, profile photos, verification documents | Image storage and delivery |
| Expo Push Service, then FCM/APNs | The push token and the notification title and body | Delivering a notification to the device |
| Brevo (or the configured SMTP host) | Email address, the message body | Transactional email |
| Meta WhatsApp Cloud API | Phone number, the message body | Journey-critical messages, when the person has not opted out |
| Google Gemini | Agreement inputs, when an agreement is generated | Drafting the agreement text |
| Hubble | An SSO token and the points balance | Reward redemption, inside their SDK |
| RewardPort | Nothing personal | The rewards catalogue |
| Sentry | Crash stack, account id and role | Crash diagnosis |
| **The other party to a deal** | The buyer's name, email and phone reach the owner on enquiry. The owner's phone reaches the buyer only after the owner engages | This is the product: the two sides deal directly |

That last row is the one to state most plainly in the privacy policy. Disintermediation is the whole proposition, so a buyer's contact details genuinely do reach a stranger. It is not a leak, it is the feature, and it should read as a deliberate design rather than a footnote.

---

## 3. Deletion

Both stores require an in-app path; Google also requires a web path.

- In-app: Settings → Delete account. Password, typed confirmation, and a biometric confirm.
- What is deleted: the account, its listings and their images, sessions, saved searches, notifications, messages, the reward wallet, referrals, push tokens, the outbound log, usage events, the shortlist and its share links. Sixteen collections, enumerated in `backend/utils/aggregateDelete.js` and asserted by a test.
- What is deliberately retained, and why the policy must say so: leads, agreements, transaction verifications, campaign memberships and project bookings. These are the other party's record of a transaction, and a signed agreement is a legal document that one side cannot unilaterally erase.
- Web path: confirm `dealdirect.in` offers deletion or a deletion-request route before submitting. **Open item.**

---

## 4. Permissions, and the disclosure each one needs

| Permission | When it is asked | The justification a reviewer will look for |
|---|---|---|
| Notifications | At the first shortlist save or saved search, never at launch | The person has just asked to be told when something changes. That is the disclosure, and it is why the prompt is placed there |
| Camera | When photographing a listing | Purpose string set, reads as a user benefit |
| Photo library | When adding listing images | Purpose string set |
| Location (foreground) | Only from "Use my location" in the city picker | Google requires a prominent in-app disclosure BEFORE the prompt and a Permissions Declaration in the console. The soft-ask copy is in `CityPickerSheet`; check it says what is collected and why before the OS dialog appears |
| Face ID / biometrics | Confirming account deletion | Confirmation only, never authentication: the server still requires the password |

No background location. No contacts. No calendar. No microphone. Keeping that list short is worth more at review than any wording.

---

## 5. What still needs a person, not code

- [ ] Rewrite `dealdirect.in/privacy` to cover the four NEW rows in §1 and the retention split in §3. The current text predates push, the device hash and usage events.
- [ ] Fill the Play Data safety form from §1 and §2.
- [ ] Fill the Apple App Privacy label from the same two sections.
- [ ] Confirm a web deletion path exists, or publish a deletion-request URL.
- [ ] Google Permissions Declaration for foreground location, with the disclosure screenshot.
- [ ] IARC and Apple age-rating questionnaires. A property marketplace with user-generated listings and, when enabled, chat.
- [ ] Support email and marketing URL for both listings.

## 6. The one that could change scope

Apple guideline 3.1.1 on the rewards flow is still unresolved and is the item most likely to force a change late. Points earned for in-app actions and redeemed for vouchers through a third-party SDK can read as either "not a purchase" or "digital content that must use in-app purchase", depending on the reviewer. Decide the position and prepare the argument before the first submission rather than after a rejection: the strongest framing is that no user ever spends money in the app, points are earned rather than bought, and redemption happens outside it.
