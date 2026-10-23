import Link from "next/link";
import LegalDocument, { LegalTable, ToConfirm, legalLink } from "../../../components/Legal/LegalDocument";
import { DRAW_POOLS, FIXED_POINTS, LIMITS, TIERS, poolSummary } from "../../../data/rewardsProgramme.mjs";

/*
 * DealDirect Rewards terms. Every rule here is the rule the reward engine
 * applies (backend services/rewardService.js, controllers/propertyController
 * claimDealReward, controllers/hubbleController, jobs/pointsExpiry.js), and
 * every number comes from data/rewardsProgramme.mjs, which the backend test
 * tests/rewards-website-contract.test.js holds to the engine.
 *
 * Points only: no rupee values and no odds, by product decision (2026-10-23).
 * Draft for legal review; <ToConfirm> marks a commitment still to be agreed.
 */

const UPDATED = "23 October 2026";
const pts = (n) => `${n.toLocaleString("en-IN")} points`;
const range = (key) => {
  const { rows, top } = poolSummary(DRAW_POOLS[key]);
  return `${pts(rows[0].points)} to ${pts(top.points)}`;
};

const drawRows = [
  [
    "Close a verified deal",
    "When our team has verified a sale or letting made through DealDirect, the owner and the buyer or tenant may each claim one draw, once per deal.",
    range("property_sale"),
  ],
  [
    "List your first property",
    "One draw when you publish your first listing. Once per account: deleting a listing and listing again does not earn another draw.",
    range("property_posting"),
  ],
  [
    "Send an enquiry",
    `One draw per enquiry (“I'm interested”), for up to ${LIMITS.enquiryRewardsPerDay} enquiries a day.`,
    range("property_enquiry"),
  ],
];

const bonusRows = [
  ["Publish a listing with 5 or more photos", "Counted when the listing is created, once per listing.", pts(FIXED_POINTS.upload_5_photos)],
  ["A friend signs up with your referral code", "Paid to the referrer.", pts(FIXED_POINTS.referral_signup)],
  ["Your referred friend makes their first listing or enquiry", "Paid to the referrer, once per friend.", pts(FIXED_POINTS.referral_first_action)],
  ["Your referred friend closes a verified deal", "Paid to the referrer, once per friend.", pts(FIXED_POINTS.referral_deal_closure)],
  ["Report a listing", "One report per listing while it is under review.", pts(FIXED_POINTS.report_property)],
];

const tierRows = TIERS.map((t, i) => {
  const next = TIERS[i + 1];
  return [
    t.name,
    next ? `${t.min.toLocaleString("en-IN")} to ${(next.min - 1).toLocaleString("en-IN")} lifetime points` : `${t.min.toLocaleString("en-IN")}+ lifetime points`,
    t.multiplier === 1 ? "Standard" : `+${Math.round((t.multiplier - 1) * 100)}% on every reward`,
  ];
});

const sections = [
  {
    id: "programme",
    title: "The programme",
    body: (
      <>
        <p>
          DealDirect Rewards (the &ldquo;Programme&rdquo;) is run by Agrawal Business Network LLP
          (&ldquo;DealDirect&rdquo;) for users of the DealDirect website and app. These terms add to our{" "}
          <Link href="/terms" className={legalLink}>Terms of Use</Link>, which also apply. Taking part is free and
          needs a DealDirect account.
        </p>
        <p>
          You earn points for the actions below. Points have <strong>no cash value</strong>: they cannot be exchanged
          for money, withdrawn, or transferred to another account. You can spend them only in the rewards store.
        </p>
      </>
    ),
  },
  {
    id: "draws",
    title: "Actions that earn a draw",
    body: (
      <>
        <p>
          For each of these actions, the system picks one prize at random from that action&rsquo;s prizes. Smaller
          prizes come up most often and the top prizes are rare. The prize you receive is shown to you straight away and
          added to your wallet.
        </p>
        <LegalTable caption="Actions that earn a draw" head={["Action", "Rules", "Prizes"]} rows={drawRows} />
        <p>
          A deal reward can be claimed only after the deal&rsquo;s verification is approved. Where our checks need
          more time, the reward is reserved and can be claimed once the confirmation window has passed, which may be up
          to 60 days.
        </p>
      </>
    ),
  },
  {
    id: "bonuses",
    title: "Fixed bonuses",
    body: <LegalTable caption="Fixed bonuses" head={["Bonus", "Rules", "Points"]} rows={bonusRows} />,
  },
  {
    id: "tiers",
    title: "Tiers",
    body: (
      <>
        <p>
          Your tier is set by the total points you have ever earned, and rises automatically. From then on its bonus
          multiplies every reward you receive, draws and fixed bonuses alike. Points you spend do not lower your tier.
        </p>
        <LegalTable caption="Tiers" head={["Tier", "Lifetime points", "Bonus"]} rows={tierRows} />
      </>
    ),
  },
  {
    id: "redeeming",
    title: "Spending points",
    body: (
      <ul>
        <li>
          Points are spent on gift cards and vouchers in the rewards store in your account. The store is provided by
          our partner Hubble, and each item shows its price in points.
        </li>
        <li>
          Gift cards and vouchers are delivered digitally and are subject to Hubble&rsquo;s terms and the issuing
          brand&rsquo;s terms, including any expiry date on the voucher itself.
        </li>
        <li>If an order fails, the points spent on it are returned to your wallet.</li>
        <li>Items in the store, and their prices in points, may change as brands and stock change.</li>
      </ul>
    ),
  },
  {
    id: "fair-play",
    title: "Fair play",
    body: (
      <>
        <p>Rewards are for genuine use of DealDirect. You may not earn points by:</p>
        <ul>
          <li>posting fake, duplicate or other people&rsquo;s listings, or listing as a broker or agent;</li>
          <li>sending enquiries you do not mean, or enquiries arranged between accounts;</li>
          <li>reporting listings without a genuine reason;</li>
          <li>referring yourself, or creating or controlling more than one account;</li>
          <li>declaring a deal that did not happen, or any other misuse of the Platform.</li>
        </ul>
        <p>
          Where we find any of these, we may cancel the points concerned, suspend rewards on the account, or close it
          under the Terms of Use. We will tell you why where it is lawful and safe to do so, and you can ask us to look
          again by writing to the Grievance Officer.
        </p>
      </>
    ),
  },
  {
    id: "expiry",
    title: "Expiry of points",
    body: (
      <p>
        Points do not expire at present. We may introduce expiry after a period of inactivity. If we do, we will
        announce the period in advance, and remind you at least 14 days before any points lapse; any earning or spending
        in that time keeps them.
      </p>
    ),
  },
  {
    id: "changes",
    title: "Changes and ending the programme",
    body: (
      <p>
        We may change how points are earned or spent, or end the Programme, by updating these terms and telling you in
        the app or by email. Points already in your wallet are not taken away by a change. If the Programme ends, you
        will have time to spend your points before it closes.{" "}
        <ToConfirm>the notice period for ending the Programme (for example, 30 days)</ToConfirm>
      </p>
    ),
  },
  {
    id: "general",
    title: "Tax, liability and contact",
    body: (
      <>
        <p>
          You are responsible for any tax that applies to rewards you receive. DealDirect is not responsible for the
          goods or services supplied under a gift card or voucher; contact the issuing brand or Hubble about those.
        </p>
        <p>
          Questions and complaints about the Programme go to our Grievance Officer at{" "}
          <a href="mailto:grievance@dealdirect.in" className={legalLink}>grievance@dealdirect.in</a>, as set out in the{" "}
          <Link href="/terms#grievance" className={legalLink}>Terms of Use</Link>. These terms are governed by the laws
          of India.
        </p>
      </>
    ),
  },
];

export default function RewardsTermsContent() {
  return (
    <LegalDocument
      title="DealDirect Rewards Terms"
      effective={UPDATED}
      updated={UPDATED}
      summary={
        <p>
          How you earn, keep and spend DealDirect Rewards points. Points are free to earn, have no cash value, and are
          spent on gift cards and vouchers in the rewards store.
        </p>
      }
      sections={sections}
      related={[
        { href: "/rewards", label: "DealDirect Rewards" },
        { href: "/terms", label: "Terms of Use" },
        { href: "/privacy", label: "Privacy Policy" },
      ]}
    />
  );
}
