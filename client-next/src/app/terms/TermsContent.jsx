import Link from "next/link";
import LegalDocument, { ToConfirm, legalLink } from "../../components/Legal/LegalDocument";

/*
 * Terms of Use for DealDirect (website and app), operated by Agrawal Business
 * Network LLP. Replaces the earlier B2B trading terms (shipments, trade
 * credit, PAN/Aadhaar at registration), which described a different business.
 *
 * Facts used, and where they come from:
 * - No fees, no money taken from users (decision 2026-10-19); the Hubble
 *   rewards store is the only purchase-like flow and runs on points.
 * - One listing per owner account; at most 5 live "I'm interested"
 *   enquiries per buyer; points worth Rs 0.05 each in the store; points may
 *   lapse on inactivity only after notice (backend controllers and jobs).
 * - Address, grievance officer, jurisdiction: from the previous terms.
 * Draft for legal review. <ToConfirm> marks facts still awaited.
 */

const UPDATED = "23 October 2026";

const sections = [
  {
    id: "about",
    title: "About these terms",
    body: (
      <>
        <p>
          These Terms of Use (&ldquo;Terms&rdquo;) govern your use of DealDirect, the website at dealdirect.in and the
          DealDirect mobile application (together, the &ldquo;Platform&rdquo;). The Platform is operated by{" "}
          <strong>Agrawal Business Network LLP</strong>, a limited liability partnership registered in India, with its
          registered office at Growmore Tower, Sector 2, Plot No. 5, Kharghar, Navi Mumbai 410210, Maharashtra
          (&ldquo;DealDirect&rdquo;, &ldquo;we&rdquo;, &ldquo;us&rdquo;).
        </p>
        <p>
          By creating an account, or by using the Platform without one, you agree to these Terms and to our{" "}
          <Link href="/privacy" className={legalLink}>Privacy Policy</Link>. If you do not agree, please do not use the
          Platform.
        </p>
        <p>
          These Terms are an electronic record under the Information Technology Act, 2000 and the rules made under it,
          and are published in accordance with Rule 3(1) of the Information Technology (Intermediary Guidelines and
          Digital Media Ethics Code) Rules, 2021. They do not need a physical or digital signature.
        </p>
      </>
    ),
  },
  {
    id: "what-we-are",
    title: "What DealDirect is, and is not",
    body: (
      <>
        <p>
          DealDirect is an online platform where property owners list homes and commercial spaces for sale or rent,
          and where buyers and tenants find them and contact the owner directly. It also publishes information about
          builder projects.
        </p>
        <ul>
          <li>
            <strong>We are not a broker or agent.</strong> We do not represent any owner, buyer, tenant or builder, we
            do not negotiate on anyone&rsquo;s behalf, and we are not a party to any sale, lease or other agreement you
            make with another user.
          </li>
          <li>
            <strong>We do not charge fees or take money from users.</strong> Listing a property, searching, and
            contacting owners are free. We never ask you to pay a token, booking amount or deposit through the
            Platform. If anyone claiming to be from DealDirect asks you for money, do not pay, and report it to us.
          </li>
          <li>
            <strong>Listings are written by users.</strong> We review listings before they are published and may
            verify some owners or documents, but we do not guarantee the accuracy of any listing, its title, its
            price or the identity of its owner. Inspect the property and its documents yourself, and take independent
            legal advice, before you pay anyone or sign anything.
          </li>
          <li>
            <strong>Builder projects.</strong> Project information is based on material supplied by the builder. It is
            not an offer or an advertisement by DealDirect. Check the project&rsquo;s registration with the relevant
            Real Estate Regulatory Authority (RERA) before you book.
          </li>
        </ul>
        <p>
          As a platform that hosts content provided by users, DealDirect is an intermediary within the meaning of the
          Information Technology Act, 2000.
        </p>
      </>
    ),
  },
  {
    id: "accounts",
    title: "Eligibility and your account",
    body: (
      <ul>
        <li>
          You must be at least 18 years old and able to enter into a binding contract under Indian law to create an
          account. <ToConfirm>that DealDirect is for adults only (client question 4)</ToConfirm>
        </li>
        <li>
          Give accurate information when you register and keep it up to date. We verify your mobile number with a
          one-time password before you can list a property or send an enquiry.
        </li>
        <li>
          Keep your password private. You are responsible for activity on your account. Tell us at once at{" "}
          <a href="mailto:grievance@dealdirect.in" className={legalLink}>grievance@dealdirect.in</a> if you think
          someone else has used it.
        </li>
        <li>
          You may sign in with Google instead of a password. You can delete your account at any time, as described on{" "}
          <Link href="/delete-account" className={legalLink}>Delete your account</Link>.
        </li>
      </ul>
    ),
  },
  {
    id: "listings",
    title: "Listing a property",
    body: (
      <>
        <p>If you list a property, you confirm that:</p>
        <ul>
          <li>you own it, or are authorised in writing by the owner to list it;</li>
          <li>
            the details, price, photos and availability are true and current, and you will update or remove the listing
            when they change, or when the property is sold or let;
          </li>
          <li>you have the right to publish every photo and document you upload;</li>
          <li>the property may lawfully be sold or let as described.</li>
        </ul>
        <p>
          Each owner account can have one listing at a time. Listings are reviewed before they appear publicly. We may
          correct the category or property type, ask you for changes or documents, decline a listing, or remove it,
          including where we receive a complaint about it.
        </p>
      </>
    ),
  },
  {
    id: "enquiries",
    title: "Enquiries and contact between users",
    body: (
      <ul>
        <li>
          When you tap &ldquo;I&rsquo;m interested&rdquo; on a listing, your name, email address and mobile number are
          shared with the owner so they can reply, and the owner is notified by email, WhatsApp and in the app. The
          owner&rsquo;s phone number is shown to you once the owner responds.
        </li>
        <li>
          You can have up to five open enquiries on listings that are still available. Saving a listing to your
          shortlist is private and does not notify the owner.
        </li>
        <li>
          Use another user&rsquo;s contact details only to discuss the property concerned. Do not add them to marketing
          lists, share them, or contact them after they have asked you to stop.
        </li>
        <li>
          Enquiries about builder projects reach the DealDirect team.{" "}
          <ToConfirm>whether, and with what consent, the team passes enquirers&rsquo; details to builders (client question 6)</ToConfirm>
        </li>
      </ul>
    ),
  },
  {
    id: "conduct",
    title: "What you must not do",
    body: (
      <>
        <p>You must not host, display, upload, publish, share or transmit any information that:</p>
        <ol type="a">
          <li>belongs to another person and to which you have no right;</li>
          <li>
            is obscene, pornographic, paedophilic, invasive of another&rsquo;s privacy (including bodily privacy),
            insulting or harassing on the basis of gender, racially or ethnically objectionable, relating to or
            encouraging money laundering or gambling, or promoting enmity between groups on the grounds of religion or
            caste with the intent to incite violence;
          </li>
          <li>is harmful to a child;</li>
          <li>infringes any patent, trademark, copyright or other proprietary right;</li>
          <li>
            deceives or misleads about its origin, or knowingly and intentionally communicates misinformation or
            information that is patently false or misleading;
          </li>
          <li>impersonates another person;</li>
          <li>
            threatens the unity, integrity, defence, security or sovereignty of India, friendly relations with foreign
            States, or public order, or causes incitement to any cognisable offence, or prevents investigation of any
            offence, or insults another nation;
          </li>
          <li>contains software viruses or any other code designed to interrupt, destroy or limit any computer resource;</li>
          <li>violates any law for the time being in force.</li>
        </ol>
        <p>In addition, you must not:</p>
        <ul>
          <li>post a fake, duplicate or bait listing, or a property that is not available;</li>
          <li>
            refuse or restrict a sale or letting, or word a listing, so as to discriminate on the basis of religion,
            caste, community, gender, marital status or food habits, where the law prohibits it;
          </li>
          <li>
            ask another user for money on the pretext of DealDirect, or collect advance payments for a property you are
            not entitled to sell or let;
          </li>
          <li>
            copy, scrape or harvest listings or user details by automated means, or interfere with the security or
            working of the Platform;
          </li>
          <li>create more than one account to get around a limit, a suspension or a refusal.</li>
        </ul>
        <p>
          We may remove content that breaks these rules, suspend or close the accounts involved, and report unlawful
          activity to the authorities. Where we are required by law, we will act on a court order or a notice from an
          authorised government agency within the time the law sets.
        </p>
      </>
    ),
  },
  {
    id: "rewards",
    title: "Rewards points",
    body: (
      <ul>
        <li>
          You may earn points for actions such as listing a property, sending an enquiry or referring a friend. The
          current actions and amounts are shown in the app.
        </li>
        <li>
          Points have no cash value. They cannot be exchanged for money or transferred. They can be redeemed for gift
          cards and vouchers in the rewards store at the rate shown there (currently 1 point = ₹0.05 of store value).
        </li>
        <li>
          The rewards store is provided by Hubble, a third-party service, and vouchers are subject to Hubble&rsquo;s and
          the brand&rsquo;s own terms.
        </li>
        <li>
          We may change how points are earned or redeemed, or end the programme, with notice in the app. Points may
          lapse after a period of inactivity only if we have announced that period in advance and warned you at least
          14 days before they lapse.
        </li>
        <li>Points obtained by fraud, fake referrals or abuse of the programme may be cancelled.</li>
      </ul>
    ),
  },
  {
    id: "reviews",
    title: "Reviews",
    body: (
      <p>
        After a deal that we have verified, the buyer or tenant and the owner may review each other. Reviews must be
        honest and about your own experience. Both reviews are published together, or after 14 days. We may remove a
        review that breaks these Terms, but we do not edit reviews to change their meaning.
      </p>
    ),
  },
  {
    id: "content",
    title: "Your content and our licence",
    body: (
      <>
        <p>
          You keep ownership of the listings, photos, reviews and other content you post. You grant DealDirect a
          non-exclusive, royalty-free, worldwide licence to host, store, reproduce, resize, display and distribute that
          content on the Platform and in promoting your listing, for as long as it is on the Platform and for a
          reasonable period afterwards to remove copies.
        </p>
        <p>
          The DealDirect name and logo, and the Platform&rsquo;s design and software, belong to Agrawal Business Network
          LLP. You may not use them without our written permission.
        </p>
      </>
    ),
  },
  {
    id: "third-parties",
    title: "Third-party services",
    body: (
      <p>
        The Platform uses services provided by others, such as Google Sign-In, maps, image hosting, messaging and the
        Hubble rewards store. Your use of those services may also be governed by their own terms. We are not
        responsible for third-party websites that the Platform links to.
      </p>
    ),
  },
  {
    id: "disclaimers",
    title: "Disclaimers",
    body: (
      <>
        <p>
          The Platform is provided &ldquo;as is&rdquo; and &ldquo;as available&rdquo;. To the extent the law allows, we
          make no warranty that it will be uninterrupted or error-free, or that any listing, user or document is
          genuine.
        </p>
        <p>
          Price history, locality price ranges, the EMI calculator and similar tools are for general information only.
          They are based on asking prices on DealDirect and simple arithmetic, and are not valuations, financial advice
          or loan offers.
        </p>
      </>
    ),
  },
  {
    id: "liability",
    title: "Limitation of liability and indemnity",
    body: (
      <>
        <p>
          DealDirect is not liable for any agreement, payment, dispute, loss or damage arising between users, or from a
          property, a listing or a builder project. To the extent the law allows, we are not liable for indirect,
          incidental or consequential loss, or for loss of profit, data or opportunity. Nothing in these Terms limits
          liability that cannot be limited under Indian law.
        </p>
        <p>
          You agree to indemnify DealDirect and its partners and staff against claims, losses and costs arising from
          your content, your breach of these Terms, or your violation of any law or of another person&rsquo;s rights.
        </p>
      </>
    ),
  },
  {
    id: "termination",
    title: "Suspension and closing your account",
    body: (
      <p>
        You may stop using the Platform and delete your account at any time. We may suspend or close an account, or
        remove content, if you break these Terms or the law, if we are required to by law, or to protect other users.
        Where it is safe and lawful to do so, we will tell you why and give you a way to respond. Sections that by their
        nature should survive (such as liability, indemnity and governing law) continue after your account is closed.
      </p>
    ),
  },
  {
    id: "changes",
    title: "Changes to these terms",
    body: (
      <p>
        We may update these Terms as the Platform or the law changes. We will show the date of the latest version at
        the top of this page, and tell you in the app or by email before a material change takes effect. If you keep
        using the Platform after that, the updated Terms apply.
      </p>
    ),
  },
  {
    id: "law",
    title: "Governing law and disputes",
    body: (
      <p>
        These Terms are governed by the laws of India. Subject to any right you have to approach a consumer forum or
        the Data Protection Board of India, the courts at Mumbai, Maharashtra have exclusive jurisdiction over any
        dispute arising from them.
      </p>
    ),
  },
  {
    id: "grievance",
    title: "Grievance officer and contact",
    body: (
      <>
        <p>
          You can report content, raise a complaint about the Platform or about how we handle your personal data, or
          ask any question about these Terms, by writing to our Grievance Officer:
        </p>
        <address className="not-italic rounded-xl border border-slate-200 bg-slate-50 p-5 leading-relaxed">
          <strong>Ms. Arti Jadhav</strong>, Grievance Officer{" "}
          <ToConfirm>designation and official email (client question 1)</ToConfirm>
          <br />
          Agrawal Business Network LLP
          <br />
          Growmore Tower, Sector 2, Plot No. 5, Kharghar, Navi Mumbai 410210, Maharashtra
          <br />
          Email: <a href="mailto:grievance@dealdirect.in" className={legalLink}>grievance@dealdirect.in</a>
          <br />
          Phone: +91 92896 38963, Monday to Friday, 10:00 am to 6:00 pm
        </address>
        <p>
          We will acknowledge your complaint within 24 hours and resolve it within 15 days of receiving it, as the
          Information Technology (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021 require. A request
          to remove content that exposes a person&rsquo;s private area, shows them in full or partial nudity or in a
          sexual act, or is an impersonation in an electronic form including artificially morphed images, will be acted
          on within 24 hours.
        </p>
        <p>
          These Terms are available in English. On request to{" "}
          <a href="mailto:info@dealdirect.in" className={legalLink}>info@dealdirect.in</a>, we will provide them in a
          language listed in the Eighth Schedule to the Constitution of India; if the versions differ, the English
          version prevails.
        </p>
      </>
    ),
  },
];

export default function TermsContent() {
  return (
    <LegalDocument
      title="Terms of Use"
      effective={UPDATED}
      updated={UPDATED}
      summary={
        <p>
          The rules for using DealDirect: what the Platform does, what you agree to when you list a property or contact
          an owner, and how to raise a complaint. DealDirect does not charge users and is not a broker.
        </p>
      }
      sections={sections}
      related={[
        { href: "/privacy", label: "Privacy Policy" },
        { href: "/delete-account", label: "Delete your account" },
      ]}
    />
  );
}
