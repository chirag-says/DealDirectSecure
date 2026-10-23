import Link from "next/link";
import LegalDocument, { LegalTable, ToConfirm, legalLink } from "../../components/Legal/LegalDocument";

/*
 * Privacy notice for DealDirect under the Digital Personal Data Protection
 * Act, 2023 (DPDP Act) and the DPDP Rules, 2025, replacing the earlier B2B
 * notice. Structured as section 5 of the Act asks: what personal data, for
 * what purpose, how to withdraw consent, how to exercise rights, how to
 * complain to the Data Protection Board.
 *
 * Every data item, recipient and retention period below was read from the
 * code on 2026-10-23 (backend models, services, TTL indexes and
 * utils/aggregateDelete.js; website and app storage). If the code changes,
 * this page must change with it.
 *
 * Draft for legal review. <ToConfirm> marks answers still awaited from the
 * client (the 12-point list sent 2026-10-22).
 */

const UPDATED = "23 October 2026";
const GRIEVANCE_EMAIL = "grievance@dealdirect.in";

const dataRows = [
  [
    "Account",
    "Name, email address, mobile number and password (stored only as a one-way hash). If you sign in with Google: your Google account's name, email address and profile photo.",
    "To create your account, sign you in and keep it secure.",
  ],
  [
    "Mobile verification",
    "Your mobile number and the one-time password (OTP) sent to it.",
    "To confirm the number is yours before you list a property or send an enquiry, and to prevent fake accounts.",
  ],
  [
    "Profile (optional)",
    "Photo, alternate phone number, address, date of birth, gender and a short bio, if you add them.",
    "To show your profile and fill in forms for you.",
  ],
  [
    "Listings",
    "Property address, map location, photos, price, description and features, and any documents you upload for verification.",
    "To publish your listing and let buyers and tenants find it, and to check that it is genuine.",
  ],
  [
    "Enquiries",
    "When you tap “I'm interested”: your name, email address and mobile number, and the conversation history, visits and notes on that enquiry. For a builder project enquiry: your name, phone, email and message.",
    "To put you in touch with the owner, or for our team to call you about the project.",
  ],
  [
    "Saved items and searches",
    "Your shortlist, saved searches and their alerts, and reviews you write after a verified deal.",
    "To let you keep and return to properties, alert you to new matches, and show reviews.",
  ],
  [
    "Deal verification",
    "Documents you upload to show that a sale or letting has completed.",
    "To verify the deal before reviews and rewards are released.",
  ],
  [
    "Rewards and referrals",
    "Your points history, referral code and who referred whom. When you open the rewards store, your name, email address and mobile number are passed to Hubble.",
    "To run the rewards programme and the store.",
  ],
  [
    "Support and reports",
    "Messages you send us and reports you make about listings or users.",
    "To answer you and act on reports.",
  ],
  [
    "Device and security",
    "IP address, browser or device type and user-agent of each signed-in session, app installation ID, push-notification token and app version.",
    "To keep sessions secure, let you see and sign out of your devices, detect misuse, and deliver notifications.",
  ],
  [
    "Usage",
    "Actions you take in the app and website (for example, viewing a listing or starting an enquiry), linked to your account or app installation. IP addresses are not stored with these events.",
    "To understand how DealDirect is used and improve it. We use no third-party analytics or advertising tools.",
  ],
  [
    "Location",
    "With your browser's or phone's permission, your approximate location, used to work out your city. On a listing, the map pin you set.",
    "To show properties near you and place listings on the map.",
  ],
];

const recipientRows = [
  ["Property owners", "When you send an enquiry: your name, email address and mobile number.", "So the owner can reply to you."],
  ["Everyone on the Platform", "A published listing (without the owner's phone or email), the owner's name, and published reviews.", "This is what listings and reviews are for."],
  ["Hostinger", "All Platform data, as our web and application host.", "Hosting."],
  ["MongoDB Atlas", "All account, listing and enquiry data, as our database service.", "Database hosting."],
  ["Cloudinary", "Profile photos, listing photos and verification documents.", "Image and document storage."],
  ["Email service", "Your email address and the content of emails we send you.", "Sending account and enquiry emails."],
  ["Equence", "Your mobile number and the OTP.", "Sending verification SMS."],
  ["Meta (WhatsApp)", "Your mobile number and the message; for an enquiry, the owner receives the enquirer's name, email and phone.", "Sending WhatsApp notifications."],
  ["Railway", "Hosts the gateway that sends our team WhatsApp alerts about new sign-ups, enquiries and contact messages (name, email and phone).", "Internal alerts to the DealDirect team."],
  ["Expo", "Your push token and the notification text.", "Sending app notifications."],
  ["Google", "Data needed to verify a Google sign-in.", "Sign in with Google."],
  ["Hubble", "Your name, email address and mobile number, when you open the store.", "The rewards store."],
  ["OpenStreetMap", "Map coordinates and address searches typed into the map.", "Showing maps and finding addresses."],
  ["Sentry", "Technical details of errors, linked to an account ID and role. Screen text, form inputs and images are masked.", "Finding and fixing faults."],
];

const storageRows = [
  ["user_session (cookie)", "Keeps you signed in. Not readable by page scripts.", "7 days"],
  ["session_exists (cookie)", "Tells the website you are signed in, without exposing the session.", "7 days"],
  ["csrf_token (cookie)", "Protects forms against cross-site request forgery.", "Session"],
  ["dd_user_city, dd-theme, dealDirectRecentSearches, dd_proj_bookmarks (browser storage)", "Your city, display theme, recent searches and saved projects, kept on your device.", "Until you clear them"],
  ["App secure storage and cache", "Your session, preferences and a cache of screens you opened (which can include enquiry details), stored on your phone. Excluded from phone backups on Android.", "Until you sign out or uninstall"],
];

const retentionRows = [
  ["Signed-in sessions", "7 days, or until you sign out."],
  ["One-time passwords", "10 minutes."],
  ["Usage events", "90 days."],
  ["Notifications you have read", "90 days."],
  ["Message delivery logs", "8 days."],
  ["Push tokens", "Removed 30 days after they stop working, or 180 days after a device was last seen."],
  [
    "Your account, profile, listings, shortlist, saved searches and notifications",
    <>
      Until you delete your account; then deleted, and listing photos are removed from image storage.{" "}
      <ToConfirm>removal of profile photos from image storage, which is not yet automatic</ToConfirm>
    </>,
  ],
  [
    "Enquiries, verified deals and project enquiries (with the names and contact details in them)",
    <>
      Kept after you delete your account, because the other party to the enquiry or deal also relies on them.{" "}
      <ToConfirm>how long these are kept</ToConfirm>
    </>,
  ],
  [
    "Backups and system logs",
    <>
      Kept for at least one year where the DPDP Rules require it, then deleted. <ToConfirm>backup and log retention (client question 13)</ToConfirm>
    </>,
  ],
];

const sections = [
  {
    id: "who-we-are",
    title: "Who we are and what this notice covers",
    body: (
      <>
        <p>
          DealDirect is operated by <strong>Agrawal Business Network LLP</strong>, Growmore Tower, Sector 2, Plot No. 5,
          Kharghar, Navi Mumbai 410210, Maharashtra (&ldquo;DealDirect&rdquo;, &ldquo;we&rdquo;, &ldquo;us&rdquo;). For
          the personal data described here, we are the Data Fiduciary under the Digital Personal Data Protection Act,
          2023.
        </p>
        <p>
          This notice explains what personal data we process when you use the dealdirect.in website or the DealDirect
          app, why, who receives it, how long we keep it, and the rights you have. It follows the Digital Personal Data
          Protection Act, 2023 and the Digital Personal Data Protection Rules, 2025, and the Information Technology Act,
          2000 and the rules under it where they still apply.
        </p>
      </>
    ),
  },
  {
    id: "summary",
    title: "The short version",
    body: (
      <ul>
        <li>We collect what we need to run accounts, listings and enquiries, and to keep the Platform safe.</li>
        <li>
          When you send an enquiry, the owner receives your name, email address and mobile number. That is how they
          reply.
        </li>
        <li>We do not sell your personal data, and we use no third-party advertising or analytics tools.</li>
        <li>
          You can see, correct and delete your data, withdraw consent, and complain to us or to the Data Protection
          Board of India.
        </li>
      </ul>
    ),
  },
  {
    id: "data-we-process",
    title: "Personal data we process, and why",
    body: (
      <>
        <p>
          We process the following personal data, each for the purpose shown next to it. We ask for your consent when you
          create an account and when you use features that need more data (such as location). Where you give us data
          voluntarily for a purpose, such as an enquiry, we use it for that purpose.
        </p>
        <LegalTable caption="Personal data and purposes" head={["What", "Personal data", "Why we use it"]} rows={dataRows} />
        <p>
          We do not ask for your PAN, Aadhaar or bank details to use the Platform. Do not include them in listings,
          photos or messages.
        </p>
      </>
    ),
  },
  {
    id: "legitimate-uses",
    title: "Processing without consent",
    body: (
      <p>
        Section 7 of the DPDP Act allows some processing without consent. We rely on it only where it applies, for
        example to comply with a law or a court order, to respond to a medical emergency or a threat to someone&rsquo;s
        safety, or to use data you gave us voluntarily for the purpose you gave it for.
      </p>
    ),
  },
  {
    id: "sharing",
    title: "Who receives your personal data",
    body: (
      <>
        <p>
          We share personal data only as set out below. The service providers listed process it on our behalf, under
          contract, and only to provide their service to us. <ToConfirm>data processing agreements with each provider (client question 8)</ToConfirm>
        </p>
        <LegalTable caption="Recipients of personal data" head={["Recipient", "What they receive", "Why"]} rows={recipientRows} />
        <p>
          Builder projects: enquiries reach the DealDirect team.{" "}
          <ToConfirm>whether, and with what consent, the team passes enquirers&rsquo; details to builders (client question 6)</ToConfirm>
        </p>
        <p>
          We may also disclose personal data to a government agency, court or regulator when the law requires it, and to
          a successor if DealDirect&rsquo;s business is transferred, under the same protections. We do not sell personal
          data or share it for others&rsquo; advertising.
        </p>
      </>
    ),
  },
  {
    id: "transfers",
    title: "Processing outside India",
    body: (
      <p>
        Some of the providers above store or process data outside India. Section 16 of the DPDP Act permits this,
        except to any country the Central Government restricts, and we will follow any such restriction.{" "}
        <ToConfirm>the countries and regions where each provider holds DealDirect data (client question 8)</ToConfirm>
      </p>
    ),
  },
  {
    id: "cookies",
    title: "Cookies and storage on your device",
    body: (
      <>
        <p>
          We use only the cookies and device storage needed for the Platform to work and to remember your choices. We do
          not use advertising or tracking cookies.
        </p>
        <LegalTable caption="Cookies and device storage" head={["Name", "What it does", "How long"]} rows={storageRows} />
      </>
    ),
  },
  {
    id: "retention",
    title: "How long we keep personal data",
    body: (
      <>
        <p>
          We keep personal data only as long as its purpose needs, or as long as the law requires, and then delete it.
        </p>
        <LegalTable caption="Retention periods" head={["Data", "How long"]} rows={retentionRows} />
        <p>
          <Link href="/delete-account" className={legalLink}>Delete your account</Link> explains how to delete your
          account and exactly what is removed and what is kept.
        </p>
      </>
    ),
  },
  {
    id: "rights",
    title: "Your rights",
    body: (
      <>
        <p>Under the DPDP Act you have the right to:</p>
        <ul>
          <li>
            <strong>Access:</strong> a summary of the personal data we process about you and the processing we carry
            out, and the identities of those we have shared it with.
          </li>
          <li>
            <strong>Correction and erasure:</strong> have inaccurate or incomplete data corrected, completed or updated,
            and have data erased when it is no longer needed. You can edit your profile and listings, and delete your
            account, yourself in the app or on the website.
          </li>
          <li>
            <strong>Withdraw consent:</strong> at any time, as easily as you gave it (see the next section).
          </li>
          <li>
            <strong>Nominate:</strong> name another person to exercise your rights if you die or become unable to.
          </li>
          <li>
            <strong>Grievance redressal:</strong> complain to us, and then to the Data Protection Board of India.
          </li>
        </ul>
        <p>
          For anything you cannot do yourself in the app or on the website, write to{" "}
          <a href={`mailto:${GRIEVANCE_EMAIL}`} className={legalLink}>{GRIEVANCE_EMAIL}</a> from the email address on
          your account, or include your registered mobile number. We may ask you to confirm your identity. We will
          respond within the time the DPDP Rules allow, and in any case within 90 days.{" "}
          <ToConfirm>a shorter response time, if the client commits to one (client question 3)</ToConfirm>
        </p>
      </>
    ),
  },
  {
    id: "consent",
    title: "Consent and withdrawing it",
    body: (
      <>
        <ul>
          <li>
            Location: turn it off in your browser&rsquo;s site settings or your phone&rsquo;s app permissions. You can
            still choose a city by hand.
          </li>
          <li>Notifications: change email, SMS and WhatsApp preferences in your account settings, or turn off app notifications on your phone.</li>
          <li>
            Promotional messages: we send them only if you agree to receive them, and every such message explains how to
            stop them. <ToConfirm>how users opt in to and out of promotional messages (client question 5)</ToConfirm>
          </li>
          <li>Everything else: delete your account, or write to us.</li>
        </ul>
        <p>
          Withdrawing consent does not affect processing that took place before. Some features, such as enquiries, cannot
          work without the data they need, so withdrawing consent for them may mean closing your account.
        </p>
      </>
    ),
  },
  {
    id: "children",
    title: "Children",
    body: (
      <p>
        DealDirect is meant for adults. You must be 18 or older to create an account. We do not knowingly process the
        personal data of anyone under 18; if we learn that we have, without verifiable consent from a parent or lawful
        guardian, we will delete it. <ToConfirm>that DealDirect is for adults only (client question 4)</ToConfirm>
      </p>
    ),
  },
  {
    id: "security",
    title: "How we protect personal data",
    body: (
      <>
        <p>We use reasonable security safeguards, including:</p>
        <ul>
          <li>encryption of data in transit (HTTPS);</li>
          <li>passwords stored only as one-way hashes, and sign-in sessions held in cookies that page scripts cannot read;</li>
          <li>sessions that expire, and a list of your signed-in devices that you can sign out of;</li>
          <li>limits on repeated sign-in and OTP attempts;</li>
          <li>access to personal data limited to the staff and providers who need it;</li>
          <li>error monitoring that masks screen text, form inputs and images.</li>
        </ul>
        <p>
          If a personal data breach affects you, we will tell you without delay, in the way the DPDP Rules require, and
          report it to the Data Protection Board of India.
        </p>
      </>
    ),
  },
  {
    id: "duties",
    title: "Your duties",
    body: (
      <p>
        The DPDP Act also asks you not to impersonate anyone, not to suppress material information, to give only true
        information when you ask us to correct your data, and not to file false or frivolous complaints.
      </p>
    ),
  },
  {
    id: "changes",
    title: "Changes to this notice",
    body: (
      <p>
        We will update this notice when our processing or the law changes, and show the date at the top. If a change is
        material, we will tell you in the app or by email before it takes effect, and ask for fresh consent where the law
        requires it.
      </p>
    ),
  },
  {
    id: "contact",
    title: "Grievance officer and the Data Protection Board",
    body: (
      <>
        <p>For questions about this notice, to exercise your rights, or to complain, contact our Grievance Officer:</p>
        <address className="not-italic rounded-xl border border-slate-200 bg-slate-50 p-5 leading-relaxed">
          <strong>Ms. Arti Jadhav</strong>, Grievance Officer{" "}
          <ToConfirm>designation and official email (client question 1)</ToConfirm>
          <br />
          Agrawal Business Network LLP
          <br />
          Growmore Tower, Sector 2, Plot No. 5, Kharghar, Navi Mumbai 410210, Maharashtra
          <br />
          Email: <a href={`mailto:${GRIEVANCE_EMAIL}`} className={legalLink}>{GRIEVANCE_EMAIL}</a>
          <br />
          Phone: +91 92896 38963, Monday to Friday, 10:00 am to 6:00 pm
        </address>
        <p>
          If you are not satisfied with our response, or we do not respond within the time allowed, you may complain to
          the Data Protection Board of India in the manner it prescribes.
        </p>
        <p>
          This notice is available in English. On request to{" "}
          <a href="mailto:info@dealdirect.in" className={legalLink}>info@dealdirect.in</a>, we will provide it in any
          language listed in the Eighth Schedule to the Constitution of India.{" "}
          <ToConfirm>which languages to publish in advance (client question 11)</ToConfirm>
        </p>
      </>
    ),
  },
];

export default function PrivacyContent() {
  return (
    <LegalDocument
      title="Privacy Policy"
      effective={UPDATED}
      updated={UPDATED}
      summary={
        <p>
          How DealDirect collects, uses, shares and protects your personal data, and how to exercise your rights under
          the Digital Personal Data Protection Act, 2023.
        </p>
      }
      sections={sections}
      related={[
        { href: "/terms", label: "Terms of Use" },
        { href: "/delete-account", label: "Delete your account" },
      ]}
    />
  );
}
