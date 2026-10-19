import Link from "next/link";

/**
 * Public account-deletion page, the URL given to Google Play's "delete
 * account" field. It must be reachable without signing in.
 *
 * Every statement describes what the code does today, checked on 2026-10-17
 * against backend `controllers/userController.js` (deleteAccount),
 * `utils/aggregateDelete.js` (USER_CASCADE), the app's settings screens and
 * this site's profile page. If the deletion cascade changes, this page has to
 * change with it.
 *
 * Facts that only the business can supply are rendered as visible
 * "[To be confirmed: ...]" markers. They are not to be published as they are:
 * replace each with the confirmed fact, or remove the sentence.
 */

export const metadata = {
    title: "Delete your account",
    description:
        "How to delete your DealDirect account from the app or the website, what is removed, and what is kept.",
    openGraph: {
        title: "Delete your account | DealDirect",
        description: "How to delete your DealDirect account, what is removed, and what is kept.",
        url: "https://dealdirect.in/delete-account",
    },
    alternates: {
        canonical: "https://dealdirect.in/delete-account",
    },
};

function ToConfirm({ children }) {
    return (
        <mark className="rounded bg-amber-100 px-1 text-amber-900">[To be confirmed: {children}]</mark>
    );
}

function Section({ id, title, children }) {
    return (
        <section id={id} aria-labelledby={`${id}-title`} className="mt-10">
            <h2 id={`${id}-title`} className="text-xl font-semibold text-slate-900">
                {title}
            </h2>
            <div className="mt-3 space-y-3 text-slate-700 leading-relaxed">{children}</div>
        </section>
    );
}

const linkClass = "font-medium text-blue-700 underline underline-offset-2 hover:text-blue-900";

export default function DeleteAccountPage() {
    return (
        <main className="min-h-screen bg-slate-50">
            <div className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
                <h1 className="text-3xl font-bold text-slate-900 sm:text-4xl">Delete your DealDirect account</h1>
                <p className="mt-4 text-lg text-slate-600">
                    You can delete your DealDirect account yourself, from the app or from this website. This page
                    explains how, what is removed when you do, and what is kept.
                </p>

                <Section id="in-the-app" title="Delete your account in the app">
                    <ol className="list-decimal space-y-2 pl-6">
                        <li>Open the DealDirect app and sign in to the account you want to delete.</li>
                        <li>Go to Profile, then Settings, then Delete account.</li>
                        <li>Type DELETE to confirm.</li>
                        <li>Enter your password. If you signed up with Google, you confirm with Google instead.</li>
                        <li>
                            Tap Permanently delete my account. Your phone may also ask for your fingerprint, face or
                            screen lock.
                        </li>
                    </ol>
                </Section>

                <Section id="on-the-website" title="Delete your account on the website">
                    <ol className="list-decimal space-y-2 pl-6">
                        <li>
                            <Link href="/login" className={linkClass}>
                                Sign in
                            </Link>{" "}
                            to the account you want to delete.
                        </li>
                        <li>
                            Open{" "}
                            <Link href="/profile?tab=settings" className={linkClass}>
                                your profile settings
                            </Link>
                            .
                        </li>
                        <li>Under Danger Zone, next to Delete Account, choose Delete.</li>
                        <li>Type the confirmation phrase shown on screen: DELETE- followed by your email address.</li>
                        <li>
                            Enter your password, or confirm with Google if you signed up with Google, then choose
                            Permanently Delete.
                        </li>
                    </ol>
                </Section>

                <Section id="cannot-sign-in" title="If you cannot sign in">
                    <p>
                        If you have forgotten your password, choose Forgot password? on the{" "}
                        <Link href="/login" className={linkClass}>
                            sign-in page
                        </Link>
                        . We send a one-time code to the mobile number on your account so you can set a new password.
                        Then follow the steps above.
                    </p>
                    <p>
                        If you no longer have that mobile number, contact us at{" "}
                        <ToConfirm>contact for privacy and account-deletion requests</ToConfirm>.
                    </p>
                </Section>

                <Section id="when-you-confirm" title="What happens when you confirm">
                    <ul className="list-disc space-y-2 pl-6">
                        <li>Deletion starts straight away. There is no waiting period, and it cannot be undone.</li>
                        <li>You are signed out on every device where you were signed in.</li>
                    </ul>
                </Section>

                <Section id="removed" title="What is removed">
                    <ul className="list-disc space-y-2 pl-6">
                        <li>Your account: your name, email address, mobile number, password and profile details.</li>
                        <li>
                            Your listings and their photos, unless a listing is tied to a deal or an agreement (see
                            below).
                        </li>
                        <li>Your saved searches, your shortlist and any shortlist links you shared.</li>
                        <li>Notifications sent to you, and the app&apos;s registration to send you notifications.</li>
                        <li>Messages you sent in chats. A chat with no one left in it is deleted.</li>
                        <li>Your reward points and referral records.</li>
                        <li>Reports you made about listings.</li>
                        <li>Messages you sent through our contact form while signed in.</li>
                        <li>Records of how you used the app and website, and our log of the messages we sent you.</li>
                    </ul>
                </Section>

                <Section id="kept" title="What is kept, and why">
                    <p>
                        Some records belong to another person as well as to you, or are the only record of a payment or
                        a completed deal. These are not deleted with your account, and they keep the name, phone number
                        and email address they were created with:
                    </p>
                    <ul className="list-disc space-y-2 pl-6">
                        <li>Enquiries you sent to property owners, and enquiries you received as an owner.</li>
                        <li>
                            Bookings for builder projects, including any payment reference (UTR) and payment screenshot
                            you submitted.
                        </li>
                        <li>Group-buy campaign memberships, including payment details.</li>
                        <li>Deal closure requests, including the documents uploaded with them.</li>
                        <li>Rental and sale agreements made on DealDirect.</li>
                        <li>
                            A listing tied to a pending or approved deal closure, or to an agreement that is still in
                            force.
                        </li>
                    </ul>
                    <p>
                        How long these records are kept: <ToConfirm>retention period for each type of record listed above</ToConfirm>.
                    </p>
                </Section>

                <Section id="also-not-removed" title="Also not removed">
                    <ul className="list-disc space-y-2 pl-6">
                        <li>Reviews you wrote after a completed deal.</li>
                        <li>
                            Notifications other people received about your activity, such as an owner being told you
                            are interested in their property. These stay in their accounts.
                        </li>
                        <li>
                            Your profile photo file. Your account no longer points to it, but the file stays in our
                            image storage.
                        </li>
                    </ul>
                </Section>

                <Section id="other-copies" title="Copies outside our main database">
                    <p>
                        Backups, server logs, error reports, and records kept by the companies that provide our hosting,
                        image storage, text messages and email may still hold your information after your account is
                        deleted. <ToConfirm>which of these exist, and how long each is kept</ToConfirm>
                    </p>
                </Section>

                <Section id="who-runs-dealdirect" title="Who runs DealDirect">
                    <p>
                        DealDirect is operated by <ToConfirm>legal name and registered address of the operator</ToConfirm>.
                    </p>
                    <p>
                        Questions about this page or your data:{" "}
                        <ToConfirm>contact for privacy and account-deletion requests</ToConfirm>.
                    </p>
                </Section>
            </div>
        </main>
    );
}
