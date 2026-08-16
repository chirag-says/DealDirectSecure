import { notFound } from 'next/navigation';
// import AgreementsContent from './AgreementsContent';

/**
 * ============================================
 * AGREEMENTS — HIDDEN (client decision, 2026-08-01)
 *
 * The client asked for the agreement generator to be withdrawn for now, to be
 * reinstated later. Nothing has been deleted: AgreementsContent.jsx, the
 * backend controller, the Agreement model, and all existing agreement records
 * are intact.
 *
 * Hidden in three places, all of which must be reversed together:
 *   1. this file            — returns 404 instead of rendering
 *   2. backend/server.js    — the /api/agreements route mount is commented out
 *   3. Navbar.jsx           — three "Agreements" links removed
 *
 * TO RE-ENABLE: restore the import and the render below, uncomment the route
 * mount in server.js, and restore the Navbar links. Search the codebase for
 * "AGREEMENTS — HIDDEN" to find every site.
 *
 * NOTE: re-enabling the backend also re-exposes POST /api/agreements/webhook/payment,
 * which skips signature verification whenever PAYMENT_WEBHOOK_SECRET is unset.
 * Set that variable, or make the check fail closed, before going live again.
 * See AI/SECURITY.md (H2).
 * ============================================
 */

export const metadata = {
    title: 'Agreement Generator',
    description: 'Generate professional property agreements with AI on DealDirect.',
    robots: { index: false, follow: false },
};

export default function AgreementsPage() {
    notFound();

    // return <AgreementsContent />;
}
