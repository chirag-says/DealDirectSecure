/**
 * FAQ content, kept free of JSX so the server component can import it too.
 *
 * page.js uses this to emit FAQPage structured data; FAQContent.jsx renders it.
 * Both read the same source, so the rich result can never drift from the page.
 * `icon` is a key into the icon map in FAQContent, not a component, because a
 * server component cannot serialise one across the boundary. `link` is an
 * optional { href, label } shown under the answer on the page only.
 *
 * Every answer describes what the product actually does (checked against the
 * backend and the Terms of Use, Privacy Policy and Rewards terms, 2026-10-23).
 * Rewards are described in points only, as on /rewards.
 */

import { FIXED_POINTS, LIMITS } from "../../data/rewardsProgramme.mjs";

export const faqCategories = [
    {
        id: 'general',
        title: 'About DealDirect',
        blurb: 'What DealDirect is, and what it costs.',
        icon: 'about',
        questions: [
            {
                id: 'what-is-dealdirect',
                q: 'What is DealDirect?',
                a: 'DealDirect is a property platform where owners list homes and commercial spaces for sale or rent, and buyers and tenants contact them directly, without a broker in between.',
            },
            {
                id: 'cost',
                q: 'Does DealDirect cost anything?',
                a: 'No. Listing, searching and contacting owners are free, and there is no brokerage. DealDirect never asks you for a token, booking amount or deposit. If anyone claiming to be from DealDirect asks you for money, do not pay, and report it to us.',
            },
            {
                id: 'not-a-broker',
                q: 'Is DealDirect a broker or an agent?',
                a: 'No. We do not represent owners, buyers or tenants, and we are not a party to any deal you make. Inspect the property and its documents yourself, and take independent legal advice, before you pay anyone or sign anything.',
                link: { href: '/terms#what-we-are', label: 'What DealDirect is, and is not' },
            },
        ],
    },
    {
        id: 'buying',
        title: 'Buying & Renting',
        blurb: 'Finding a property and contacting the owner.',
        icon: 'key',
        questions: [
            {
                id: 'contact-owner',
                q: 'How do I contact an owner?',
                a: 'Open the listing and tap “I’m interested”. The owner receives your name, email address and mobile number, by email, WhatsApp and in the app, so they can reply. The owner’s phone number is shown to you once they respond.',
            },
            {
                id: 'save-vs-interested',
                q: 'What is the difference between saving a listing and “I’m interested”?',
                a: 'Saving adds the listing to your private shortlist; the owner is not told and nothing is shared. “I’m interested” sends your contact details to the owner and starts an enquiry.',
            },
            {
                id: 'enquiry-limit',
                q: 'How many enquiries can I have open?',
                a: 'Up to five, on listings that are still available. Withdraw one, or wait for a listing to be sold or let, to make room for another.',
            },
            {
                id: 'verify-phone',
                q: 'Why do I have to verify my mobile number?',
                a: 'We send a one-time password to confirm the number is yours before you send an enquiry or list a property. It keeps fake accounts out, and means owners and buyers reach real people.',
            },
        ],
    },
    {
        id: 'listings',
        title: 'Listing a Property',
        blurb: 'Rules for putting a property on DealDirect.',
        icon: 'listing',
        questions: [
            {
                id: 'who-can-list',
                q: 'Who can list a property?',
                a: 'The owner, or someone the owner has authorised in writing. Brokers and agencies may not list on DealDirect.',
            },
            {
                id: 'one-property-only',
                q: 'Why can I list only one property?',
                a: 'Each owner account can have one listing at a time. It keeps DealDirect free of bulk uploads by brokers and of duplicate listings.',
            },
            {
                id: 'go-live',
                q: 'When does my listing go live?',
                a: 'As soon as you submit it. Our team may review it at any time, ask you for changes or documents, or unpublish it if it breaks the rules.',
            },
            {
                id: 'edit-or-delete',
                q: 'Can I edit or delete my listing?',
                a: 'Yes, at any time from your account. Update the details, or mark it sold or rented. Deleting it lets you publish a new one.',
            },
            {
                id: 'stand-out',
                q: 'How do I make my listing stand out?',
                a: `Add clear, well-lit photos of every room, write a specific description, and state the price and amenities plainly. A listing published with five or more photos also earns ${FIXED_POINTS.upload_5_photos} bonus points.`,
            },
        ],
    },
    {
        id: 'projects',
        title: 'Builder Projects',
        blurb: 'New developments listed on DealDirect.',
        icon: 'project',
        questions: [
            {
                id: 'project-enquiry',
                q: 'How do builder project enquiries work?',
                a: 'Send an enquiry from the project page and our team will call you. There is no booking amount or payment on DealDirect.',
            },
            {
                id: 'rera',
                q: 'Should I check a project’s RERA registration?',
                a: 'Yes. Project details come from the builder. Check the project’s registration with the relevant Real Estate Regulatory Authority before you book.',
            },
        ],
    },
    {
        id: 'rewards',
        title: 'Rewards',
        blurb: 'Earning and spending DealDirect Rewards points.',
        icon: 'gift',
        questions: [
            {
                id: 'how-to-earn',
                q: 'How do I earn points?',
                a: `A verified deal, your first listing, and enquiries (up to ${LIMITS.enquiryRewardsPerDay} a day) each earn a draw of points. You also earn fixed bonuses, for example for a listing with five or more photos and for referring friends.`,
                link: { href: '/rewards', label: 'See all the ways to earn' },
            },
            {
                id: 'how-to-refer',
                q: 'How do referrals work?',
                a: `Share the referral code in your Rewards tab. You earn ${FIXED_POINTS.referral_signup} points when a friend signs up with it, ${FIXED_POINTS.referral_first_action} when they make their first listing or enquiry, and ${FIXED_POINTS.referral_deal_closure} if they close a verified deal.`,
            },
            {
                id: 'spend-points',
                q: 'What can I do with my points?',
                a: 'Spend them on gift cards and vouchers in the rewards store in your account. Points have no cash value and cannot be withdrawn or transferred.',
                link: { href: '/rewards/terms', label: 'Rewards terms' },
            },
            {
                id: 'points-expiry',
                q: 'Do my points expire?',
                a: 'Not at present. If we introduce expiry for inactive accounts, we will announce it in advance and remind you at least 14 days before any points lapse.',
            },
        ],
    },
    {
        id: 'safety',
        title: 'Account & Privacy',
        blurb: 'Your data, your account, and how to raise a concern.',
        icon: 'shield',
        questions: [
            {
                id: 'who-sees-details',
                q: 'Who can see my contact details?',
                a: 'Your email address and phone number are never shown on a listing. They go to an owner only when you send that owner an enquiry. We do not sell personal data, and we use no third-party advertising or analytics tools.',
                link: { href: '/privacy', label: 'Privacy Policy' },
            },
            {
                id: 'report-listing',
                q: 'How do I report a suspicious listing?',
                a: 'Use Report on the listing page. Our team reviews every report. You can report a listing once while it is under review.',
            },
            {
                id: 'delete-account',
                q: 'How do I delete my account?',
                a: 'From the app (Profile, then Settings) or on the website (your profile). Deleting your account removes your profile and listings. Some records of enquiries and deals are kept, because the other party relies on them.',
                link: { href: '/delete-account', label: 'Delete your account' },
            },
            {
                id: 'complaint',
                q: 'How do I raise a complaint?',
                a: 'Write to our Grievance Officer at grievance@dealdirect.in. We acknowledge complaints within 24 hours and resolve them within 15 days.',
                link: { href: '/terms#grievance', label: 'Grievance officer' },
            },
        ],
    },
];

/** Flattened list, for the JSON-LD FAQPage schema and for search. */
export const allFaqs = faqCategories.flatMap((cat) =>
    cat.questions.map((item) => ({
        ...item,
        categoryId: cat.id,
        categoryTitle: cat.title,
    }))
);
