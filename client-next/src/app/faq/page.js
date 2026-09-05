import FAQContent from "./FAQContent";
import { allFaqs } from "./faqData";
import { FAQJsonLd, BreadcrumbJsonLd } from "../../components/JsonLd";

export const metadata = {
    title: "FAQs — Deal Direct",
    description:
        "Frequently Asked Questions about DealDirect — learn about our zero brokerage policy, one-post-per-user rule, rewards program, referrals, and how we keep your data safe.",
    openGraph: {
        title: "FAQs — DealDirect | India's No-Broker Property Platform",
        description: "Get answers to all your questions about DealDirect — zero brokerage, verified listings, rewards, referrals, and more.",
        url: 'https://dealdirect.in/faq',
    },
    alternates: {
        canonical: 'https://dealdirect.in/faq',
    },
};

export default function FAQPage() {
    return (
        <>
            {/* FAQPage markup drives the expandable Q&A rich result in search.
                It reads the same faqData the page renders, so the two cannot drift. */}
            <FAQJsonLd faqs={allFaqs.map((f) => ({ question: f.q, answer: f.a }))} />
            <BreadcrumbJsonLd items={[{ name: 'Home', href: '/' }, { name: 'FAQs', href: '/faq' }]} />
            <FAQContent />
        </>
    );
}
