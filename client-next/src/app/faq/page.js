import FAQContent from "./FAQContent";
import { allFaqs } from "./faqData";
import { FAQJsonLd, BreadcrumbJsonLd } from "../../components/JsonLd";

export const metadata = {
    title: "Help centre and FAQs",
    description:
        "Answers about DealDirect: contacting owners, listing a property, builder projects, rewards points, and your account and privacy. No brokerage, no fees.",
    openGraph: {
        title: "Help centre and FAQs | DealDirect",
        description: "How DealDirect works: contacting owners, listing a property, rewards points, and your account and privacy.",
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
