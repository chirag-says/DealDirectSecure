import TermsContent from "./TermsContent";

export const metadata = {
    title: "Terms of Use",
    description:
        "The terms for using DealDirect, a free platform where owners list property and buyers and tenants contact them directly. No brokerage, no fees.",
    openGraph: {
        title: "Terms of Use | DealDirect",
        description: "The terms for listing a property, contacting owners and using DealDirect.",
        url: 'https://dealdirect.in/terms',
    },
    alternates: {
        canonical: 'https://dealdirect.in/terms',
    },
};

export default function TermsPage() {
    return <TermsContent />;
}
