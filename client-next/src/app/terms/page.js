import TermsContent from "./TermsContent";

export const metadata = {
    title: "Terms of Use",
    description:
        "Read DealDirect's Terms of Use. Understand the rules and obligations governing your use of India's leading no-broker B2B property platform.",
    openGraph: {
        title: "Terms of Use | DealDirect",
        description: "Terms and conditions governing the use of the DealDirect platform.",
        url: 'https://dealdirect.in/terms',
    },
    alternates: {
        canonical: 'https://dealdirect.in/terms',
    },
};

export default function TermsPage() {
    return <TermsContent />;
}
