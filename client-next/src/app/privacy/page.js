import PrivacyContent from "./PrivacyContent";

export const metadata = {
    title: "Privacy Policy",
    description:
        "Read DealDirect's Privacy Policy. Learn how we collect, use, and protect your information on India's leading no-broker property platform.",
    openGraph: {
        title: "Privacy Policy | DealDirect",
        description: "How DealDirect handles your data — transparent, secure, and compliant with Indian IT regulations.",
        url: 'https://dealdirect.in/privacy',
    },
    alternates: {
        canonical: 'https://dealdirect.in/privacy',
    },
};

export default function PrivacyPage() {
    return <PrivacyContent />;
}
