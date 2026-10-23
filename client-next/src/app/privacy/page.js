import PrivacyContent from "./PrivacyContent";

export const metadata = {
    title: "Privacy Policy",
    description:
        "How DealDirect collects, uses, shares and protects personal data, and how to exercise your rights under the Digital Personal Data Protection Act, 2023.",
    openGraph: {
        title: "Privacy Policy | DealDirect",
        description: "What personal data DealDirect processes, who receives it, how long it is kept, and your rights under the DPDP Act, 2023.",
        url: 'https://dealdirect.in/privacy',
    },
    alternates: {
        canonical: 'https://dealdirect.in/privacy',
    },
};

export default function PrivacyPage() {
    return <PrivacyContent />;
}
