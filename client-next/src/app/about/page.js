import AboutContent from "./AboutContent";

export const metadata = {
    title: "About Us",
    description:
        "Learn about DealDirect — India's leading PropTech platform that connects property buyers and sellers directly, eliminating brokerage fees. 10,000+ happy families and counting.",
    openGraph: {
        title: "About DealDirect — India's No-Broker Property Platform",
        description: "DealDirect connects property buyers and sellers directly. No brokerage, no middlemen — just transparent property deals.",
        url: 'https://dealdirect.in/about',
    },
    alternates: {
        canonical: 'https://dealdirect.in/about',
    },
};

export default function AboutPage() {
    return <AboutContent />;
}
