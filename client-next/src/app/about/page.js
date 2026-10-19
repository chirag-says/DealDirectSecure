import AboutContent from "./AboutContent";

export const metadata = {
    title: "About Us",
    description:
        "Learn about DealDirect, a no-broker property platform that connects property buyers and sellers directly, without brokerage fees.",
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
