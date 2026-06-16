import WhyUs from "./WhyUsContent";

export const metadata = {
    title: "Why DealDirect?",
    description:
        "Discover why DealDirect is the best platform for property buyers, sellers, and owners. Direct no-broker model, smart search, transparent pricing, and more.",
    openGraph: {
        title: "Why Choose DealDirect — Zero Brokerage, Direct Deals",
        description: "No middlemen, no hidden charges – just clean, data-driven property matchmaking.",
        url: 'https://dealdirect.in/why-us',
    },
    alternates: {
        canonical: 'https://dealdirect.in/why-us',
    },
};

export default function WhyUsPage() {
    return <WhyUs />;
}
