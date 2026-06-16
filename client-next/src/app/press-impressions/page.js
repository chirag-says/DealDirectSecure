import PressImpressionsContent from "./PressImpressionsContent";

export const metadata = {
    title: "Press Impressions",
    description:
        "DealDirect.in has been featured in 267+ publications worldwide including Google News, Yahoo, News18, Business Standard, Tribune India, and ANI. Explore our complete press coverage.",
    openGraph: {
        title: "Press Impressions — DealDirect in the News",
        description:
            "DealDirect's broker-free property marketplace launch covered by 267+ news publications reaching 782M+ readers.",
        url: "https://dealdirect.in/press-impressions",
    },
    alternates: {
        canonical: "https://dealdirect.in/press-impressions",
    },
};

export default function PressImpressionsPage() {
    return <PressImpressionsContent />;
}
