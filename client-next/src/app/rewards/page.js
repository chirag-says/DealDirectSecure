import RewardsContent from "./RewardsContent";

export const metadata = {
    title: "DealDirect Rewards — Earn Points, Unlock Real Value",
    description:
        "Every action on DealDirect earns you coins. List property, send enquiries, refer friends, and redeem points for vouchers, listing boosts, or cash. Join DealDirect Rewards today.",
    openGraph: {
        title: "DealDirect Rewards — Earn Points, Unlock Real Value",
        description: "Earn points on every listing, visit, referral, and deal. Redeem for Amazon vouchers, premium listings, or cash.",
        url: "https://dealdirect.in/rewards",
    },
    alternates: {
        canonical: "https://dealdirect.in/rewards",
    },
};

export default function RewardsPage() {
    return <RewardsContent />;
}
