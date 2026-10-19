import RewardsContent from "./RewardsContent";

export const metadata = {
    title: "DealDirect Rewards — Earn Points, Unlock Real Value",
    description:
        "Every action on DealDirect earns you coins. List property, send enquiries, refer friends, and redeem points for gift cards. Join DealDirect Rewards today.",
    openGraph: {
        title: "DealDirect Rewards — Earn Points, Unlock Real Value",
        description: "Earn points on every listing, visit, referral, and deal. Redeem them for gift cards.",
        url: "https://dealdirect.in/rewards",
    },
    alternates: {
        canonical: "https://dealdirect.in/rewards",
    },
};

export default function RewardsPage() {
    return <RewardsContent />;
}
