import RewardsContent from "./RewardsContent";

export const metadata = {
    title: "DealDirect Rewards: earn points, redeem gift cards",
    description:
        "Earn points for verified deals, your first listing, enquiries and referrals, and redeem them for gift cards. Free to join, no fees.",
    openGraph: {
        title: "DealDirect Rewards: earn points, redeem gift cards",
        description: "Points for verified deals, your first listing, enquiries and referrals, redeemable for gift cards.",
        url: "https://dealdirect.in/rewards",
    },
    alternates: {
        canonical: "https://dealdirect.in/rewards",
    },
};

export default function RewardsPage() {
    return <RewardsContent />;
}
