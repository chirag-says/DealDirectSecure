import React from "react";
import { Link } from "react-router-dom";

const plans = [
  {
    id: "free",
    name: "Starter (Free)",
    price: "Free",
    description: "Perfect for individual owners trying DealDirect for the first time.",
    tag: "Most basic",
    features: [
      "1 active property listing",
      "Standard visibility in search results",
      "Lead notifications via email & in-app",
      "Basic owner dashboard",
    ],
  },
  {
    id: "growth",
    name: "Growth Owner",
    price: "₹499 / month",
    description: "For serious owners who want faster discovery and better lead control.",
    tag: "Recommended",
    features: [
      "Up to 3 active listings",
      "Priority placement in relevant searches",
      "Smart lead insights & basic analytics",
      "Saved replies & lead follow-up nudges",
    ],
  },
  {
    id: "pro",
    name: "Pro Owner",
    price: "₹1,499 / month",
    description: "Ideal for investors and NRI owners managing a small portfolio.",
    tag: "Value",
    features: [
      "Up to 10 active listings",
      "Highlighted listings with premium tags",
      "Lead analytics & conversion tracking",
      "Early access to lead packs",
    ],
  },
  {
    id: "scale",
    name: "Scale (Builder / Portfolio)",
    price: "₹4,999 / month",
    description: "For builders and power owners who need a scalable, always-on presence.",
    tag: "For builders",
    features: [
      "Unlimited active listings (fair usage)",
      "Dedicated success manager (where available)",
      "Bulk uploads & project-level branding",
      "Custom campaigns & spotlight placements",
    ],
  },
];

const Pricing = () => {
  return (
    <div className="max-w-6xl mx-auto px-4 py-12">
      <div className="mb-10 text-center">
        <h1 className="text-3xl md:text-4xl font-bold text-slate-900 mb-3">Pricing & Plans</h1>
        <p className="text-slate-600 text-base md:text-lg max-w-2xl mx-auto">
          DealDirect keeps the core experience accessible for everyone while advanced tools and visibility boosters are
          offered on simple, predictable plans for owners and partners.
        </p>
      </div>

      {/* Owner Subscription Plans */}
      <section className="mb-12">
        <div className="flex items-center justify-between gap-4 mb-4">
          <div className="text-left">
            <h2 className="text-xl md:text-2xl font-semibold text-slate-900">Owner Subscription Plans</h2>
            <p className="text-slate-600 text-sm md:text-base max-w-xl">
              Choose a plan that matches how actively you are selling or renting. Upgrade or downgrade anytime.
            </p>
          </div>
          <div className="hidden sm:flex flex-col items-end text-right text-xs text-slate-500">
            <span className="font-medium text-emerald-600">No brokerage. No lock-in.</span>
            <span>Billed monthly in INR • Taxes extra as applicable</span>
          </div>
        </div>

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className={`relative border rounded-3xl p-5 flex flex-col h-full bg-white shadow-sm border-slate-200`}
            >
              {plan.tag && (
                <span className="absolute -top-3 left-4 inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-red-50 text-red-700 border border-red-100">
                  {plan.tag}
                </span>
              )}
              <div className="mb-4 mt-1">
                <h3 className="text-lg font-semibold text-slate-900">{plan.name}</h3>
                <p className="text-sm text-slate-500 mt-1">{plan.description}</p>
              </div>
              <div className="mb-4">
                <span className="text-2xl font-bold text-slate-900">{plan.price}</span>
              </div>
              <ul className="space-y-2 text-sm text-slate-700 flex-1 mb-4">
                {plan.features.map((f) => (
                  <li key={f} className="flex items-start gap-2">
                    <span className="mt-1 h-1.5 w-1.5 rounded-full bg-emerald-500" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <button className="mt-auto w-full inline-flex items-center justify-center rounded-xl bg-slate-900 text-white text-sm font-semibold py-2.5 hover:bg-slate-800 transition disabled:opacity-60" disabled>
                Coming Soon
              </button>
              <p className="mt-2 text-[11px] text-slate-500">
                Need this now? <Link to="/contact" className="text-red-600 hover:text-red-700 font-medium">Talk to us</Link> for early access.
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Other Revenue Streams Overview */}
      <section className="mb-10">
        <h2 className="text-xl md:text-2xl font-semibold text-slate-900 mb-3">How Else Does DealDirect Earn?</h2>
        <p className="text-slate-600 text-sm md:text-base max-w-3xl mb-5">
          Beyond subscriptions, we monetise through value-added services and partnerships so that we never have to sneak
          in hidden charges or brokerage.
        </p>

        <div className="grid gap-5 md:grid-cols-2">
          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Lead Packs</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Owners • Rent ₹20–₹50/lead • Sale ₹100–₹200/lead</p>
            <p className="text-sm text-slate-600">
              Verified, intent-based buyer/tenant leads that owners can purchase in small packs when they need an extra
              push on demand.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">DealSuccess Fee (Optional)</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Owners • Rent 10–20% of 1-month rent • Sale 0.5%</p>
            <p className="text-sm text-slate-600">
              For owners who opt-in for extra support, a small fee is charged only when a deal successfully closes
              through DealDirect.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Home Services Marketplace</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Service Providers • 15–25% commission</p>
            <p className="text-sm text-slate-600">
              Movers, cleaning, painting, interiors and more. We charge partners a commission per completed job, not
              the end user.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Loan & Finance Partnerships</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Banks & NBFCs • ~₹1,000–₹4,000 / approved loan</p>
            <p className="text-sm text-slate-600">
              When buyers opt to explore loans, we may route them to partner institutions and earn a fee per approved
              case.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Ads & Featured Spots</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Developers & Brands • ~₹15,000–₹50,000 / month</p>
            <p className="text-sm text-slate-600">
              Clearly labelled project promotions, banners and featured home services, designed to be helpful and
              non-intrusive.
            </p>
          </div>

          <div className="border border-slate-200 rounded-2xl p-4 bg-slate-50/70">
            <h3 className="text-base font-semibold text-slate-900 mb-1">Verification & Premium Tools</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Owners / Tenants • ₹249–₹699 • ₹49–₹99 per tool</p>
            <p className="text-sm text-slate-600">
              Optional verification (KYC, documents, screening) and smart tools for seekers like price alerts and
              insights, each offered as small, clear add-ons.
            </p>
          </div>
        </div>
      </section>

      <div className="mt-6 border border-amber-100 bg-amber-50 text-amber-900 text-sm rounded-2xl p-4 space-y-1">
        <p>
          All pricing mentioned here is indicative and subject to refinement as we learn from real users. Before any
          paid feature goes live, it will be clearly marked and explained inside your dashboard.
        </p>
        <p>
          Owners will see options for lead packs, verification, home services and add-ons inside My Properties and the
          post-listing flows, while buyers and tenants will discover premium tools like alerts and insights around
          Saved Searches and Notifications.
        </p>
      </div>
    </div>
  );
};

export default Pricing;
