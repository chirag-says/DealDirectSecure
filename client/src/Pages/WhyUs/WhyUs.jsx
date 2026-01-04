import React from "react";

const WhyUs = () => {
  return (
    <div className="max-w-6xl mx-auto px-4 py-12">
      <div className="bg-white rounded-3xl shadow-sm border border-slate-200 p-8 md:p-12">
        <h1 className="text-3xl md:text-4xl font-bold text-slate-900 mb-4">Why DealDirect?</h1>
        <p className="text-slate-600 text-base md:text-lg mb-8 max-w-3xl">
          We built DealDirect to make property transactions simple, transparent, and fair for both owners and seekers.
          No middlemen, no hidden charges – just clean, data-driven matchmaking.
        </p>

        <div className="grid gap-8 md:grid-cols-3">
          <div className="space-y-3">
            <h2 className="text-xl font-semibold text-slate-900">Direct, No-Broker Model</h2>
            <p className="text-sm text-slate-600">
              Connect directly with verified owners and genuine tenants/buyers. Save on hefty brokerage and have full control
              over your conversations and decisions.
            </p>
          </div>

          <div className="space-y-3">
            <h2 className="text-xl font-semibold text-slate-900">Smart Search & Alerts</h2>
            <p className="text-sm text-slate-600">
              Powerful filters, saved searches, and instant alerts help you find the right property faster – whether
              you are buying, renting, or exploring investment options.
            </p>
          </div>

          <div className="space-y-3">
            <h2 className="text-xl font-semibold text-slate-900">Trust & Transparency</h2>
            <p className="text-sm text-slate-600">
              From detailed listings and rich media to agreement tools and notifications, we keep every step clear so you
              can make confident decisions.
            </p>
          </div>
        </div>

        <div className="mt-10 grid gap-6 md:grid-cols-2">
          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-slate-900">For Property Owners</h3>
            <p className="text-sm text-slate-600">
              List your property in minutes, manage enquiries from a single dashboard, and get notified when serious
              leads show interest. You stay in control from listing to closing.
            </p>
          </div>

          <div className="space-y-3">
            <h3 className="text-lg font-semibold text-slate-900">For Seekers</h3>
            <p className="text-sm text-slate-600">
              Explore curated listings, compare options, save favourites, and receive updates when new properties match
              your preferences.
            </p>
          </div>
        </div>

        {/* Transparent Revenue Model */}
        <div className="mt-12">
          <h2 className="text-2xl md:text-3xl font-bold text-slate-900 mb-3">Simple, Transparent Revenue Model</h2>
          <p className="text-slate-600 text-sm md:text-base max-w-3xl mb-6">
            DealDirect is designed so that the core experience stays accessible while power users and partners pay for
            advanced value. Here is exactly how we plan to earn, without compromising trust between owners and seekers.
          </p>

          <div className="mb-6 flex flex-wrap gap-3">
            <a
              href="/pricing"
              className="inline-flex items-center px-4 py-2 rounded-full bg-slate-900 text-white text-xs md:text-sm font-semibold hover:bg-slate-800 transition"
            >
              View detailed Pricing & Plans
              <span className="ml-1 text-[13px]">→</span>
            </a>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            {/* 1. Freemium Listings */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">1. Freemium Listings</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Property Owners</p>
              <p className="text-sm text-slate-600 mb-2">
                Basic listings stay <span className="font-semibold text-emerald-600">free</span> so any owner can get
                started. Paid tiers boost visibility in search results and highlight serious, well-presented listings.
              </p>
              <p className="text-xs text-slate-500">Pricing: Free → ₹299 → ₹999 per listing</p>
            </div>

            {/* 2. Owner Subscription Plans */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">2. Owner Subscription Plans</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Property Owners</p>
              <p className="text-sm text-slate-600 mb-2">
                Power owners and builders can unlock dashboards, deeper lead insights, bulk listing tools, and campaign
                style promotion with simple monthly plans.
              </p>
              <p className="text-xs text-slate-500">Pricing: ₹499 / ₹1,499 / ₹4,999 per month</p>
            </div>

            {/* 3. Lead Packs */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">3. Lead Packs (No-Broker)</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Owners</p>
              <p className="text-sm text-slate-600 mb-2">
                Owners can purchase verified, intent-based buyer or tenant contacts, with clear tracking from first
                enquiry to closure.
              </p>
              <p className="text-xs text-slate-500">Pricing: Rent ₹20–₹50/lead • Sale ₹100–₹200/lead</p>
            </div>

            {/* 4. DealSuccess Fee */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">4. DealSuccess Fee (Optional)</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Owners (on successful deal)</p>
              <p className="text-sm text-slate-600 mb-2">
                For owners who want extra handholding, we may charge a small success fee only when a deal closes through
                DealDirect. No closure, no fee.
              </p>
              <p className="text-xs text-slate-500">Pricing: Rent 10–20% of 1-month rent • Sale 0.5%</p>
            </div>

            {/* 5. Home Services Marketplace */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">5. Home Services Marketplace</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Service Providers</p>
              <p className="text-sm text-slate-600 mb-2">
                Movers, cleaners, painting, interiors and more – we partner with trusted vendors and charge them a
                commission for confirmed jobs, not the end user.
              </p>
              <p className="text-xs text-slate-500">Pricing: 15–25% commission on service value</p>
            </div>

            {/* 6. Loan Partnerships */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">6. Loan & Finance Partnerships</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Partner Banks/NBFCs</p>
              <p className="text-sm text-slate-600 mb-2">
                When buyers opt to explore home loans, we may pass qualified leads to partner institutions and earn a
                fee per approved loan.
              </p>
              <p className="text-xs text-slate-500">Pricing: ~₹1,000–₹4,000 per approved loan</p>
            </div>

            {/* 7. Advertisements */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">7. Smart, Non-Intrusive Ads</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Brands & Service Providers</p>
              <p className="text-sm text-slate-600 mb-2">
                Selective project promotions, banners and featured slots for developers and home service brands – always
                labelled, never mixed with organic results.
              </p>
              <p className="text-xs text-slate-500">Pricing: ~₹15,000–₹50,000 per month</p>
            </div>

            {/* 8. Verification Services */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">8. Verification & Screening</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Owners / Tenants</p>
              <p className="text-sm text-slate-600 mb-2">
                Optional verification checks – from owner KYC and document validation to tenant screening – to build
                more trust into every interaction.
              </p>
              <p className="text-xs text-slate-500">Pricing: ~₹249–₹699 per verification</p>
            </div>

            {/* 9. Premium Tools for Buyers & Tenants */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">9. Premium Tools for Seekers</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Buyers / Tenants</p>
              <p className="text-sm text-slate-600 mb-2">
                Advanced features like granular price alerts, smart saved searches, neighbourhood insights and
                affordability calculators will be available as small add-ons.
              </p>
              <p className="text-xs text-slate-500">Pricing: ~₹49–₹99 per premium feature</p>
            </div>

            {/* 10. Home Discovery Add-ons */}
            <div className="border border-slate-200 rounded-2xl p-5 bg-slate-50/60">
              <h3 className="text-base font-semibold text-slate-900 mb-1">10. Home Discovery Add-ons</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">Who pays: Owners</p>
              <p className="text-sm text-slate-600 mb-2">
                Rich media experiences – virtual tours, 3D walkthroughs, drone videos and more – that help serious buyers
                experience the property before stepping in.
              </p>
              <p className="text-xs text-slate-500">Pricing: ~₹499–₹2,999 per shoot</p>
            </div>
          </div>
        </div>

        <div className="mt-10 p-4 rounded-2xl bg-red-50 border border-red-100 text-sm text-red-900">
          DealDirect is continuously evolving – we ship new features often, based on real user feedback. If you have
          suggestions, we would love to hear from you via the Contact page.
        </div>
      </div>
    </div>
  );
};

export default WhyUs;
