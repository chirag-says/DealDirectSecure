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

        <div className="mt-10 p-4 rounded-2xl bg-red-50 border border-red-100 text-sm text-red-900">
          DealDirect is continuously evolving – we ship new features often, based on real user feedback. If you have
          suggestions, we would love to hear from you via the Contact page.
        </div>
      </div>
    </div>
  );
};

export default WhyUs;
