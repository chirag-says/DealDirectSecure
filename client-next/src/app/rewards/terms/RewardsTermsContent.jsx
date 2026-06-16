'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowLeft, ShieldCheck, Scale, AlertOctagon, HeartHandshake } from 'lucide-react';

export default function RewardsTermsContent() {
  return (
    <div className="min-h-screen bg-slate-50 pt-28 pb-20 font-sans">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Back Link */}
        <div className="mb-8">
          <Link href="/rewards" className="inline-flex items-center text-red-600 hover:text-red-700 font-medium transition-colors gap-2">
            <ArrowLeft className="w-4 h-4" />
            Back to Rewards
          </Link>
        </div>

        {/* Header */}
        <div className="bg-white rounded-t-3xl border-t border-x border-slate-200 p-8 sm:p-12 text-center relative overflow-hidden">
          <div className="absolute top-0 right-0 w-64 h-64 bg-red-50 rounded-full blur-3xl -z-10 translate-x-1/2 -translate-y-1/2"></div>
          <div className="w-16 h-16 bg-red-100 text-red-600 rounded-2xl flex items-center justify-center mx-auto mb-6">
            <Scale className="w-8 h-8" />
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-900 mb-4">Deal Direct Rewards:<br/>Terms & Fair Play</h1>
          <p className="text-lg text-slate-600 max-w-2xl mx-auto leading-relaxed">
            At Deal Direct, we believe in rewarding genuine engagement. Our rewards program is designed to build a high-quality, broker-free community. To keep the ecosystem fair for everyone, the following terms apply:
          </p>
        </div>

        {/* Content Body */}
        <div className="bg-white rounded-b-3xl border-b border-x border-slate-200 p-8 sm:p-12 shadow-sm space-y-12">
          
          {/* Section 1 */}
          <section>
            <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-3">
              <span className="w-8 h-8 rounded-full bg-red-100 text-red-600 flex items-center justify-center text-sm">1</span>
              Earning Rewards
            </h2>
            <div className="space-y-6 text-slate-600 ml-11">
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Property Posting</h3>
                <p>Rewards are credited once a listing is verified as a "Direct Owner" or "Direct Tenant" post.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Making Enquiries</h3>
                <p>Rewards are granted for genuine inquiries. To prevent "spam-clicking," rewards are capped at a specific number of unique inquiries per day.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Closing a Deal</h3>
                <p>Milestone rewards are released once both parties confirm a successful transaction through the portal.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Referrals</h3>
                <p>Referral rewards are credited only after the referred user completes their profile and makes their first verified post or inquiry.</p>
              </div>
            </div>
          </section>

          {/* Section 2 */}
          <section>
            <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-3">
              <span className="w-8 h-8 rounded-full bg-amber-100 text-amber-600 flex items-center justify-center text-sm"><ShieldCheck className="w-4 h-4" /></span>
              The "Anti-Broker" & Anti-Spam Guardrails
            </h2>
            <div className="space-y-6 text-slate-600 ml-11">
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2 text-red-600">The Power of One</h3>
                <p>Our platform strictly enforces a <strong>1-listing-per-user</strong> limit. Attempting to create multiple accounts to bypass this limit will result in a permanent ban and forfeiture of all accumulated rewards.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Verification</h3>
                <p>We reserve the right to verify any listing. If a post is found to be uploaded by a broker or agency, the post will be removed immediately.</p>
              </div>
            </div>
          </section>

          {/* Section 3 */}
          <section>
            <h2 className="text-2xl font-bold text-slate-900 mb-6 flex items-center gap-3">
              <span className="w-8 h-8 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-sm">3</span>
              Redemption & Validity
            </h2>
            <div className="space-y-6 text-slate-600 ml-11">
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Non-Transferable</h3>
                <p>Rewards earned on DealDirect.in are tied to your specific account and cannot be transferred to other users.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Expiry</h3>
                <p>Rewards may have an expiration period (e.g., 12 months) from the date of credit.</p>
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-800 mb-2">Platform Rights</h3>
                <p>Deal Direct reserves the right to modify the reward values or redemption methods to ensure the sustainability of the platform.</p>
              </div>
            </div>
          </section>

          {/* Section 4 */}
          <section className="bg-slate-50 -mx-8 sm:-mx-12 px-8 sm:px-12 py-8 mt-12 border-t border-slate-200">
            <h2 className="text-2xl font-bold text-slate-900 mb-4 flex items-center gap-3">
              <AlertOctagon className="w-7 h-7 text-red-600" />
              Zero Tolerance for Misuse
            </h2>
            <div className="text-slate-600">
              <p className="mb-4">
                Any attempt to "game" the system (using bots, fake accounts, or fraudulent enquiries) will lead to an immediate account audit. 
              </p>
              <p className="font-bold text-slate-800 flex items-center gap-2">
                <HeartHandshake className="w-5 h-5 text-emerald-600" />
                We value real people making real deals.
              </p>
            </div>
          </section>

        </div>
        
        {/* Footer info */}
        <div className="text-center mt-12 text-sm text-slate-500">
          Last updated: {new Date().toLocaleDateString('en-IN', { month: 'long', year: 'numeric' })}
        </div>
      </div>
    </div>
  );
}
