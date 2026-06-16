'use client';
import React, { useState } from 'react';
import Link from 'next/link';
import { FaBed, FaBath, FaRulerCombined, FaCompass, FaCouch, FaPhone, FaWhatsapp, FaCheckCircle, FaParking } from 'react-icons/fa';
import { ChevronLeft, Shield, MapPin, Layers, Home, Tag, ArrowRight } from 'lucide-react';
import BookingModal from './BookingModal';

const FALLBACK = "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800";
const fmt = (n) => n ? `₹${n >= 1e7 ? (n/1e7).toFixed(2)+'Cr' : (n/1e5).toFixed(2)+'L'}` : null;
const fmtN = (n) => n?.toLocaleString('en-IN');

function SpecRow({ label, value }) {
  if (!value) return null;
  return (
    <div className="flex justify-between py-2.5 border-b border-slate-100 last:border-0 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="font-semibold text-slate-800 text-right max-w-[55%]">{value}</span>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-5">
      <h2 className="font-bold text-slate-900 mb-4 text-base">{title}</h2>
      {children}
    </div>
  );
}

export default function UnitDetailContent({ unitType: ut, project: p }) {
  const [showBooking, setShowBooking] = useState(false);
  const loc = [p.location?.locality, p.location?.city, p.location?.state].filter(Boolean).join(', ');
  const price = ut.pricing?.effectivePrice;
  const base = ut.pricing?.basePrice;
  const charges = ut.pricing?.additionalCharges || {};
  const fp2d = ut.floorPlans?.twoDUrl;
  const fp3d = ut.floorPlans?.threeDUrl;
  const specs = ut.specifications || {};
  const tokenAmount = p.financials?.bookingAmount || 0;

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Breadcrumb */}
      <div className="bg-white border-b border-slate-200 py-3 px-4 pt-4">
        <div className="max-w-6xl mx-auto flex items-center gap-2 text-sm text-slate-500">
          <Link href="/" className="hover:text-indigo-600">Home</Link><span>&gt;</span>
          <Link href="/projects" className="hover:text-indigo-600">Projects</Link><span>&gt;</span>
          <Link href={`/projects/${p._id}`} className="hover:text-indigo-600">{p.basics?.name}</Link><span>&gt;</span>
          <span className="text-slate-800 font-medium">{ut.config?.name}</span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* ── LEFT ── */}
        <div className="lg:col-span-2 space-y-5">

          {/* Hero */}
          <div className="bg-white rounded-2xl border border-slate-200 p-6">
            <Link href={`/projects/${p._id}`} className="inline-flex items-center gap-1 text-sm text-indigo-600 hover:text-indigo-800 mb-4 font-medium">
              <ChevronLeft size={16} /> Back to {p.basics?.name}
            </Link>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-2xl font-extrabold text-slate-900 mb-1">{ut.config?.name}</h1>
                <p className="text-slate-500 flex items-center gap-1.5 text-sm"><MapPin size={13} className="text-red-500" /> {loc}</p>
                <div className="flex flex-wrap gap-2 mt-3">
                  {ut.config?.bedrooms && <span className="flex items-center gap-1.5 text-sm bg-slate-100 px-3 py-1 rounded-full text-slate-700"><FaBed size={12}/> {ut.config.bedrooms} BHK</span>}
                  {ut.config?.bathrooms && <span className="flex items-center gap-1.5 text-sm bg-slate-100 px-3 py-1 rounded-full text-slate-700"><FaBath size={12}/> {ut.config.bathrooms} Bath</span>}
                  {ut.area?.carpetSqft && <span className="flex items-center gap-1.5 text-sm bg-slate-100 px-3 py-1 rounded-full text-slate-700"><FaRulerCombined size={12}/> {fmtN(ut.area.carpetSqft)} sqft</span>}
                  {ut.facing?.length > 0 && <span className="flex items-center gap-1.5 text-sm bg-slate-100 px-3 py-1 rounded-full text-slate-700"><FaCompass size={12}/> {ut.facing.join(', ')}</span>}
                  {ut.furnishing && ut.furnishing !== 'Bare Shell' && <span className="flex items-center gap-1.5 text-sm bg-slate-100 px-3 py-1 rounded-full text-slate-700"><FaCouch size={12}/> {ut.furnishing}</span>}
                </div>
              </div>
              <div className="text-right">
                <p className="text-3xl font-extrabold text-slate-900">{fmt(price) || 'Price on request'}</p>
                {ut.area?.carpetSqft && price && <p className="text-sm text-slate-400">₹{Math.round(price/ut.area.carpetSqft).toLocaleString('en-IN')}/sqft</p>}
                <div className="flex items-center gap-2 mt-1 justify-end text-sm text-slate-500">
                  <span className="text-emerald-600 font-semibold">{ut.inventory?.availableUnits ?? '—'} available</span>
                  <span>of {ut.inventory?.totalUnits ?? '—'} total</span>
                </div>
              </div>
            </div>
          </div>

          {/* Floor Plans */}
          {(fp2d || fp3d) && (
            <Section title="Floor Plans">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {fp2d && (
                  <a href={fp2d} target="_blank" rel="noopener noreferrer" className="block group">
                    <div className="relative rounded-xl overflow-hidden border border-slate-200 bg-slate-50 h-52">
                      <img src={fp2d} alt="2D Floor Plan" className="w-full h-full object-contain group-hover:scale-105 transition-transform duration-300"
                        onError={e => { e.target.onerror=null; e.target.src=FALLBACK; }} />
                      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/10 transition flex items-center justify-center">
                        <span className="opacity-0 group-hover:opacity-100 transition bg-white text-slate-800 text-xs font-semibold px-3 py-1.5 rounded-full shadow">View Full Size</span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-slate-700 mt-2 text-center">2D Floor Plan</p>
                  </a>
                )}
                {fp3d && (
                  <a href={fp3d} target="_blank" rel="noopener noreferrer" className="block group">
                    <div className="relative rounded-xl overflow-hidden border border-slate-200 bg-slate-50 h-52">
                      <img src={fp3d} alt="3D Floor Plan" className="w-full h-full object-contain group-hover:scale-105 transition-transform duration-300"
                        onError={e => { e.target.onerror=null; e.target.src=FALLBACK; }} />
                      <div className="absolute inset-0 bg-black/0 group-hover:bg-black/10 transition flex items-center justify-center">
                        <span className="opacity-0 group-hover:opacity-100 transition bg-white text-slate-800 text-xs font-semibold px-3 py-1.5 rounded-full shadow">View Full Size</span>
                      </div>
                    </div>
                    <p className="text-sm font-medium text-slate-700 mt-2 text-center">3D Floor Plan</p>
                  </a>
                )}
              </div>
            </Section>
          )}

          {/* Area Details */}
          <Section title="Area Details">
            <div className="grid grid-cols-3 gap-4">
              {[['Carpet Area', ut.area?.carpetSqft, 'sqft'], ['Built-up Area', ut.area?.builtUpSqft, 'sqft'], ['Super Built-up', ut.area?.superBuiltUpSqft, 'sqft']].map(([label, val, unit]) =>
                val ? (
                  <div key={label} className="bg-slate-50 rounded-xl p-4 text-center">
                    <p className="text-xs text-slate-400 mb-1">{label}</p>
                    <p className="font-bold text-slate-900 text-lg">{fmtN(val)}</p>
                    <p className="text-xs text-slate-400">{unit}</p>
                  </div>
                ) : null
              )}
            </div>
          </Section>

          {/* Specifications */}
          {(specs.flooring || specs.kitchen || specs.bathroom || specs.doors || specs.electrical) && (
            <Section title="Specifications">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
                {specs.flooring && Object.values(specs.flooring).some(Boolean) && (
                  <div>
                    <p className="text-xs font-bold text-slate-400 uppercase mb-2">Flooring</p>
                    <SpecRow label="Living / Dining" value={specs.flooring.livingDining} />
                    <SpecRow label="Bedrooms" value={specs.flooring.bedrooms} />
                    <SpecRow label="Kitchen" value={specs.flooring.kitchen} />
                    <SpecRow label="Bathroom" value={specs.flooring.bathroom} />
                    <SpecRow label="Balcony" value={specs.flooring.balcony} />
                  </div>
                )}
                {specs.kitchen && (
                  <div>
                    <p className="text-xs font-bold text-slate-400 uppercase mb-2">Kitchen</p>
                    <SpecRow label="Countertop" value={specs.kitchen.countertop} />
                    <SpecRow label="Modular" value={specs.kitchen.isModular ? 'Yes' : null} />
                    <SpecRow label="Chimney" value={specs.kitchen.chimney ? 'Included' : null} />
                    <SpecRow label="Sink" value={specs.kitchen.sink} />
                  </div>
                )}
                {specs.bathroom && (
                  <div>
                    <p className="text-xs font-bold text-slate-400 uppercase mb-2">Bathroom</p>
                    <SpecRow label="Sanitary Brand" value={specs.bathroom.sanitaryBrand} />
                    <SpecRow label="Fittings Brand" value={specs.bathroom.fittingsBrand} />
                    <SpecRow label="Dado Height" value={specs.bathroom.dadoHeight} />
                  </div>
                )}
                {specs.doors && (
                  <div>
                    <p className="text-xs font-bold text-slate-400 uppercase mb-2">Doors & Windows</p>
                    <SpecRow label="Main Door" value={specs.doors.mainDoor} />
                    <SpecRow label="Internal Doors" value={specs.doors.internalDoors} />
                    <SpecRow label="Finish" value={specs.doors.finish} />
                    <SpecRow label="Windows" value={specs.windows?.type} />
                    <SpecRow label="Mosquito Mesh" value={specs.windows?.mosquitoMesh ? 'Included' : null} />
                  </div>
                )}
                {specs.electrical && (
                  <div>
                    <p className="text-xs font-bold text-slate-400 uppercase mb-2">Electrical</p>
                    <SpecRow label="Wiring" value={specs.electrical.wiringType} />
                    <SpecRow label="Switch Brand" value={specs.electrical.switchBrand} />
                    <SpecRow label="AC Points/Room" value={specs.electrical.acPointsPerRoom} />
                  </div>
                )}
              </div>
            </Section>
          )}

          {/* Parking */}
          {(ut.parking?.covered > 0 || ut.parking?.open > 0 || ut.parking?.ev > 0) && (
            <Section title="Parking">
              <div className="flex flex-wrap gap-4">
                {ut.parking.covered > 0 && <div className="flex items-center gap-2 bg-slate-50 rounded-xl px-4 py-3"><FaParking className="text-indigo-500"/> <span className="text-sm font-medium text-slate-700">{ut.parking.covered} Covered</span></div>}
                {ut.parking.open > 0 && <div className="flex items-center gap-2 bg-slate-50 rounded-xl px-4 py-3"><FaParking className="text-slate-400"/> <span className="text-sm font-medium text-slate-700">{ut.parking.open} Open</span></div>}
                {ut.parking.ev > 0 && <div className="flex items-center gap-2 bg-slate-50 rounded-xl px-4 py-3"><FaParking className="text-emerald-500"/> <span className="text-sm font-medium text-slate-700">{ut.parking.ev} EV Charging</span></div>}
              </div>
            </Section>
          )}

          {/* Unit Highlights */}
          {ut.highlights?.length > 0 && (
            <Section title="Unit Highlights">
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {ut.highlights.map((h, i) => (
                  <li key={i} className="flex items-center gap-2 text-sm text-slate-700">
                    <FaCheckCircle className="text-emerald-500 flex-shrink-0" size={13} /> {h}
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>

        {/* ── RIGHT SIDEBAR ── */}
        <div>
          <div className="sticky top-24 space-y-4">
            {/* Pricing Breakdown */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5">
              <h3 className="font-bold text-slate-900 mb-4">Pricing Breakdown</h3>
              <div className="space-y-2.5 text-sm">
                <div className="flex justify-between"><span className="text-slate-500">Base Price</span><span className="font-semibold">{fmt(base) || '—'}</span></div>
                {charges.plc > 0 && <div className="flex justify-between"><span className="text-slate-500">PLC Charges</span><span className="font-semibold">{fmt(charges.plc)}</span></div>}
                {charges.parking > 0 && <div className="flex justify-between"><span className="text-slate-500">Parking</span><span className="font-semibold">{fmt(charges.parking)}</span></div>}
                {charges.clubhouse > 0 && <div className="flex justify-between"><span className="text-slate-500">Clubhouse</span><span className="font-semibold">{fmt(charges.clubhouse)}</span></div>}
                {charges.legal > 0 && <div className="flex justify-between"><span className="text-slate-500">Legal Charges</span><span className="font-semibold">{fmt(charges.legal)}</span></div>}
                {charges.maintenance > 0 && <div className="flex justify-between"><span className="text-slate-500">Maintenance</span><span className="font-semibold">{fmt(charges.maintenance)}</span></div>}
                {ut.pricing?.viewPremium > 0 && <div className="flex justify-between"><span className="text-slate-500">View Premium</span><span className="font-semibold">{fmt(ut.pricing.viewPremium)}</span></div>}
                <div className="flex justify-between pt-2.5 border-t border-slate-200"><span className="font-bold text-slate-900">Total Price</span><span className="font-extrabold text-indigo-700 text-base">{fmt(price) || '—'}</span></div>
                {p.financials?.gstPercentage && <div className="flex justify-between text-xs text-slate-400"><span>+ GST</span><span>{p.financials.gstPercentage}%</span></div>}
                {p.financials?.stampDutyPercentage && <div className="flex justify-between text-xs text-slate-400"><span>+ Stamp Duty</span><span>{p.financials.stampDutyPercentage}%</span></div>}
              </div>

              {/* Book Now CTA */}
              <div className="mt-5 space-y-2">
                <button onClick={() => setShowBooking(true)}
                  className="w-full py-3 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition flex items-center justify-center gap-2">
                  Book Now — Pay ₹{tokenAmount.toLocaleString('en-IN')} Token
                  <ArrowRight size={16} />
                </button>
                {p.salesContact?.phone && (
                  <a href={`tel:${p.salesContact.phone}`} className="w-full py-2.5 border border-slate-200 text-slate-700 rounded-xl font-semibold text-sm hover:bg-slate-50 transition flex items-center justify-center gap-2">
                    <FaPhone size={12}/> Call Sales Team
                  </a>
                )}
                {p.salesContact?.whatsapp && (
                  <a href={`https://wa.me/91${p.salesContact.whatsapp}?text=Hi, I'm interested in ${ut.config?.name} at ${p.basics?.name}`} target="_blank" rel="noopener noreferrer"
                    className="w-full py-2.5 bg-green-500 text-white rounded-xl font-semibold text-sm hover:bg-green-600 transition flex items-center justify-center gap-2">
                    <FaWhatsapp /> WhatsApp
                  </a>
                )}
              </div>
            </div>

            {/* Project Info */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5">
              <h3 className="font-bold text-slate-900 mb-3">About the Project</h3>
              <Link href={`/projects/${p._id}`} className="flex items-start gap-3 group">
                <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center font-bold text-indigo-700 flex-shrink-0">
                  {(p.builder?.company || p.builder?.name || 'B').charAt(0)}
                </div>
                <div>
                  <p className="font-semibold text-slate-900 group-hover:text-indigo-600 transition">{p.basics?.name}</p>
                  <p className="text-xs text-slate-400">{p.builder?.company || p.builder?.name} · {p.basics?.status}</p>
                </div>
              </Link>
              {p.basics?.reraNumber && (
                <div className="mt-3 flex items-center gap-2 text-xs text-emerald-700 bg-emerald-50 px-3 py-2 rounded-lg border border-emerald-100">
                  <Shield size={12}/> RERA: {p.basics.reraNumber}
                </div>
              )}
            </div>

            {/* Inventory Bar */}
            {ut.inventory?.totalUnits > 0 && (
              <div className="bg-white border border-slate-200 rounded-2xl p-5">
                <h3 className="font-bold text-slate-900 mb-3">Availability</h3>
                <div className="w-full bg-slate-100 rounded-full h-2.5 mb-3">
                  <div className="bg-emerald-500 h-2.5 rounded-full transition-all"
                    style={{ width: `${Math.round((ut.inventory.availableUnits / ut.inventory.totalUnits) * 100)}%` }} />
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-emerald-600 font-semibold">{ut.inventory.availableUnits} Available</span>
                  <span className="text-slate-400">{ut.inventory.bookedUnits || 0} Booked</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Booking Modal */}
      {showBooking && (
        <BookingModal
          unitType={ut}
          project={p}
          tokenAmount={tokenAmount}
          onClose={() => setShowBooking(false)}
        />
      )}
    </div>
  );
}
