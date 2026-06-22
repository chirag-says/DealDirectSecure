'use client';
import React, { useState } from 'react';
import Link from 'next/link';
import { FaMapMarkerAlt, FaPhone, FaWhatsapp, FaEnvelope, FaCheckCircle, FaFilePdf, FaBed, FaBath, FaRulerCombined, FaCompass, FaCouch, FaUsers } from 'react-icons/fa';
import { Building2, CheckCircle, ChevronLeft, ChevronRight, Layers, Star, Shield, MapPin, Home, Calendar, TreePine, Key, TowerControl, Building, BarChart3 } from 'lucide-react';

const FALLBACK = "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800";
const STATUS_BADGE = { "New Launch": "bg-indigo-600 text-white", "Under Construction": "bg-red-600 text-white", "Ready To Move": "bg-emerald-600 text-white", "Completed": "bg-slate-600 text-white" };
const toArray = (v) => { if (!v) return []; if (Array.isArray(v)) return v.filter(Boolean); if (typeof v === 'string' && v.trim()) return [v.trim()]; return []; };
const toHighlights = (v) => { if (!v) return []; if (Array.isArray(v)) return v.filter(Boolean); if (typeof v === 'string') { try { const p = JSON.parse(v); if (Array.isArray(p)) return p; } catch {} return v.split(/[,;|\n]/).map(s => s.trim()).filter(Boolean); } return []; };
const fmtDate = (d) => d ? new Date(d).toLocaleDateString("en-IN", { month: "short", year: "numeric" }) : null;

function ImageGallery({ images = [] }) {
  const all = images.length > 0 ? images : [FALLBACK];
  const [idx, setIdx] = useState(0);
  return (
    <div>
      <div className="relative h-72 sm:h-[400px] rounded-2xl overflow-hidden bg-slate-900">
        <img src={all[idx] || FALLBACK} alt="Project" className="w-full h-full object-cover" onError={(e) => { e.target.onerror = null; e.target.src = FALLBACK; }} />
        {all.length > 1 && (<>
          <button onClick={() => setIdx(i => (i - 1 + all.length) % all.length)} className="absolute left-3 top-1/2 -translate-y-1/2 p-2.5 bg-white/90 text-slate-800 rounded-full hover:bg-white transition shadow-lg"><ChevronLeft size={18} /></button>
          <button onClick={() => setIdx(i => (i + 1) % all.length)} className="absolute right-3 top-1/2 -translate-y-1/2 p-2.5 bg-white/90 text-slate-800 rounded-full hover:bg-white transition shadow-lg"><ChevronRight size={18} /></button>
          <span className="absolute bottom-3 right-4 bg-black/60 text-white text-xs px-3 py-1 rounded-full font-medium">{idx + 1} / {all.length}</span>
        </>)}
      </div>
      {all.length > 1 && (
        <div className="flex gap-2 mt-3 overflow-x-auto pb-1">
          {all.map((img, i) => (
            <button key={i} onClick={() => setIdx(i)} className={`flex-shrink-0 w-16 h-16 rounded-xl overflow-hidden border-2 transition ${i === idx ? 'border-indigo-500 ring-2 ring-indigo-200' : 'border-transparent hover:border-slate-300'}`}>
              <img src={img} alt="" className="w-full h-full object-cover" onError={(e) => { e.target.onerror = null; e.target.src = FALLBACK; }} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function StatCard({ icon: Icon, label, value }) {
  if (!value) return null;
  return (
    <div className="flex items-center gap-3 p-3">
      <div className="w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center flex-shrink-0">
        <Icon size={16} className="text-slate-500" />
      </div>
      <div>
        <p className="text-[11px] text-slate-400 leading-tight">{label}</p>
        <p className="font-bold text-slate-900 text-sm">{value}</p>
      </div>
    </div>
  );
}

function UnitTypeCard({ ut, projectId }) {
  const price = ut.pricing?.effectivePrice;
  return (
    <div className="border-b border-slate-100 pb-4 mb-4 last:border-0 last:pb-0 last:mb-0">
      <h4 className="font-bold text-slate-900 mb-2">{ut.config?.name}</h4>
      <div className="text-sm text-slate-600 space-y-1.5 mb-3">
        {ut.config?.bedrooms && <p className="flex items-center gap-2"><FaBed className="text-slate-400" size={12} /> {ut.config.bedrooms} BHK {ut.config.bathrooms && <><span className="text-slate-300 mx-1">·</span> <FaBath className="text-slate-400" size={12} /> {ut.config.bathrooms} Bath</>}</p>}
        {ut.area?.carpetSqft && <p className="flex items-center gap-2"><FaRulerCombined className="text-slate-400" size={12} /> {ut.area.carpetSqft.toLocaleString('en-IN')} sqft carpet {ut.area?.superBuiltUpSqft && <> · {ut.area.superBuiltUpSqft.toLocaleString('en-IN')} sqft super built-up</>}</p>}
        {ut.facing?.length > 0 && <p className="flex items-center gap-2"><FaCompass className="text-slate-400" size={12} /> {ut.facing.join(", ")} Facing</p>}
        {ut.furnishing && <p className="flex items-center gap-2"><FaCouch className="text-slate-400" size={12} /> {ut.furnishing}</p>}
      </div>
      <div className="flex items-end justify-between">
        <div>
          {price ? (<>
            <p className="text-xl font-extrabold text-slate-900">₹{price >= 1e7 ? `${(price/1e7).toFixed(2)}Cr` : `${(price/1e5).toFixed(2)}L`}</p>
            {ut.area?.carpetSqft && <p className="text-xs text-slate-400">₹{Math.round(price / ut.area.carpetSqft).toLocaleString('en-IN')}/sqft</p>}
          </>) : <p className="text-sm text-slate-400">Price on request</p>}
        </div>
        <div className="text-right text-xs text-slate-500">
          <p>{ut.inventory?.availableUnits ?? "—"} available</p>
          <p className="text-slate-400">of {ut.inventory?.totalUnits ?? "—"} total</p>
        </div>
      </div>
      <Link href={`/projects/${projectId}/units/${ut._id}`}
        className="mt-3 inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white text-xs font-semibold rounded-lg hover:bg-indigo-700 transition">
        View Details & Book →
      </Link>
    </div>
  );
}

export default function ProjectDetailContent({ project, unitTypes = [] }) {
  const p = project;
  const status = p.basics?.status || "New Launch";
  const loc = [p.location?.locality, p.location?.microMarket, p.location?.city, p.location?.state].filter(Boolean).join(", ");
  const exteriorImages = toArray(p.media?.exteriorImages);
  const droneImages = toArray(p.media?.droneImages);
  const masterPlanImages = toArray(p.media?.masterPlan);
  const allImages = [...exteriorImages, ...droneImages];
  const highlights = toHighlights(p.basics?.highlights);
  const amenities = Array.isArray(p.amenities) ? p.amenities : [];

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="bg-white border-b border-slate-200 pt-4 pb-4 px-4">
        <div className="max-w-6xl mx-auto flex items-center gap-2 text-sm text-slate-500">
          <Link href="/" className="hover:text-indigo-600">Home</Link><span>&gt;</span>
          <Link href="/projects" className="hover:text-indigo-600">Projects</Link><span>&gt;</span>
          <span className="text-slate-800 font-medium truncate">{p.basics?.name}</span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 py-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* ── LEFT COLUMN ── */}
        <div className="lg:col-span-2 space-y-6">
          <ImageGallery images={allImages} />

          {/* Badges + Title */}
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <span className={`text-xs font-bold px-3 py-1.5 rounded-lg ${STATUS_BADGE[status]}`}>{status}</span>
              <span className="text-xs text-slate-600 px-3 py-1.5 rounded-lg border border-slate-200 font-medium bg-white">{p.basics?.subType || p.basics?.category}</span>
              {p.basics?.reraNumber && (
                <span className="text-xs text-emerald-700 px-3 py-1.5 rounded-lg border border-emerald-200 bg-emerald-50 font-medium flex items-center gap-1.5">
                  <span className="w-3.5 h-3.5 rounded-full bg-emerald-500 flex items-center justify-center flex-shrink-0">
                    <svg width="8" height="8" viewBox="0 0 8 8" fill="none"><path d="M1.5 4L3 5.5L6.5 2" stroke="white" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                  </span>
                  RERA Verified
                </span>
              )}
              {p.basics?.isVastuCompliant && (
                <span className="text-xs text-violet-700 px-3 py-1.5 rounded-lg border border-violet-200 bg-violet-50 font-medium">Vastu</span>
              )}
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 mb-1">{p.basics?.name}</h1>
            <p className="text-slate-500 flex items-center gap-1.5 text-sm"><FaMapMarkerAlt className="text-red-500 text-xs" /> {loc || "India"}</p>
            {p.basics?.description && <p className="text-slate-600 text-sm mt-3 leading-relaxed">{p.basics.description}</p>}
          </div>

          {/* ── PROJECT OVERVIEW (full width) ── */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5">
            <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2"><Building2 size={16} /> Project Overview</h2>
            <div className="grid grid-cols-3 gap-1">
              <StatCard icon={Home} label="Total Units" value={p.overview?.totalUnits} />
              <StatCard icon={Building} label="Towers" value={p.overview?.totalTowers} />
              <StatCard icon={BarChart3} label="Floors/Tower" value={p.overview?.floorsPerTower} />
              <StatCard icon={Layers} label="Land Area" value={p.overview?.totalLandArea} />
              <StatCard icon={TreePine} label="Open Space" value={p.overview?.openSpacePercentage ? `${p.overview.openSpacePercentage}%` : null} />
              <StatCard icon={Calendar} label="Possession" value={fmtDate(p.overview?.possessionDate)} />
              <StatCard icon={Calendar} label="Launch Date" value={fmtDate(p.overview?.launchDate)} />
              <StatCard icon={Key} label="Ownership" value={p.basics?.ownershipType} />
            </div>
          </div>

          {/* ── CONFIGS + AMENITIES (side by side) ── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {unitTypes.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2"><Layers size={16} /> Available Configurations</h2>
                {unitTypes.map(ut => <UnitTypeCard key={ut._id} ut={ut} projectId={p._id} />)}
              </div>
            )}
            {amenities.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h2 className="font-bold text-slate-900 mb-4">Amenities</h2>
                <div className="grid grid-cols-2 gap-x-6 gap-y-3">
                  {amenities.map((a, i) => (
                    <div key={i} className="flex items-center gap-2.5 text-sm text-slate-700">
                      <FaCheckCircle className="text-emerald-500 flex-shrink-0" size={13} /> {a.name}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ── NEARBY INFRASTRUCTURE ── */}
          {p.nearbyPlaces?.length > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5">
              <h2 className="font-bold text-slate-900 mb-4">Nearby Infrastructure</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {p.nearbyPlaces.map((n, i) => (
                  <div key={i} className="flex items-center justify-between text-sm bg-slate-50 rounded-xl px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="w-9 h-9 rounded-lg bg-indigo-50 flex items-center justify-center"><MapPin size={14} className="text-indigo-500" /></span>
                      <div><p className="text-[11px] text-slate-400">{n.category}</p><p className="text-slate-700 font-medium">{n.name}</p></div>
                    </div>
                    <span className="text-indigo-600 font-semibold text-xs">{n.distance}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Documents */}
          {(p.documents?.reraCertificateUrl || p.media?.brochureUrl) && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5">
              <h2 className="font-bold text-slate-900 mb-4">Documents</h2>
              <div className="flex flex-wrap gap-3">
                {p.media?.brochureUrl && <a href={p.media.brochureUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-4 py-2.5 bg-red-50 text-red-700 border border-red-200 rounded-xl text-sm font-medium hover:bg-red-100 transition"><FaFilePdf /> Download Brochure</a>}
                {p.documents?.reraCertificateUrl && <a href={p.documents.reraCertificateUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-4 py-2.5 bg-green-50 text-green-700 border border-green-200 rounded-xl text-sm font-medium hover:bg-green-100 transition"><Shield size={14} /> RERA Certificate</a>}
              </div>
            </div>
          )}
        </div>

        {/* ── RIGHT SIDEBAR ── */}
        <div className="space-y-4">
          <div className="sticky top-24 space-y-4">
            {p.builder && (
              <div className="bg-white border border-slate-200 rounded-2xl p-5">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center font-bold text-slate-600 text-xl border border-slate-200 overflow-hidden">
                    {p.builder.logoUrl ? (
                      <img src={p.builder.logoUrl} alt={p.builder.company || p.builder.name} className="w-full h-full object-cover" />
                    ) : (
                      (p.builder.company || p.builder.name || "B").charAt(0)
                    )}
                  </div>
                  <div>
                    <p className="font-bold text-slate-900 flex items-center gap-1.5">{p.builder.company || p.builder.name} <FaCheckCircle className="text-blue-500" size={12} /></p>
                    <p className="text-xs text-slate-400">Verified Developer</p>
                  </div>
                </div>
                <h3 className="text-sm font-semibold text-slate-700 mb-3">Contact Sales Team</h3>
                <div className="space-y-2">
                  {p.salesContact?.phone && <a href={`tel:${p.salesContact.phone}`} className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition"><FaPhone size={12} /> {p.salesContact.phone}</a>}
                  {p.salesContact?.whatsapp && <a href={`https://wa.me/91${p.salesContact.whatsapp}`} target="_blank" rel="noopener noreferrer" className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-green-500 text-white rounded-xl text-sm font-semibold hover:bg-green-600 transition"><FaWhatsapp /> WhatsApp</a>}
                  {p.salesContact?.email && <a href={`mailto:${p.salesContact.email}`} className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-white text-slate-700 border border-slate-200 rounded-xl text-sm font-semibold hover:bg-slate-50 transition"><FaEnvelope /> Email Us</a>}
                </div>
                {p.salesContact?.managerName && <p className="text-xs text-slate-400 text-center mt-3">Ask for: {p.salesContact.managerName}</p>}
              </div>
            )}
            {(p.financials?.bookingAmount || p.financials?.gstPercentage) && (
              <div className="bg-white border border-slate-200 rounded-2xl p-5">
                <h3 className="font-bold text-slate-900 mb-3">Pricing Info</h3>
                <div className="space-y-2.5 text-sm">
                  {p.financials.bookingAmount && <div className="flex justify-between"><span className="text-slate-500">Booking Amount</span><span className="font-bold text-slate-900">₹{p.financials.bookingAmount.toLocaleString('en-IN')}</span></div>}
                  {p.financials.gstPercentage && <div className="flex justify-between"><span className="text-slate-500">GST</span><span className="font-bold text-slate-900">{p.financials.gstPercentage}%</span></div>}
                  {p.financials.stampDutyPercentage && <div className="flex justify-between"><span className="text-slate-500">Stamp Duty</span><span className="font-bold text-slate-900">{p.financials.stampDutyPercentage}%</span></div>}
                </div>
              </div>
            )}

            {highlights.length > 0 && (
              <div className="bg-gradient-to-br from-[#1a1145] to-[#2d1b4e] rounded-2xl p-5 text-white">
                <h3 className="font-bold mb-4 flex items-center gap-2"><Star size={16} className="text-amber-400" /> Highlights</h3>
                <ul className="space-y-3">
                  {highlights.map((h, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-sm text-slate-200 leading-relaxed">
                      <span className="w-5 h-5 rounded-full bg-amber-500/20 flex items-center justify-center flex-shrink-0 mt-0.5"><CheckCircle size={12} className="text-amber-400" /></span> {h}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {masterPlanImages[0] && (
              <div className="bg-white border border-slate-200 rounded-2xl p-5">
                <h3 className="font-bold text-slate-900 mb-3">Master Plan</h3>
                <div className="relative h-48 rounded-xl overflow-hidden">
                  <img src={masterPlanImages[0]} alt="Master Plan" className="w-full h-full object-cover" onError={(e) => { e.target.onerror = null; e.target.src = FALLBACK; }} />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
