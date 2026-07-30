'use client';
import React, { useState } from 'react';
import Link from 'next/link';
import { FaMapMarkerAlt, FaPhoneAlt, FaWhatsapp, FaEnvelope, FaCheckCircle, FaFilePdf, FaBed, FaBath, FaRulerCombined, FaCompass, FaCouch, FaUsers, FaGift, FaFire } from 'react-icons/fa';
import { Building2, CheckCircle, ChevronLeft, ChevronRight, Layers, Star, Shield, MapPin, Home, Calendar, TreePine, Key, TowerControl, Building, BarChart3, Users, Zap } from 'lucide-react';
import ddAdminPfp from '../../../assets/clientadminpfp.png';

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

export default function ProjectDetailContent({ project, unitTypes = [], campaigns = [] }) {
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
        </div>

        {/* ── RIGHT SIDEBAR ── */}
        <div className="space-y-4">
          <div className="space-y-4">

            {/* ── GROUP BUY BANNER ── */}
            {campaigns.length > 0 && campaigns.map((c) => {
              const discount = c.discountPerBuyer || 0;
              const fmtDiscount = discount >= 1e7 ? `₹${(discount/1e7).toFixed(discount % 1e7 === 0 ? 0 : 2)} Cr` : discount >= 1e5 ? `₹${(discount/1e5).toFixed(0)} L` : `₹${discount.toLocaleString('en-IN')}`;
              const progress = c.buyerTargets?.minBuyers ? Math.min(100, Math.round(((c.memberCount || 0) / c.buyerTargets.minBuyers) * 100)) : 0;
              const unitName = typeof c.unitType === 'object' ? c.unitType.config?.name : null;

              return (
                <div key={c._id} className="bg-slate-900 rounded-2xl overflow-hidden">
                  {/* Header strip */}
                  <div className="px-5 pt-4 pb-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="text-[11px] font-semibold uppercase tracking-[0.15em] text-slate-400">Group Buy</span>
                    </div>
                    {unitName && <span className="text-[10px] text-slate-500 font-medium">{unitName}</span>}
                  </div>

                  {/* Discount */}
                  <div className="px-5 pb-4">
                    <p className="text-3xl font-extrabold text-white tracking-tight leading-none">{fmtDiscount} <span className="text-emerald-400 text-lg font-bold">OFF</span></p>
                    <p className="text-xs text-slate-400 mt-1.5">per buyer · {c.buyerTargets?.minBuyers}+ buyers needed</p>
                  </div>

                  {/* Divider + Progress */}
                  <div className="px-5 pb-4">
                    <div className="flex justify-between text-[10px] text-slate-500 mb-1.5 font-medium">
                      <span>{c.memberCount || 0} joined</span>
                      <span>{c.buyerTargets?.maxBuyers ? `${Math.max(0, c.buyerTargets.maxBuyers - (c.memberCount || 0))} left` : `min ${c.buyerTargets?.minBuyers}`}</span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1">
                      <div className="h-1 rounded-full bg-emerald-400 transition-all duration-500" style={{ width: `${progress}%` }} />
                    </div>
                  </div>

                  {/* Perks */}
                  {c.perks?.length > 0 && (
                    <div className="px-5 pb-4 space-y-2">
                      {c.perks.map((perk, i) => (
                        <div key={i} className="flex items-center gap-2.5">
                          <FaCheckCircle size={10} className="text-emerald-400 flex-shrink-0" />
                          <span className="text-xs text-slate-300">{perk}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}

            {/* ── DealDirect Contact Card ── */}
            <div className="bg-white border border-slate-200 rounded-2xl p-5">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-14 h-14 rounded-full bg-indigo-50 flex items-center justify-center font-bold text-indigo-600 text-xl border border-indigo-100 overflow-hidden flex-shrink-0">
                  <img src={ddAdminPfp.src} alt="DealDirect Admin" className="w-full h-full object-cover" />
                </div>
                <div>
                  <p className="font-bold text-slate-900 flex items-center gap-1.5">DealDirect Admin <FaCheckCircle className="text-blue-500" size={12} /></p>
                  <p className="text-xs text-slate-400">Your Buying Partner</p>
                </div>
              </div>

              {p.builder && (
                <div className="bg-slate-50 rounded-xl px-4 py-3 mb-4">
                  <p className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider mb-1">Developer</p>
                  <div className="flex items-center gap-2">
                    {p.builder.logoUrl ? (
                      <img src={p.builder.logoUrl} alt={p.builder.company || p.builder.name} className="w-7 h-7 rounded-md object-cover border border-slate-200" />
                    ) : null}
                    <p className="font-semibold text-slate-700 text-sm">{p.builder.company || p.builder.name}</p>
                  </div>
                </div>
              )}

              <div className="border-t border-slate-100 pt-4">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Contact DealDirect</h3>
                <div className="grid grid-cols-2 gap-2">
                  <a href="tel:6360122696" className="flex items-center justify-center gap-2 px-3 py-3 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition"><FaPhoneAlt size={12} /> Call</a>
                  <a href="https://wa.me/916360122696" target="_blank" rel="noopener noreferrer" className="flex items-center justify-center gap-2 px-3 py-3 bg-green-500 text-white rounded-xl text-sm font-semibold hover:bg-green-600 transition"><FaWhatsapp /> WhatsApp</a>
                </div>
                <a href="mailto:admin@dealdirect.in" className="w-full flex items-center justify-center gap-2 px-4 py-2.5 text-slate-500 text-sm font-medium hover:text-indigo-600 transition mt-2">
                  <FaEnvelope size={12} /> admin@dealdirect.in
                </a>
              </div>
            </div>

            {/* ── CONFIGS ── */}
            {unitTypes.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h3 className="font-bold text-slate-900 mb-4 flex items-center gap-2"><Layers size={16} /> Available Configurations</h3>
                {unitTypes.map(ut => <UnitTypeCard key={ut._id} ut={ut} projectId={p._id} />)}
              </div>
            )}

            {/* ── AMENITIES ── */}
            {amenities.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h3 className="font-bold text-slate-900 mb-3">Amenities</h3>
                <div className="grid grid-cols-1 gap-y-2.5">
                  {amenities.map((a, i) => (
                    <div key={i} className="flex items-center gap-2.5 text-sm text-slate-700">
                      <FaCheckCircle className="text-emerald-500 flex-shrink-0" size={13} /> {a.name}
                    </div>
                  ))}
                </div>
                {/* Feature 5 — Amenity photo gallery */}
                {toArray(p.media?.amenityImages).length > 0 && (
                  <div className="mt-4 grid grid-cols-2 gap-2">
                    {toArray(p.media.amenityImages).map((url, i) => (
                      <div key={i} className="rounded-xl overflow-hidden border border-slate-100">
                        <img src={url} alt={`Amenity ${i + 1}`} className="w-full h-24 object-cover" onError={e => { e.target.onerror = null; e.target.src = FALLBACK; }} />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── PAYMENT PLANS — Feature 6 ── */}
            {p.paymentPlans?.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h3 className="font-bold text-slate-900 mb-4">Payment Plans</h3>
                <div className="space-y-4">
                  {p.paymentPlans.map((plan, pi) => (
                    <div key={pi} className="border border-slate-100 rounded-xl p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold text-slate-800 text-sm">{plan.planType}</span>
                        {plan.description && <span className="text-xs text-slate-400">{plan.description}</span>}
                      </div>
                      {plan.schedule?.length > 0 && (
                        <div className="space-y-1.5">
                          {plan.schedule.map((s, si) => (
                            <div key={si} className="flex justify-between text-sm">
                              <span className="text-slate-500">{s.stage}</span>
                              <span className="font-medium text-slate-800">{s.percentage}%</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── DOCUMENTS (moved from left) ── */}
            {(p.documents?.reraCertificateUrl || p.media?.brochureUrl) && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h3 className="font-bold text-slate-900 mb-3">Documents</h3>
                <div className="space-y-2">
                  {p.media?.brochureUrl && <a href={p.media.brochureUrl} target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-2 px-4 py-2.5 bg-red-50 text-red-700 border border-red-200 rounded-xl text-sm font-medium hover:bg-red-100 transition"><FaFilePdf /> Download Brochure</a>}
                  {p.documents?.reraCertificateUrl && <a href={p.documents.reraCertificateUrl} target="_blank" rel="noopener noreferrer" className="w-full flex items-center gap-2 px-4 py-2.5 bg-green-50 text-green-700 border border-green-200 rounded-xl text-sm font-medium hover:bg-green-100 transition"><Shield size={14} /> RERA Certificate</a>}
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
