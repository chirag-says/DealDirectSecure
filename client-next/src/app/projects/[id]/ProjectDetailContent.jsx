'use client';
import React, { useState } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';
import { FaMapMarkerAlt, FaPhoneAlt, FaWhatsapp, FaEnvelope, FaCheckCircle, FaFilePdf, FaBed, FaBath, FaRulerCombined, FaCompass, FaCouch } from 'react-icons/fa';
import { Building2, CheckCircle, ChevronLeft, ChevronRight, Layers, ListChecks, Shield, MapPin, Home, Calendar, TreePine, Key, Building, BarChart3, HardHat, Landmark, FileText, Award, PlayCircle, X } from 'lucide-react';
import ddAdminPfp from '../../../assets/clientadminpfp.png';

// Leaflet reads `window` at module scope, so this cannot be server-rendered —
// it would not degrade the map, it would throw and take the page with it.
const ProjectLocationMap = dynamic(
  () => import('../../../components/Projects/ProjectLocationMap'),
  {
    ssr: false,
    loading: () => (
      <div className="bg-white rounded-2xl border border-slate-200 p-5">
        <div className="h-72 rounded-xl bg-slate-100 animate-pulse" />
      </div>
    ),
  }
);

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
  // Full-size viewer for plan drawings. A master plan is dense line art; the
  // page-level thumbnail exists to be clicked, not to be read.
  const [zoomed, setZoomed] = useState(null);
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
              {/* The registration NUMBER, not just a badge.
                  "RERA Verified" with no number is precisely the pattern state
                  regulators penalise — MahaRERA and GujRERA both require the
                  number displayed prominently in advertisements, and a listing
                  page is an advertising surface.
                  Neutral styling, no tick: the number is shown as entered, and
                  nothing checks it against the register. */}
              {p.basics?.reraNumber && (
                <a
                  href="https://maharera.maharashtra.gov.in/"
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Verify this registration on the state RERA register"
                  className="text-xs text-slate-700 px-3 py-1.5 rounded-lg border border-slate-200 bg-white font-medium flex items-center gap-1.5 hover:bg-slate-50 transition"
                >
                  RERA: {p.basics?.reraNumber}
                </a>
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

          {/* ── LOCATION MAP ──
              Coordinates are filled on 7 of 7 live projects and were rendered
              on none of them. The component guards its own empty case, so it
              is safe to mount unconditionally. */}
          <ProjectLocationMap project={p} />

          {/* ── WALKTHROUGH VIDEO ── */}
          {p.media?.walkthroughVideoUrl && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5">
              <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
                <PlayCircle size={16} /> Project Walkthrough
              </h2>
              <a href={p.media.walkthroughVideoUrl} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-3 bg-slate-50 hover:bg-slate-100 rounded-xl px-4 py-3.5 transition group">
                <span className="w-10 h-10 rounded-full bg-red-50 flex items-center justify-center shrink-0">
                  <PlayCircle size={18} className="text-red-600" />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-800">Watch the walkthrough</p>
                  <p className="text-xs text-slate-400 truncate">Opens in a new tab</p>
                </div>
              </a>
            </div>
          )}

          {/* ── CONSTRUCTION UPDATES ──
              Admins can post these with photos and a completion percentage,
              and nothing has ever displayed them. For an under-construction
              project this is the strongest trust signal the data model holds:
              proof that something is actually being built. */}
          {p.constructionUpdates?.length > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5">
              <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
                <HardHat size={16} /> Construction Progress
              </h2>
              <div className="space-y-5">
                {[...p.constructionUpdates]
                  .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
                  .map((u, i) => (
                    <div key={i} className="relative pl-5 border-l-2 border-slate-100 last:pb-0">
                      <span className="absolute -left-[7px] top-1 w-3 h-3 rounded-full bg-indigo-500 border-2 border-white" />
                      <div className="flex items-baseline justify-between gap-3 flex-wrap">
                        <p className="font-semibold text-slate-800 text-sm">{u.title}</p>
                        <span className="text-xs text-slate-400">{fmtDate(u.date)}</span>
                      </div>
                      {typeof u.percentComplete === 'number' && (
                        <div className="mt-2 mb-2">
                          <div className="flex justify-between text-[11px] text-slate-400 mb-1">
                            <span>Completion</span><span className="font-semibold text-indigo-600">{u.percentComplete}%</span>
                          </div>
                          <div className="w-full bg-slate-100 rounded-full h-1.5">
                            <div className="h-1.5 rounded-full bg-indigo-500 transition-all"
                              style={{ width: `${Math.min(100, Math.max(0, u.percentComplete))}%` }} />
                          </div>
                        </div>
                      )}
                      {u.description && <p className="text-sm text-slate-600 mt-1 leading-relaxed">{u.description}</p>}
                      {toArray(u.images).length > 0 && (
                        <div className="grid grid-cols-3 gap-2 mt-3">
                          {toArray(u.images).map((img, j) => (
                            <img key={j} src={img} alt={`${u.title} ${j + 1}`}
                              className="w-full h-24 object-cover rounded-lg border border-slate-100"
                              onError={(e) => { e.target.onerror = null; e.target.src = FALLBACK; }} />
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* ── ABOUT THE DEVELOPER ──
              The Builder model documents this block explicitly and only the
              name and logo ever reached a page. Contact details are absent by
              design: DealDirect is the sole point of contact, and the public
              API strips builder phone and email for exactly that reason. */}
          {p.builder && (p.builder.description || p.builder.yearEstablished ||
            p.builder.totalProjectsDelivered || toArray(p.builder.operatingCities).length > 0) && (
            <div className="bg-white rounded-2xl border border-slate-200 p-5">
              <h2 className="font-bold text-slate-900 mb-4 flex items-center gap-2">
                <Landmark size={16} /> About the Developer
              </h2>
              <div className="flex items-start gap-4">
                {p.builder.logoUrl && (
                  <img src={p.builder.logoUrl} alt={p.builder.company || p.builder.name}
                    className="w-14 h-14 rounded-xl object-cover border border-slate-200 shrink-0" />
                )}
                <div className="min-w-0">
                  <p className="font-bold text-slate-900">{p.builder.company || p.builder.name}</p>
                  {p.builder.description && (
                    <p className="text-sm text-slate-600 mt-1.5 leading-relaxed">{p.builder.description}</p>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-4">
                {p.builder.yearEstablished && (
                  <div className="bg-slate-50 rounded-xl px-4 py-3">
                    <p className="text-[11px] text-slate-400">Established</p>
                    <p className="font-bold text-slate-800 text-sm">{p.builder.yearEstablished}</p>
                  </div>
                )}
                {p.builder.totalProjectsDelivered > 0 && (
                  <div className="bg-slate-50 rounded-xl px-4 py-3">
                    <p className="text-[11px] text-slate-400">Projects delivered</p>
                    <p className="font-bold text-slate-800 text-sm">{p.builder.totalProjectsDelivered}</p>
                  </div>
                )}
                {p.builder.totalSqFtDelivered && (
                  <div className="bg-slate-50 rounded-xl px-4 py-3">
                    <p className="text-[11px] text-slate-400">Area delivered</p>
                    <p className="font-bold text-slate-800 text-sm">{p.builder.totalSqFtDelivered}</p>
                  </div>
                )}
              </div>

              {toArray(p.builder.operatingCities).length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] text-slate-400 mb-1.5">Operating in</p>
                  <div className="flex flex-wrap gap-1.5">
                    {toArray(p.builder.operatingCities).map((c, i) => (
                      <span key={i} className="text-xs bg-slate-100 text-slate-600 px-2.5 py-1 rounded-full">{c}</span>
                    ))}
                  </div>
                </div>
              )}

              {Array.isArray(p.builder.awards) && p.builder.awards.length > 0 && (
                <div className="mt-3 space-y-1.5">
                  {p.builder.awards.map((a, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm text-slate-600">
                      <Award size={13} className="text-amber-500 shrink-0" />
                      {a.name}{a.year ? ` · ${a.year}` : ''}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── RIGHT SIDEBAR ── */}
        <div className="space-y-4">
          <div className="space-y-4">


            {/* GROUP BUY — buyer-facing sections removed (Stage 1).
                The terms are stored and admin-authorable, and nothing enforces
                them: no code reads paidMemberCount >= minBuyers, applies
                discountPerBuyer to any price, or notifies anyone when a goal is
                met. Advertising a discount no code will honour is the defect.
                Restore when the mechanic exists. */}
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

            {/* ── DOCUMENTS ──
                Every uploaded document, not just two. The commencement and
                occupancy certificates and the approval list were all being
                collected and none of them reached a page — and the OC is the
                document that proves a completed project is legally occupiable,
                which is the single paper a buyer of a finished flat asks for. */}
            {(() => {
              const docs = [
                [p.media?.brochureUrl, 'Project Brochure', FaFilePdf, 'red'],
                [p.documents?.reraCertificateUrl, 'RERA Certificate', Shield, 'green'],
                [p.documents?.occupancyCertificateUrl, 'Occupancy Certificate', FileText, 'green'],
                [p.documents?.commencementCertificateUrl, 'Commencement Certificate', FileText, 'slate'],
                [p.documents?.environmentalClearanceUrl, 'Environmental Clearance', FileText, 'slate'],
              ].filter(([url]) => Boolean(url));

              const approvals = toArray(p.documents?.approvalDocumentUrls);
              if (docs.length === 0 && approvals.length === 0) return null;

              const tone = {
                red: 'bg-red-50 text-red-700 border-red-200 hover:bg-red-100',
                green: 'bg-green-50 text-green-700 border-green-200 hover:bg-green-100',
                slate: 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100',
              };

              return (
                <div className="bg-white rounded-2xl border border-slate-200 p-5">
                  <h3 className="font-bold text-slate-900 mb-3">Documents</h3>
                  <div className="space-y-2">
                    {docs.map(([url, label, Icon, colour], i) => (
                      <a key={i} href={url} target="_blank" rel="noopener noreferrer"
                        className={`w-full flex items-center gap-2 px-4 py-2.5 border rounded-xl text-sm font-medium transition ${tone[colour]}`}>
                        <Icon size={14} /> {label}
                      </a>
                    ))}
                    {approvals.map((url, i) => (
                      <a key={`ap-${i}`} href={url} target="_blank" rel="noopener noreferrer"
                        className={`w-full flex items-center gap-2 px-4 py-2.5 border rounded-xl text-sm font-medium transition ${tone.slate}`}>
                        <FileText size={14} /> Approval Document {approvals.length > 1 ? i + 1 : ''}
                      </a>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* ── BANK APPROVALS ──
                A home-loan trust signal every competing portal shows, stored
                here and never rendered. Buyers read "SBI approved" as "the
                title has been checked by someone with money at risk". */}
            {Array.isArray(p.bankApprovals) && p.bankApprovals.length > 0 && (
              <div className="bg-white rounded-2xl border border-slate-200 p-5">
                <h3 className="font-bold text-slate-900 mb-3 flex items-center gap-2">
                  <Landmark size={15} /> Home Loans Available
                </h3>
                <div className="space-y-2">
                  {p.bankApprovals.map((b, i) => (
                    <div key={i} className="flex items-center justify-between bg-slate-50 rounded-xl px-4 py-2.5">
                      <div className="flex items-center gap-2.5 min-w-0">
                        <CheckCircle size={13} className="text-emerald-500 shrink-0" />
                        <span className="text-sm font-medium text-slate-700 truncate">{b.bankName}</span>
                      </div>
                      {b.loanType && <span className="text-[11px] text-slate-400 shrink-0 ml-2">{b.loanType}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {highlights.length > 0 && (
              <div className="bg-gradient-to-br from-[#1a1145] to-[#2d1b4e] rounded-2xl p-5 text-white">
                <h3 className="font-bold mb-4 flex items-center gap-2"><ListChecks size={16} className="text-slate-400" /> Highlights</h3>
                <ul className="space-y-3">
                  {highlights.map((h, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-sm text-slate-200 leading-relaxed">
                      <span className="w-5 h-5 rounded-full bg-amber-500/20 flex items-center justify-center flex-shrink-0 mt-0.5"><CheckCircle size={12} className="text-amber-400" /></span> {h}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {/* ── MASTER PLAN ──
                `h-48 object-cover` crushed a site-layout drawing into a strip
                of decorative noise — tower labels and the legend cropped away,
                which is the entire content of a master plan. object-contain
                preserves it, and clicking opens it full size, because a plan
                readable at 12rem is not a plan.
                All images render, not only the first. */}
            {masterPlanImages.length > 0 && (
              <div className="bg-white border border-slate-200 rounded-2xl p-5">
                <h3 className="font-bold text-slate-900 mb-3">Master Plan</h3>
                <div className="space-y-2">
                  {masterPlanImages.map((img, i) => (
                    <button key={i} onClick={() => setZoomed(img)}
                      className="block w-full rounded-xl overflow-hidden bg-slate-50 border border-slate-100 hover:border-indigo-300 transition group">
                      <img src={img} alt={`Master Plan ${masterPlanImages.length > 1 ? i + 1 : ''}`}
                        className="w-full max-h-72 object-contain"
                        onError={(e) => { e.target.onerror = null; e.target.src = FALLBACK; }} />
                      <span className="block text-[11px] text-slate-400 group-hover:text-indigo-500 py-1.5 transition">
                        Click to enlarge
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Full-size plan viewer. Backdrop click and Escape both close it. */}
      {zoomed && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setZoomed(null)}
          onKeyDown={(e) => e.key === 'Escape' && setZoomed(null)}
          role="dialog"
          aria-modal="true"
          aria-label="Master plan"
          tabIndex={-1}
        >
          <button
            onClick={() => setZoomed(null)}
            aria-label="Close"
            className="absolute top-4 right-4 p-2 bg-white/90 rounded-full hover:bg-white transition"
          >
            <X size={18} className="text-slate-800" />
          </button>
          <img
            src={zoomed}
            alt="Master plan, full size"
            className="max-w-full max-h-full object-contain rounded-lg"
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </div>
  );
}
