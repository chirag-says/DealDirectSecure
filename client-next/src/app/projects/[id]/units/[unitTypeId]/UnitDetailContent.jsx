'use client';
import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter, useParams } from 'next/navigation';
import { FaBed, FaBath, FaRulerCombined, FaCompass, FaFilePdf, FaPhone, FaWhatsapp } from 'react-icons/fa';
import { Shield, Users, Calendar, CheckCircle, Upload, Loader2, X, AlertTriangle, ChevronRight, Home, Tag, TrendingDown } from 'lucide-react';
import { bookingApi } from '../../../../../utils/api';
import { useAuth } from '../../../../../context/AuthContext';
import { toast } from 'react-toastify';

const fmt = (n) => !n ? null : n >= 1e7 ? `₹${(n/1e7).toFixed(2)} Cr` : `₹${(n/1e5).toFixed(2)} L`;
const inp = 'w-full border border-gray-300 rounded-lg px-3.5 py-2.5 text-sm focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-200 transition';

/* ── Booking Modal ── */
function BookingModal({ ut, project, onClose, user }) {
  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    name: user?.name || '',
    phone: user?.phone || '',
    email: user?.email || '',
    notes: '',
  });
  const [bookingId, setBookingId] = useState(null);
  const [utr, setUtr] = useState('');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const token = project?.financials?.bookingAmount || 0;
  const set = (k,v) => setForm(f=>({...f,[k]:v}));

  // Payment config — fetched securely from backend
  const [qrUrl, setQrUrl] = useState('');
  const [upiId, setUpiId] = useState('');

  useEffect(() => {
    const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:9000/api';
    fetch(`${API}/bookings/payment-config`, { credentials: 'include' })
      .then(r => r.json())
      .then(d => { if (d.success) { setQrUrl(d.data.qrUrl); setUpiId(d.data.upiId); } })
      .catch(() => {});
  }, []);

  const doStep1 = async () => {
    if (!form.name.trim() || !form.phone.trim()) { setErr('Name and phone are required.'); return; }
    setErr(''); setLoading(true);
    try {
      const d = await bookingApi.create({
        unitTypeId: ut._id,
        projectId: project?._id,
        clientName: form.name,
        clientPhone: form.phone,
        clientEmail: form.email,
        notes: form.notes,
        tokenAmount: token,
      });
      if (!d.success) throw new Error(d.message);
      setBookingId(d.data.bookingId); setStep(2);
    } catch(e) { setErr(e?.response?.data?.message || e.message || 'Failed.'); }
    finally { setLoading(false); }
  };

  const doStep3 = async () => {
    if (!utr.trim() && !file) { setErr('Enter UTR or upload screenshot.'); return; }
    setErr(''); setLoading(true);
    try {
      const fd = new FormData();
      if (utr.trim()) fd.append('utrNumber', utr.trim());
      if (file) fd.append('screenshot', file);
      await bookingApi.submitPayment(bookingId, fd);
      setStep(4);
    } catch(e) { setErr(e?.response?.data?.message || e.message || 'Failed.'); }
    finally { setLoading(false); }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/40 p-4">
      <div className="bg-white w-full max-w-md rounded-2xl shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <div>
            <p className="font-bold text-gray-900 text-base">{ut?.config?.name}</p>
            <p className="text-xs text-gray-400 mt-0.5">{project?.basics?.name}</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-full bg-gray-100 hover:bg-gray-200 transition"><X size={15}/></button>
        </div>
        {/* Step bar */}
        <div className="flex border-b border-gray-100">
          {['Details','Payment','Proof','Done'].map((s,i)=>(
            <div key={i} className={`flex-1 text-center py-2.5 text-xs font-semibold transition border-b-2 ${step===i+1?'border-blue-600 text-blue-600':step>i+1?'border-green-400 text-green-600':'border-transparent text-gray-400'}`}>{step>i+1?'✓ ':''}{s}</div>
          ))}
        </div>
        {/* Body */}
        <div className="px-5 py-5 overflow-y-auto space-y-4">
          {err && <p className="text-sm text-red-600 bg-red-50 border border-red-200 px-4 py-2.5 rounded-lg flex items-center gap-2"><AlertTriangle size={14}/>{err}</p>}
          {step===1 && (<>
            <div className="space-y-3">
              <div><label className="text-xs font-semibold text-gray-500 block mb-1">Full Name *</label><input className={inp} placeholder="Rahul Mehta" value={form.name} onChange={e=>set('name',e.target.value)}/></div>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="text-xs font-semibold text-gray-500 block mb-1">Phone *</label><input className={inp} type="tel" placeholder="10-digit" value={form.phone} onChange={e=>set('phone',e.target.value)}/></div>
                <div><label className="text-xs font-semibold text-gray-500 block mb-1">Email</label><input className={inp} type="email" placeholder="Optional" value={form.email} onChange={e=>set('email',e.target.value)}/></div>
              </div>
              <div><label className="text-xs font-semibold text-gray-500 block mb-1">Notes</label><textarea className={`${inp} resize-none`} rows={2} value={form.notes} onChange={e=>set('notes',e.target.value)}/></div>
            </div>
            {token>0 && <div className="flex items-center justify-between bg-blue-50 border border-blue-100 rounded-xl px-4 py-3"><span className="text-sm text-blue-700 font-medium">Token Amount</span><span className="text-xl font-bold text-blue-800">₹{token.toLocaleString('en-IN')}</span></div>}
            <button onClick={doStep1} disabled={loading} className="w-full py-3 bg-blue-600 text-white rounded-xl font-semibold text-sm hover:bg-blue-700 transition disabled:opacity-60 flex items-center justify-center gap-2">
              {loading?<><Loader2 size={15} className="animate-spin"/>Processing...</>:<>Continue <ChevronRight size={15}/></>}
            </button>
          </>)}
          {step===2 && (<>
            <p className="text-sm text-gray-600 text-center">Scan the QR code below and pay the token amount to secure your booking.</p>
            {qrUrl && (
              <div className="bg-gray-50 border border-gray-200 rounded-2xl p-4 text-center">
                <img src={qrUrl} alt="DealDirect UPI QR" className="w-48 h-48 object-contain mx-auto rounded-lg" onError={e => { e.target.style.display='none'; }}/>
                {upiId && (
                  <div className="mt-3 bg-blue-50 rounded-xl px-4 py-2">
                    <p className="text-xs text-gray-500">UPI ID</p>
                    <p className="font-bold text-blue-700 text-sm">{upiId}</p>
                  </div>
                )}
              </div>
            )}
            <div className="bg-gray-900 rounded-xl p-4 text-white text-center">
              <p className="text-gray-400 text-xs font-semibold mb-1 uppercase tracking-wide">Token Amount to Transfer</p>
              <p className="text-3xl font-bold">₹{token.toLocaleString('en-IN')}</p>
            </div>
            {bookingId && <p className="text-xs text-gray-500 text-center">Booking ref: <span className="font-mono font-bold text-gray-700">#{bookingId.slice(-8).toUpperCase()}</span></p>}
            {project?.salesContact?.phone && <p className="text-xs text-gray-500 text-center flex items-center justify-center gap-1.5"><FaPhone size={10}/>For queries: +91 {project.salesContact.phone}</p>}
            <button onClick={()=>setStep(3)} className="w-full py-3 bg-blue-600 text-white rounded-xl font-semibold text-sm hover:bg-blue-700 transition">I've Paid — Upload Proof →</button>
            <button onClick={onClose} className="w-full text-xs text-gray-400 hover:text-gray-600 text-center">Upload later in My Bookings</button>
          </>)}
          {step===3 && (<>
            <div><label className="text-xs font-semibold text-gray-500 block mb-1">UTR / Transaction ID</label><input className={`${inp} font-mono`} placeholder="e.g. SBIN12345678" value={utr} onChange={e=>setUtr(e.target.value)}/></div>
            <label className={`flex flex-col items-center gap-2.5 border-2 border-dashed rounded-xl py-7 cursor-pointer transition ${file?'border-green-400 bg-green-50':'border-gray-200 hover:border-blue-300 hover:bg-blue-50/30'}`}>
              <input type="file" accept="image/*" className="hidden" onChange={e=>setFile(e.target.files[0])}/>
              {file?<><CheckCircle size={24} className="text-green-500"/><span className="text-sm font-medium text-green-700">{file.name}</span></>:<><Upload size={24} className="text-gray-300"/><span className="text-sm text-gray-500">Upload Payment Screenshot</span><span className="text-xs text-gray-400">JPG or PNG</span></>}
            </label>
            <button onClick={doStep3} disabled={loading} className="w-full py-3 bg-blue-600 text-white rounded-xl font-semibold text-sm hover:bg-blue-700 transition disabled:opacity-60 flex items-center justify-center gap-2">
              {loading?<><Loader2 size={15} className="animate-spin"/>Submitting...</>:'Submit Proof →'}
            </button>
          </>)}
          {step===4 && (
            <div className="text-center py-6">
              <div className="w-16 h-16 rounded-full bg-green-100 flex items-center justify-center mx-auto mb-4"><CheckCircle size={32} className="text-green-500"/></div>
              <p className="font-bold text-gray-900 text-lg mb-1">Booking Submitted!</p>
              <p className="text-gray-500 text-sm mb-5">Our team will verify and confirm within 24 hours.</p>
              <Link href="/my-bookings" className="inline-block px-6 py-3 bg-blue-600 text-white rounded-xl font-semibold text-sm hover:bg-blue-700 transition">Track My Bookings →</Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Campaign Card ── */
function CampaignCard({ c, onBook }) {
  const active = c.status==='active';
  const pct = Math.min(100, Math.round(((c.currentBuyers||0)/(c.maxBuyers||1))*100));
  const savings = c.regularPrice&&c.groupBuyPrice ? Math.round(((c.regularPrice-c.groupBuyPrice)/c.regularPrice)*100) : 0;
  const ends = c.endDate ? new Date(c.endDate).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'}) : null;
  return (
    <div className={`rounded-xl border p-4 ${active&&pct<100?'border-blue-200 bg-blue-50/40':'border-gray-200 bg-white opacity-60'}`}>
      <div className="flex items-start justify-between mb-3">
        <div><p className="font-semibold text-gray-900 text-sm">{c.name}</p>{ends&&<p className="text-xs text-gray-400 mt-0.5 flex items-center gap-1"><Calendar size={10}/>Ends {ends}</p>}</div>
        {savings>0 && <span className="text-xs font-bold px-2 py-1 bg-green-100 text-green-700 rounded-full flex items-center gap-1"><TrendingDown size={10}/>{savings}% off</span>}
      </div>
      <div className="mb-3">
        <div className="flex justify-between text-xs text-gray-400 mb-1"><span className="flex items-center gap-1"><Users size={10}/>{c.currentBuyers||0}/{c.maxBuyers} joined</span><span className="font-semibold text-blue-600">{pct}% full</span></div>
        <div className="bg-gray-200 rounded-full h-1.5"><div className="bg-blue-500 h-1.5 rounded-full" style={{width:`${pct}%`}}/></div>
      </div>
      <div className="flex items-center justify-between">
        <div>{c.groupBuyPrice&&<p className="font-bold text-gray-900">{fmt(c.groupBuyPrice)} <span className="text-xs font-normal text-gray-400 line-through">{fmt(c.regularPrice)}</span></p>}</div>
        {active&&pct<100&&<button onClick={onBook} className="px-4 py-2 bg-blue-600 text-white rounded-lg font-semibold text-xs hover:bg-blue-700 transition">Join Now</button>}
      </div>
    </div>
  );
}

/* ── Spec Tabs ── */
function SpecsSection({ specs }) {
  const [tab, setTab] = useState(0);
  if (!specs) return null;
  const sections = [
    { label:'Flooring', rows:[['Living/Dining',specs.flooring?.livingDining],['Bedrooms',specs.flooring?.bedrooms],['Kitchen',specs.flooring?.kitchen],['Bathroom',specs.flooring?.bathroom],['Balcony',specs.flooring?.balcony]] },
    { label:'Kitchen', rows:[['Countertop',specs.kitchen?.countertop],['Sink',specs.kitchen?.sink],['Modular',specs.kitchen?.isModular?'Yes':null],['Chimney',specs.kitchen?.chimney?'Included':null]] },
    { label:'Bathroom', rows:[['Sanitary Brand',specs.bathroom?.sanitaryBrand],['Fittings Brand',specs.bathroom?.fittingsBrand],['Dado Height',specs.bathroom?.dadoHeight]] },
    { label:'Doors & Windows', rows:[['Main Door',specs.doors?.mainDoor],['Internal Doors',specs.doors?.internalDoors],['Finish',specs.doors?.finish],['Window Type',specs.windows?.type],['Mosquito Mesh',specs.windows?.mosquitoMesh?'Yes':null]] },
    { label:'Electrical', rows:[['Wiring',specs.electrical?.wiringType],['Switch Brand',specs.electrical?.switchBrand],['AC Points/Room',specs.electrical?.acPointsPerRoom!=null?String(specs.electrical.acPointsPerRoom):null]] },
  ].filter(s=>s.rows.some(([,v])=>v));
  if (!specs.structure && sections.length===0) return null;
  return (
    <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
      <div className="px-5 pt-5">
        <h2 className="font-bold text-gray-900 text-base mb-3">Construction Specifications</h2>
        {specs.structure && <div className="text-sm text-gray-600 bg-gray-50 rounded-lg px-4 py-2.5 mb-4"><span className="font-semibold text-gray-700">Structure: </span>{specs.structure}</div>}
      </div>
      {sections.length>0 && (<>
        <div className="flex overflow-x-auto border-b border-gray-100 px-3">
          {sections.map((s,i)=>(
            <button key={i} onClick={()=>setTab(i)} className={`px-4 py-2.5 text-xs font-semibold whitespace-nowrap border-b-2 transition ${tab===i?'border-blue-600 text-blue-700':'border-transparent text-gray-400 hover:text-gray-600'}`}>{s.label}</button>
          ))}
        </div>
        <div className="px-5 py-4 divide-y divide-gray-50">
          {sections[tab]?.rows.filter(([,v])=>v).map(([label,value],i)=>(
            <div key={i} className="flex justify-between py-2.5 text-sm"><span className="text-gray-500">{label}</span><span className="font-medium text-gray-800 text-right max-w-[55%]">{value}</span></div>
          ))}
        </div>
      </>)}
    </div>
  );
}

/* ── Main Page ── */
export default function UnitDetailContent({ unitType:ut, campaigns=[], project, projectId }) {
  const [showModal, setShowModal] = useState(false);
  const { isAuthenticated, user } = useAuth();
  const router = useRouter();
  const price = ut.pricing?.effectivePrice;
  const carpet = ut.area?.carpetSqft;
  const hasCharges = ut.pricing?.additionalCharges && Object.values(ut.pricing.additionalCharges).some(v=>v>0);

  // Login gate — same pattern as "I'm Interested" on owner properties
  const handleBookClick = () => {
    if (!isAuthenticated || !user) {
      toast.info('Please login to book this unit');
      router.push(`/login?from=/projects/${projectId}/units/${ut._id}`);
      return;
    }
    setShowModal(true);
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {showModal && <BookingModal ut={ut} project={project} user={user} onClose={()=>setShowModal(false)}/>}

      {/* Breadcrumb */}
      <div className="bg-white border-b border-gray-200 px-4 py-3">
        <div className="max-w-6xl mx-auto flex items-center gap-1.5 text-xs text-gray-400 flex-wrap">
          <Link href="/" className="hover:text-blue-600 flex items-center gap-1"><Home size={11}/>Home</Link>
          <ChevronRight size={10}/><Link href="/projects" className="hover:text-blue-600">Projects</Link>
          <ChevronRight size={10}/><Link href={`/projects/${projectId}`} className="hover:text-blue-600 max-w-[120px] truncate">{project?.basics?.name||'Project'}</Link>
          <ChevronRight size={10}/><span className="text-gray-700 font-semibold">{ut.config?.name}</span>
        </div>
      </div>

      <div className="max-w-6xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* LEFT */}
        <div className="lg:col-span-2 space-y-5">

          {/* Title */}
          <div className="bg-white border border-gray-200 rounded-xl p-5">
            <div className="flex flex-wrap gap-2 mb-2">
              {ut.furnishing && <span className="text-xs font-semibold px-2.5 py-1 bg-blue-50 text-blue-700 rounded-md">{ut.furnishing}</span>}
              {ut.facing?.length>0 && <span className="text-xs font-semibold px-2.5 py-1 bg-gray-100 text-gray-600 rounded-md flex items-center gap-1"><FaCompass size={9}/>{ut.facing.join(', ')} Facing</span>}
              {ut.config?.hasUtilityArea && <span className="text-xs font-semibold px-2.5 py-1 bg-green-50 text-green-700 rounded-md">Utility Area</span>}
            </div>
            <h1 className="text-2xl font-bold text-gray-900">{ut.config?.name}</h1>
            <p className="text-gray-500 text-sm mt-1">{project?.basics?.name}{project?.location?.city ? ` · ${project.location.city}` : ''}</p>

            {/* Key stats inline */}
            <div className="flex flex-wrap gap-5 mt-4 pt-4 border-t border-gray-100 text-sm">
              {ut.config?.bedrooms>0 && <div className="flex items-center gap-1.5 text-gray-600"><FaBed className="text-gray-400"/><span className="font-semibold text-gray-900">{ut.config.bedrooms}</span> Beds</div>}
              {ut.config?.bathrooms>0 && <div className="flex items-center gap-1.5 text-gray-600"><FaBath className="text-gray-400"/><span className="font-semibold text-gray-900">{ut.config.bathrooms}</span> Baths</div>}
              {carpet>0 && <div className="flex items-center gap-1.5 text-gray-600"><FaRulerCombined className="text-gray-400"/><span className="font-semibold text-gray-900">{carpet.toLocaleString('en-IN')}</span> sqft carpet</div>}
              {ut.area?.builtUpSqft>0 && <div className="text-gray-600"><span className="font-semibold text-gray-900">{ut.area.builtUpSqft.toLocaleString('en-IN')}</span> sqft built-up</div>}
              {ut.area?.superBuiltUpSqft>0 && <div className="text-gray-600"><span className="font-semibold text-gray-900">{ut.area.superBuiltUpSqft.toLocaleString('en-IN')}</span> sqft super BU</div>}
              {ut.pricing?.pricePerSqft>0 && <div className="text-gray-600"><span className="font-semibold text-gray-900">₹{ut.pricing.pricePerSqft.toLocaleString('en-IN')}</span>/sqft</div>}
              {ut.config?.balconies>0 && <div className="text-gray-600"><span className="font-semibold text-gray-900">{ut.config.balconies}</span> Balcon{ut.config.balconies>1?'ies':'y'}</div>}
            </div>
          </div>

          {/* Floor Plans */}
          {(ut.floorPlans?.twoDUrl || ut.floorPlans?.threeDUrl) && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h2 className="font-bold text-gray-900 mb-4">Floor Plans</h2>
              <div className={`grid gap-4 ${ut.floorPlans?.twoDUrl && ut.floorPlans?.threeDUrl ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1'}`}>
                {ut.floorPlans?.twoDUrl && (
                  <div><p className="text-xs font-semibold text-gray-400 mb-2">2D PLAN</p><img src={ut.floorPlans.twoDUrl} alt="2D Floor Plan" className="w-full rounded-lg border border-gray-100 object-contain max-h-72 bg-gray-50"/></div>
                )}
                {ut.floorPlans?.threeDUrl && (
                  <div><p className="text-xs font-semibold text-gray-400 mb-2">3D VIEW</p><img src={ut.floorPlans.threeDUrl} alt="3D Floor Plan" className="w-full rounded-lg border border-gray-100 object-contain max-h-72 bg-gray-50"/></div>
                )}
              </div>
            </div>
          )}

          {/* Highlights */}
          {ut.highlights?.length>0 && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h2 className="font-bold text-gray-900 mb-4">Key Highlights</h2>
              <div className="grid sm:grid-cols-2 gap-2.5">
                {ut.highlights.map((h,i)=>(
                  <div key={i} className="flex items-start gap-2.5 bg-blue-50/60 border border-blue-100 rounded-lg px-3.5 py-2.5 text-sm text-gray-700">
                    <CheckCircle size={14} className="text-blue-500 shrink-0 mt-0.5"/>{h}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Specs */}
          <SpecsSection specs={ut.specifications}/>

          {/* Parking */}
          {(ut.parking?.covered>0||ut.parking?.open>0||ut.parking?.ev>0) && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h2 className="font-bold text-gray-900 mb-4">Parking</h2>
              <div className="flex gap-4 flex-wrap">
                {ut.parking?.covered>0 && <div className="bg-gray-50 border border-gray-200 rounded-xl px-5 py-3 text-center"><p className="text-xl font-bold text-gray-900">{ut.parking.covered}</p><p className="text-xs text-gray-500 mt-0.5">Covered</p></div>}
                {ut.parking?.open>0 && <div className="bg-gray-50 border border-gray-200 rounded-xl px-5 py-3 text-center"><p className="text-xl font-bold text-gray-900">{ut.parking.open}</p><p className="text-xs text-gray-500 mt-0.5">Open</p></div>}
                {ut.parking?.ev>0 && <div className="bg-green-50 border border-green-200 rounded-xl px-5 py-3 text-center"><p className="text-xl font-bold text-green-700">{ut.parking.ev}</p><p className="text-xs text-green-500 mt-0.5">EV Charging</p></div>}
              </div>
            </div>
          )}

          {/* Campaigns */}
          {campaigns.length>0 && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h2 className="font-bold text-gray-900 mb-4 flex items-center gap-2"><Tag size={15} className="text-blue-500"/>Group Buy Campaigns</h2>
              <div className="space-y-3">{campaigns.map(c=><CampaignCard key={c._id} c={c} onBook={handleBookClick}/>)}</div>
            </div>
          )}

          {/* Brochure */}
          {project?.media?.brochureUrl && (
            <div className="bg-white border border-gray-200 rounded-xl p-5">
              <h2 className="font-bold text-gray-900 mb-3">Documents</h2>
              <a href={project.media.brochureUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 px-4 py-2.5 bg-red-50 text-red-700 border border-red-200 rounded-lg text-sm font-semibold hover:bg-red-100 transition"><FaFilePdf/>Project Brochure</a>
            </div>
          )}
        </div>

        {/* RIGHT SIDEBAR */}
        <div>
          <div className="sticky top-24 space-y-4">
            {/* Price */}
            <div className="bg-white border border-gray-200 rounded-xl overflow-hidden shadow-sm">
              <div className="px-5 py-4 border-b border-gray-100">
                {price ? (<>
                  <p className="text-2xl font-bold text-gray-900">{fmt(price)}</p>
                  {ut.pricing?.pricePerSqft>0 && <p className="text-xs text-gray-400 mt-0.5">₹{ut.pricing.pricePerSqft.toLocaleString('en-IN')}/sqft</p>}
                </>) : <p className="text-gray-500 font-semibold">Price on request</p>}
              </div>
              <div className="px-5 py-4 space-y-3">
                {/* Charge breakdown */}
                {hasCharges && (
                  <div className="text-sm space-y-2 pb-3 border-b border-gray-100">
                    <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Price Breakdown</p>
                    {ut.pricing.additionalCharges.plc>0 && <div className="flex justify-between text-gray-500"><span>PLC</span><span>₹{ut.pricing.additionalCharges.plc.toLocaleString('en-IN')}</span></div>}
                    {ut.pricing.additionalCharges.parking>0 && <div className="flex justify-between text-gray-500"><span>Parking</span><span>₹{ut.pricing.additionalCharges.parking.toLocaleString('en-IN')}</span></div>}
                    {ut.pricing.additionalCharges.clubhouse>0 && <div className="flex justify-between text-gray-500"><span>Clubhouse</span><span>₹{ut.pricing.additionalCharges.clubhouse.toLocaleString('en-IN')}</span></div>}
                    {ut.pricing.additionalCharges.legal>0 && <div className="flex justify-between text-gray-500"><span>Legal</span><span>₹{ut.pricing.additionalCharges.legal.toLocaleString('en-IN')}</span></div>}
                    {ut.pricing.additionalCharges.maintenance>0 && <div className="flex justify-between text-gray-500"><span>Maintenance</span><span>₹{ut.pricing.additionalCharges.maintenance.toLocaleString('en-IN')}</span></div>}
                    {ut.pricing?.viewPremium>0 && <div className="flex justify-between text-gray-500"><span>View Premium</span><span>₹{ut.pricing.viewPremium.toLocaleString('en-IN')}</span></div>}
                    <div className="flex justify-between font-bold text-gray-900 pt-2 border-t border-gray-100"><span>Total</span><span>{fmt(price)}</span></div>
                  </div>
                )}
                {/* Inventory */}
                <div className="text-sm space-y-2">
                  {ut.inventory?.availableUnits!=null && <div className="flex justify-between"><span className="text-gray-500">Available</span><span className="font-bold text-green-600">{ut.inventory.availableUnits} units</span></div>}
                  {ut.inventory?.bookedUnits>0 && <div className="flex justify-between"><span className="text-gray-500">Booked</span><span className="font-bold text-gray-900">{ut.inventory.bookedUnits}</span></div>}
                  {ut.inventory?.totalUnits!=null && <div className="flex justify-between"><span className="text-gray-500">Total</span><span className="font-bold text-gray-900">{ut.inventory.totalUnits} units</span></div>}
                </div>
                {/* Tower */}
                {ut.inventory?.towerAllocation?.length>0 && (
                  <div className="pt-2 border-t border-gray-100 text-sm space-y-1">
                    <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">Tower Allocation</p>
                    {ut.inventory.towerAllocation.map((t,i)=>(
                      <div key={i} className="flex justify-between text-gray-600"><span>Tower {t.tower}</span><span className="font-medium">{t.units} units</span></div>
                    ))}
                  </div>
                )}
                <button onClick={handleBookClick} className="w-full py-3 bg-blue-600 text-white rounded-xl font-bold text-sm hover:bg-blue-700 transition">Book This Unit</button>
                <Link href={`/projects/${projectId}`} className="w-full py-2.5 border border-gray-200 text-gray-600 rounded-xl font-semibold text-sm hover:bg-gray-50 transition flex items-center justify-center">← Back to Project</Link>
              </div>
            </div>

            {/* Builder */}
            {project?.builder && (
              <div className="bg-white border border-gray-200 rounded-xl p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-10 h-10 rounded-full bg-blue-50 border border-blue-100 flex items-center justify-center font-bold text-blue-600 text-base">{(project.builder.company||project.builder.name||'B').charAt(0)}</div>
                  <div><p className="font-semibold text-gray-900 text-sm flex items-center gap-1">{project.builder.company||project.builder.name}<CheckCircle size={12} className="text-blue-500"/></p><p className="text-xs text-gray-400">Verified Developer</p></div>
                </div>
                <div className="space-y-2">
                  {project.salesContact?.phone && <a href={`tel:${project.salesContact.phone}`} className="w-full flex items-center justify-center gap-2 py-2.5 bg-blue-600 text-white rounded-lg text-sm font-semibold hover:bg-blue-700 transition"><FaPhone size={11}/>Call Sales</a>}
                  {project.salesContact?.whatsapp && <a href={`https://wa.me/91${project.salesContact.whatsapp}`} target="_blank" rel="noopener noreferrer" className="w-full flex items-center justify-center gap-2 py-2.5 bg-green-500 text-white rounded-lg text-sm font-semibold hover:bg-green-600 transition"><FaWhatsapp size={13}/>WhatsApp</a>}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Mobile sticky CTA */}
      <div className="lg:hidden fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 px-4 py-3 flex items-center gap-3 z-40">
        <div className="flex-1"><p className="font-bold text-gray-900">{price ? fmt(price) : 'Price on request'}</p>{ut.inventory?.availableUnits!=null && <p className="text-xs text-green-600">{ut.inventory.availableUnits} units available</p>}</div>
        <button onClick={handleBookClick} className="px-5 py-2.5 bg-blue-600 text-white rounded-xl font-bold text-sm hover:bg-blue-700 transition">Book Now</button>
      </div>
      <div className="h-20 lg:hidden"/>
    </div>
  );
}
