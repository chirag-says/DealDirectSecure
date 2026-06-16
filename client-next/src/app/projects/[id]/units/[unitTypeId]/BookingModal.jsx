'use client';
import React, { useState, useRef } from 'react';
import { X, CheckCircle, Upload, Loader2 } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:9000/api';

// DealDirect UPI QR — replace QR_URL with the actual hosted QR image URL
const QR_URL = process.env.NEXT_PUBLIC_DEALDIRECT_QR_URL || '/dealdirect-upi-qr.png';
const UPI_ID = process.env.NEXT_PUBLIC_DEALDIRECT_UPI_ID || 'dealdirect@upi';

const STEPS = ['details', 'payment', 'proof', 'done'];

export default function BookingModal({ unitType: ut, project: p, tokenAmount, onClose }) {
  const [step, setStep] = useState('details');
  const [bookingId, setBookingId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);

  // Form state
  const [form, setForm] = useState({ name: '', phone: '', email: '', notes: '' });
  const [utr, setUtr] = useState('');
  const [screenshot, setScreenshot] = useState(null);
  const fileRef = useRef(null);

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  // Step 1 — submit enquiry
  const handleSubmitDetails = async () => {
    if (!form.name.trim() || !form.phone.trim()) { setError('Name and phone are required.'); return; }
    if (!/^[0-9]{10}$/.test(form.phone.replace(/\s+/g, ''))) { setError('Enter a valid 10-digit phone number.'); return; }
    setError(''); setLoading(true);
    try {
      const res = await fetch(`${API}/bookings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          projectId: p._id,
          unitTypeId: ut._id,
          clientName: form.name,
          clientPhone: form.phone,
          clientEmail: form.email,
          notes: form.notes,
        }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      setBookingId(data.data.bookingId);
      setStep('payment');
    } catch (e) {
      setError(e.message || 'Failed to create booking. Please try again.');
    } finally { setLoading(false); }
  };

  // Step 3 — submit UTR + screenshot
  const handleSubmitProof = async () => {
    if (!utr.trim() && !screenshot) { setError('Please enter UTR number or upload payment screenshot.'); return; }
    setError(''); setLoading(true);
    try {
      const fd = new FormData();
      if (utr.trim()) fd.append('utrNumber', utr.trim());
      if (screenshot) fd.append('screenshot', screenshot);
      const res = await fetch(`${API}/bookings/${bookingId}/payment`, {
        method: 'POST',
        credentials: 'include',
        body: fd,
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      setStep('done');
    } catch (e) {
      setError(e.message || 'Failed to submit payment details.');
    } finally { setLoading(false); }
  };

  const copy = (text) => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md relative overflow-hidden">

        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-indigo-700 p-5 text-white">
          <button onClick={onClose} className="absolute top-4 right-4 p-1.5 bg-white/20 rounded-full hover:bg-white/30 transition"><X size={16} /></button>
          <p className="text-sm text-indigo-200 mb-1">Booking {ut.config?.name}</p>
          <h2 className="font-bold text-xl">{p.basics?.name}</h2>
          <p className="text-indigo-200 text-sm mt-1">Token Amount: <span className="text-white font-bold">₹{tokenAmount.toLocaleString('en-IN')}</span></p>
        </div>

        {/* Step Indicator */}
        <div className="flex border-b border-slate-100">
          {[['1', 'Details'], ['2', 'Payment'], ['3', 'Proof'], ['4', 'Done']].map(([n, label], i) => {
            const s = STEPS[i];
            const active = step === s;
            const done = STEPS.indexOf(step) > i;
            return (
              <div key={n} className={`flex-1 py-2.5 text-center text-xs font-semibold transition ${active ? 'text-indigo-600 border-b-2 border-indigo-600' : done ? 'text-emerald-600' : 'text-slate-400'}`}>
                {done ? <CheckCircle size={14} className="inline mr-1" /> : null}{label}
              </div>
            );
          })}
        </div>

        <div className="p-6">
          {error && <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4">{error}</p>}

          {/* Step 1: Details */}
          {step === 'details' && (
            <div className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-1 block">Full Name *</label>
                <input value={form.name} onChange={e => set('name', e.target.value)} placeholder="Your name"
                  className="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-1 block">Phone Number *</label>
                <input value={form.phone} onChange={e => set('phone', e.target.value)} placeholder="10-digit mobile number" type="tel"
                  className="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-1 block">Email (optional)</label>
                <input value={form.email} onChange={e => set('email', e.target.value)} placeholder="you@email.com" type="email"
                  className="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-1 block">Notes (optional)</label>
                <textarea value={form.notes} onChange={e => set('notes', e.target.value)} placeholder="Any preferences, floor preference, etc." rows={2}
                  className="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300 resize-none" />
              </div>
              <button onClick={handleSubmitDetails} disabled={loading}
                className="w-full py-3 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition disabled:opacity-60 flex items-center justify-center gap-2">
                {loading ? <><Loader2 size={16} className="animate-spin"/> Processing...</> : 'Continue to Payment →'}
              </button>
            </div>
          )}

          {/* Step 2: QR Payment */}
          {step === 'payment' && (
            <div className="text-center space-y-4">
              <p className="text-sm text-slate-600">Scan the QR code below and pay the token amount to secure your booking.</p>
              <div className="bg-slate-50 border border-slate-200 rounded-2xl p-4 inline-block">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img src={QR_URL} alt="DealDirect UPI QR" className="w-48 h-48 object-contain mx-auto"
                  onError={e => { e.target.style.display='none'; }} />
                <div className="mt-3 bg-indigo-50 rounded-xl px-4 py-2">
                  <p className="text-xs text-slate-500">UPI ID</p>
                  <p className="font-bold text-indigo-700 text-sm">{UPI_ID}</p>
                </div>
              </div>
              <div className="bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-left">
                <p className="text-sm font-bold text-amber-800">Pay exactly ₹{tokenAmount.toLocaleString('en-IN')}</p>
                <p className="text-xs text-amber-700 mt-1">Add your booking reference in the payment note: <span className="font-mono font-bold">{bookingId?.slice(-8)?.toUpperCase()}</span></p>
                <button onClick={() => copy(bookingId?.slice(-8)?.toUpperCase())} className="text-xs text-amber-600 underline mt-1">
                  {copied ? '✓ Copied!' : 'Copy reference'}
                </button>
              </div>
              <div className="flex gap-3">
                <button onClick={() => setStep('details')} className="flex-1 py-2.5 border border-slate-200 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50 transition">← Back</button>
                <button onClick={() => { setError(''); setStep('proof'); }} className="flex-1 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-bold hover:bg-indigo-700 transition">I've Paid →</button>
              </div>
            </div>
          )}

          {/* Step 3: Submit Proof */}
          {step === 'proof' && (
            <div className="space-y-4">
              <p className="text-sm text-slate-600">Submit your payment proof. Enter the UTR/transaction ID from your UPI app or upload a screenshot.</p>
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-1 block">UTR / Transaction Reference</label>
                <input value={utr} onChange={e => setUtr(e.target.value)} placeholder="e.g. 123456789012"
                  className="w-full border border-slate-200 rounded-xl px-4 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-300" />
              </div>
              <div>
                <label className="text-xs font-semibold text-slate-600 mb-2 block">Payment Screenshot</label>
                <input type="file" accept="image/*" ref={fileRef} className="hidden" onChange={e => setScreenshot(e.target.files[0])} />
                <button onClick={() => fileRef.current?.click()}
                  className={`w-full border-2 border-dashed rounded-xl py-5 text-center transition ${screenshot ? 'border-emerald-400 bg-emerald-50' : 'border-slate-200 hover:border-indigo-300 hover:bg-indigo-50/30'}`}>
                  {screenshot ? (
                    <><CheckCircle size={20} className="text-emerald-500 mx-auto mb-1" /><p className="text-sm text-emerald-700 font-semibold">{screenshot.name}</p><p className="text-xs text-slate-400">Click to change</p></>
                  ) : (
                    <><Upload size={20} className="text-slate-400 mx-auto mb-1" /><p className="text-sm text-slate-500">Upload screenshot</p><p className="text-xs text-slate-400">JPG, PNG, WebP</p></>
                  )}
                </button>
              </div>
              <div className="flex gap-3">
                <button onClick={() => setStep('payment')} className="flex-1 py-2.5 border border-slate-200 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50 transition">← Back</button>
                <button onClick={handleSubmitProof} disabled={loading}
                  className="flex-1 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-bold hover:bg-indigo-700 transition disabled:opacity-60 flex items-center justify-center gap-2">
                  {loading ? <><Loader2 size={16} className="animate-spin"/> Submitting...</> : 'Submit Proof →'}
                </button>
              </div>
            </div>
          )}

          {/* Step 4: Done */}
          {step === 'done' && (
            <div className="text-center py-4 space-y-4">
              <div className="w-16 h-16 bg-emerald-100 rounded-full flex items-center justify-center mx-auto">
                <CheckCircle size={32} className="text-emerald-500" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-lg">Payment Submitted!</h3>
                <p className="text-slate-500 text-sm mt-2">Your booking request has been received. Our team will verify your payment within <strong>24 hours</strong> and confirm your booking.</p>
              </div>
              <div className="bg-slate-50 rounded-xl px-4 py-3">
                <p className="text-xs text-slate-400">Booking Reference</p>
                <p className="font-mono font-bold text-slate-800 text-lg">{bookingId?.slice(-8)?.toUpperCase()}</p>
                <p className="text-xs text-slate-400 mt-1">Save this for your records</p>
              </div>
              <div className="text-sm text-slate-500 bg-blue-50 rounded-xl px-4 py-3">
                📞 For queries, contact sales: <a href={`tel:${p.salesContact?.phone}`} className="text-indigo-600 font-semibold">{p.salesContact?.phone}</a>
              </div>
              <button onClick={onClose} className="w-full py-3 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition">Close</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
