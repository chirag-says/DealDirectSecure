'use client';
import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { CheckCircle, Clock, XCircle, Upload, Loader2, ChevronRight, Building2, Phone } from 'lucide-react';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:9000/api';

const STATUS = {
  enquiry:           { label: 'Enquiry Created',       icon: Clock,         color: 'text-slate-500',   bg: 'bg-slate-100',  ring: 'ring-slate-200', step: 1 },
  payment_submitted: { label: 'Payment Under Review',  icon: Clock,         color: 'text-amber-600',   bg: 'bg-amber-50',   ring: 'ring-amber-200', step: 2 },
  confirmed:         { label: 'Booking Confirmed! 🎉', icon: CheckCircle,   color: 'text-emerald-600', bg: 'bg-emerald-50', ring: 'ring-emerald-200', step: 3 },
  cancelled:         { label: 'Booking Cancelled',     icon: XCircle,       color: 'text-red-500',     bg: 'bg-red-50',     ring: 'ring-red-200',   step: 0 },
  completed:         { label: 'Completed',             icon: CheckCircle,   color: 'text-blue-600',    bg: 'bg-blue-50',    ring: 'ring-blue-200',  step: 4 },
};

const STEPS = ['Enquiry', 'Payment Submitted', 'Verified', 'Completed'];

function ProgressBar({ status }) {
  const step = STATUS[status]?.step ?? 0;
  if (status === 'cancelled') return (
    <div className="flex items-center gap-2 text-sm text-red-500 mt-3">
      <XCircle size={14} /> Booking was cancelled
    </div>
  );
  return (
    <div className="mt-4">
      <div className="flex items-center gap-0">
        {STEPS.map((label, i) => {
          const done = i < step;
          const active = i === step - 1;
          return (
            <React.Fragment key={i}>
              <div className="flex flex-col items-center">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all ${done || active ? 'bg-indigo-600 border-indigo-600 text-white' : 'bg-white border-slate-200 text-slate-400'}`}>
                  {done ? '✓' : i + 1}
                </div>
                <p className={`text-[10px] mt-1 whitespace-nowrap ${done || active ? 'text-indigo-600 font-semibold' : 'text-slate-400'}`}>{label}</p>
              </div>
              {i < STEPS.length - 1 && (
                <div className={`flex-1 h-0.5 mx-1 mb-5 ${i < step - 1 ? 'bg-indigo-600' : 'bg-slate-200'}`} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

function ResubmitForm({ bookingId, onSuccess }) {
  const [utr, setUtr] = useState('');
  const [screenshot, setScreenshot] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef(null);

  const handleSubmit = async () => {
    if (!utr.trim() && !screenshot) { setError('Enter UTR or upload a screenshot.'); return; }
    setError(''); setLoading(true);
    try {
      const fd = new FormData();
      if (utr.trim()) fd.append('utrNumber', utr.trim());
      if (screenshot) fd.append('screenshot', screenshot);
      const res = await fetch(`${API}/bookings/${bookingId}/payment`, { method: 'POST', credentials: 'include', body: fd });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      onSuccess();
    } catch (e) {
      setError(e.message || 'Submission failed. Try again.');
    } finally { setLoading(false); }
  };

  return (
    <div className="mt-4 bg-amber-50 border border-amber-200 rounded-xl p-4">
      <p className="text-sm font-bold text-amber-800 mb-3">Re-submit Payment Proof</p>
      {error && <p className="text-xs text-red-600 mb-2">{error}</p>}
      <input value={utr} onChange={e => setUtr(e.target.value)} placeholder="UTR / Transaction Reference"
        className="w-full border border-slate-200 rounded-lg px-3 py-2 text-sm font-mono mb-2 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
      <input type="file" accept="image/*" ref={fileRef} className="hidden" onChange={e => setScreenshot(e.target.files[0])} />
      <button onClick={() => fileRef.current?.click()}
        className={`w-full border-2 border-dashed rounded-lg py-2.5 text-sm text-center mb-3 transition ${screenshot ? 'border-emerald-400 text-emerald-700' : 'border-slate-200 text-slate-500 hover:border-indigo-300'}`}>
        {screenshot ? `✓ ${screenshot.name}` : <><Upload size={13} className="inline mr-1" />Upload Screenshot</>}
      </button>
      <button onClick={handleSubmit} disabled={loading}
        className="w-full py-2.5 bg-indigo-600 text-white rounded-lg text-sm font-bold hover:bg-indigo-700 transition disabled:opacity-60 flex items-center justify-center gap-2">
        {loading ? <><Loader2 size={14} className="animate-spin" />Submitting...</> : 'Submit Proof'}
      </button>
    </div>
  );
}

function BookingCard({ booking, onRefresh }) {
  const [showResubmit, setShowResubmit] = useState(false);
  const cfg = STATUS[booking.status] || STATUS.enquiry;
  const Icon = cfg.icon;
  const rejected = booking.payment?.status === 'rejected';

  return (
    <div className={`bg-white rounded-2xl border ring-1 ${cfg.ring} border-slate-200 p-5 shadow-sm`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-1">
        <div>
          <p className="font-extrabold text-slate-900 text-base">{booking.unitType?.config?.name || 'Unit'}</p>
          <Link href={`/projects/${booking.project?._id}`} className="text-sm text-indigo-600 hover:underline font-medium flex items-center gap-1">
            <Building2 size={12} /> {booking.project?.basics?.name}
            <ChevronRight size={12} />
          </Link>
        </div>
        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${cfg.bg} ${cfg.color}`}>
          <Icon size={12} /> {cfg.label}
        </span>
      </div>

      {/* Booking meta */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 my-4 text-sm">
        <div className="bg-slate-50 rounded-xl p-3">
          <p className="text-slate-400 text-xs">Booking Ref</p>
          <p className="font-mono font-bold text-slate-800">#{booking._id?.slice(-8)?.toUpperCase()}</p>
        </div>
        <div className="bg-slate-50 rounded-xl p-3">
          <p className="text-slate-400 text-xs">Token Amount</p>
          <p className="font-bold text-indigo-700">₹{booking.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}</p>
        </div>
        <div className="bg-slate-50 rounded-xl p-3">
          <p className="text-slate-400 text-xs">Booked On</p>
          <p className="font-semibold text-slate-700">{new Date(booking.createdAt).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
        </div>
      </div>

      {/* Progress */}
      <ProgressBar status={booking.status} />

      {/* Payment submitted — show UTR */}
      {booking.status === 'payment_submitted' && (
        <div className="mt-4 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-sm">
          <p className="text-amber-700 font-semibold">⏳ Payment is under review by our team.</p>
          <p className="text-amber-600 text-xs mt-1">We'll confirm within 24 hours. Check your email for updates.</p>
          {booking.payment?.utrNumber && (
            <p className="text-slate-600 mt-2 text-xs">UTR submitted: <span className="font-mono font-bold">{booking.payment.utrNumber}</span></p>
          )}
        </div>
      )}

      {/* Confirmed */}
      {booking.status === 'confirmed' && (
        <div className="mt-4 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-3 text-sm">
          <p className="text-emerald-700 font-bold">🎉 Your unit has been allotted!</p>
          <p className="text-emerald-600 text-xs mt-1">Our sales team will contact you shortly with next steps — agreement signing, payment schedule, etc.</p>
          {booking.project?.salesContact?.phone && (
            <a href={`tel:${booking.project.salesContact.phone}`} className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 hover:underline">
              <Phone size={11} /> Call Sales Team
            </a>
          )}
        </div>
      )}

      {/* Rejected — show reason + resubmit */}
      {rejected && booking.status === 'enquiry' && (
        <div className="mt-4 bg-red-50 border border-red-200 rounded-xl px-4 py-3 text-sm">
          <p className="text-red-700 font-bold">❌ Payment Rejected</p>
          {booking.payment?.rejectionReason && (
            <p className="text-red-600 text-xs mt-1">Reason: {booking.payment.rejectionReason}</p>
          )}
          <p className="text-slate-600 text-xs mt-1">Please re-submit with the correct UTR or a clearer screenshot.</p>
          <button onClick={() => setShowResubmit(s => !s)}
            className="mt-2 text-xs text-indigo-600 font-semibold underline">
            {showResubmit ? 'Hide form' : 'Re-submit Payment Proof →'}
          </button>
          {showResubmit && (
            <ResubmitForm bookingId={booking._id} onSuccess={() => { setShowResubmit(false); onRefresh(); }} />
          )}
        </div>
      )}

      {/* Pure enquiry (no rejection) — awaiting payment */}
      {booking.status === 'enquiry' && !rejected && (
        <div className="mt-4 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm text-slate-600">
          ⚠️ Payment not yet submitted.
          <Link href={`/projects/${booking.project?._id}/units/${booking.unitType?._id}`} className="ml-2 text-indigo-600 font-semibold hover:underline">
            Go back and pay →
          </Link>
        </div>
      )}
    </div>
  );
}

export default function MyBookingsContent() {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetch_ = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/bookings/my`, { credentials: 'include' });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      setBookings(data.data);
    } catch (e) {
      setError(e.message || 'Failed to load bookings.');
    } finally { setLoading(false); }
  };

  useEffect(() => { fetch_(); }, []);

  return (
    <div className="min-h-screen bg-slate-50 pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-2xl font-extrabold text-slate-900 mb-1">My Bookings</h1>
        <p className="text-slate-500 text-sm mb-8">Track your project unit bookings and payment status.</p>

        {loading ? (
          <div className="flex items-center justify-center py-24 text-slate-400">
            <Loader2 size={24} className="animate-spin mr-2" /> Loading your bookings...
          </div>
        ) : error ? (
          <div className="bg-red-50 border border-red-200 rounded-2xl p-8 text-center">
            <p className="text-red-600 font-semibold">{error}</p>
            <Link href="/login" className="text-indigo-600 text-sm mt-2 inline-block font-semibold">Login to view your bookings →</Link>
          </div>
        ) : bookings.length === 0 ? (
          <div className="bg-white rounded-2xl border border-slate-200 p-16 text-center">
            <Building2 size={40} className="text-slate-300 mx-auto mb-3" />
            <p className="font-bold text-slate-700 text-lg">No bookings yet</p>
            <p className="text-slate-400 text-sm mt-1">Browse builder projects and book a unit to get started.</p>
            <Link href="/projects" className="mt-5 inline-block px-6 py-2.5 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition">
              Browse Projects →
            </Link>
          </div>
        ) : (
          <div className="space-y-5">
            {bookings.map(b => <BookingCard key={b._id} booking={b} onRefresh={fetch_} />)}
          </div>
        )}
      </div>
    </div>
  );
}
