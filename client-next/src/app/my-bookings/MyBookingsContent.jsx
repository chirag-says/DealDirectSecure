'use client';
import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import {
  CheckCircle, Clock, XCircle, Upload, Loader2, ChevronRight,
  Building2, Phone, AlertCircle, FileText, ArrowRight, Hash,
  Calendar, IndianRupee, Check, Circle, ShieldCheck, ExternalLink
} from 'lucide-react';
import { bookingApi } from '../../utils/api';

/* ── Status config ── */
const STATUS = {
  enquiry:           { label: 'Enquiry Created',      icon: Circle,      color: 'text-slate-600',    bg: 'bg-slate-50',     border: 'border-slate-200', step: 1 },
  payment_submitted: { label: 'Payment Under Review', icon: Clock,       color: 'text-amber-700',    bg: 'bg-amber-50',     border: 'border-amber-200', step: 2 },
  confirmed:         { label: 'Booking Confirmed',    icon: CheckCircle, color: 'text-emerald-700',  bg: 'bg-emerald-50',   border: 'border-emerald-200', step: 3 },
  cancelled:         { label: 'Cancelled',            icon: XCircle,     color: 'text-red-600',      bg: 'bg-red-50',       border: 'border-red-200', step: 0 },
  completed:         { label: 'Completed',            icon: ShieldCheck, color: 'text-blue-700',     bg: 'bg-blue-50',      border: 'border-blue-200', step: 4 },
};

const STEPS = [
  { label: 'Enquiry',   icon: FileText },
  { label: 'Payment',   icon: IndianRupee },
  { label: 'Verified',  icon: ShieldCheck },
  { label: 'Completed', icon: CheckCircle },
];

/* ── Progress stepper ── */
function ProgressBar({ status }) {
  const step = STATUS[status]?.step ?? 0;

  if (status === 'cancelled') return (
    <div className="flex items-center gap-2 mt-4 px-4 py-3 bg-red-50 border border-red-100 rounded-lg">
      <XCircle size={16} className="text-red-500 shrink-0" />
      <p className="text-sm text-red-600 font-medium">This booking has been cancelled</p>
    </div>
  );

  return (
    <div className="mt-5">
      <div className="flex items-center">
        {STEPS.map((s, i) => {
          const done = i < step;
          const active = i === step - 1;
          const StepIcon = s.icon;
          return (
            <React.Fragment key={i}>
              <div className="flex flex-col items-center relative">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center transition-all duration-300 ${
                  done ? 'bg-slate-900 text-white' :
                  active ? 'bg-slate-900 text-white ring-4 ring-slate-200' :
                  'bg-slate-100 text-slate-400 border border-slate-200'
                }`}>
                  {done ? <Check size={14} strokeWidth={3} /> : <StepIcon size={14} />}
                </div>
                <p className={`text-[10px] mt-1.5 whitespace-nowrap font-medium ${
                  done || active ? 'text-slate-900' : 'text-slate-400'
                }`}>{s.label}</p>
              </div>
              {i < STEPS.length - 1 && (
                <div className={`flex-1 h-px mx-2 mb-5 transition-all ${i < step - 1 ? 'bg-slate-900' : 'bg-slate-200'}`} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

/* ── Resubmit payment form ── */
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
      await bookingApi.submitPayment(bookingId, fd);
      onSuccess();
    } catch (e) {
      setError(e?.response?.data?.message || e.message || 'Submission failed. Try again.');
    } finally { setLoading(false); }
  };

  return (
    <div className="mt-4 border border-slate-200 rounded-lg p-4 bg-white">
      <p className="text-sm font-semibold text-slate-800 mb-3">Re-submit Payment Proof</p>
      {error && (
        <div className="flex items-center gap-2 text-xs text-red-600 mb-3 bg-red-50 px-3 py-2 rounded-md">
          <AlertCircle size={12} />{error}
        </div>
      )}
      <input value={utr} onChange={e => setUtr(e.target.value)} placeholder="UTR / Transaction Reference"
        className="w-full border border-slate-200 rounded-lg px-3.5 py-2.5 text-sm font-mono mb-3 focus:outline-none focus:border-slate-400 transition placeholder:text-slate-300" />
      <input type="file" accept="image/*" ref={fileRef} className="hidden" onChange={e => setScreenshot(e.target.files[0])} />
      <button onClick={() => fileRef.current?.click()}
        className={`w-full border rounded-lg py-2.5 text-sm text-center mb-3 transition flex items-center justify-center gap-2 ${
          screenshot
            ? 'border-emerald-300 text-emerald-700 bg-emerald-50'
            : 'border-dashed border-slate-300 text-slate-500 hover:border-slate-400 hover:bg-slate-50'
        }`}>
        {screenshot ? <><CheckCircle size={14} />{screenshot.name}</> : <><Upload size={14} />Upload Screenshot</>}
      </button>
      <button onClick={handleSubmit} disabled={loading}
        className="w-full py-2.5 bg-slate-900 text-white rounded-lg text-sm font-semibold hover:bg-slate-800 transition disabled:opacity-50 flex items-center justify-center gap-2">
        {loading ? <><Loader2 size={14} className="animate-spin" />Submitting...</> : 'Submit Proof'}
      </button>
    </div>
  );
}

/* ── Booking Card ── */
function BookingCard({ booking, onRefresh }) {
  const [showResubmit, setShowResubmit] = useState(false);
  const cfg = STATUS[booking.status] || STATUS.enquiry;
  const Icon = cfg.icon;
  const rejected = booking.payment?.status === 'rejected';

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden hover:shadow-md transition-shadow duration-200">
      {/* Header */}
      <div className="px-5 pt-5 pb-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="font-semibold text-slate-900 text-[15px] truncate">{booking.unitType?.config?.name || 'Unit'}</h3>
            <Link href={`/projects/${booking.project?._id}`}
              className="text-sm text-slate-500 hover:text-slate-700 font-medium flex items-center gap-1.5 mt-0.5 group">
              <Building2 size={13} className="text-slate-400" />
              {booking.project?.basics?.name}
              <ExternalLink size={11} className="opacity-0 group-hover:opacity-100 transition-opacity" />
            </Link>
          </div>
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border ${cfg.bg} ${cfg.color} ${cfg.border} shrink-0`}>
            <Icon size={13} />
            {cfg.label}
          </span>
        </div>

        {/* Meta row */}
        <div className="grid grid-cols-3 gap-3 mt-4">
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <Hash size={11} className="text-slate-400" />
              <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">Ref</p>
            </div>
            <p className="font-mono font-semibold text-slate-800 text-sm">{booking._id?.slice(-8)?.toUpperCase()}</p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <IndianRupee size={11} className="text-slate-400" />
              <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">Token</p>
            </div>
            <p className="font-semibold text-slate-800 text-sm">{booking.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}</p>
          </div>
          <div className="bg-slate-50 rounded-lg px-3 py-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <Calendar size={11} className="text-slate-400" />
              <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wider">Booked</p>
            </div>
            <p className="font-semibold text-slate-800 text-sm">{new Date(booking.createdAt).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' })}</p>
          </div>
        </div>

        {/* Progress */}
        <ProgressBar status={booking.status} />
      </div>

      {/* Status-specific footer panels */}
      {booking.status === 'payment_submitted' && (
        <div className="mx-5 mb-5 bg-amber-50 border border-amber-100 rounded-lg px-4 py-3">
          <div className="flex items-start gap-2.5">
            <Clock size={16} className="text-amber-600 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-800">Payment is under review</p>
              <p className="text-xs text-amber-600 mt-0.5">We will confirm within 24 hours. Check your email for updates.</p>
              {booking.payment?.utrNumber && (
                <p className="text-xs text-slate-600 mt-1.5 font-mono">UTR: <span className="font-semibold">{booking.payment.utrNumber}</span></p>
              )}
            </div>
          </div>
        </div>
      )}

      {booking.status === 'confirmed' && (
        <div className="mx-5 mb-5 bg-emerald-50 border border-emerald-100 rounded-lg px-4 py-3">
          <div className="flex items-start gap-2.5">
            <CheckCircle size={16} className="text-emerald-600 mt-0.5 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-emerald-800">Your unit has been allotted</p>
              <p className="text-xs text-emerald-600 mt-0.5">Our sales team will contact you with next steps — agreement signing, payment schedule, etc.</p>
              {booking.project?.salesContact?.phone && (
                <a href={`tel:${booking.project.salesContact.phone}`}
                  className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 hover:text-slate-900 transition">
                  <Phone size={12} /> Call Sales Team
                </a>
              )}
            </div>
          </div>
        </div>
      )}

      {rejected && booking.status === 'enquiry' && (
        <div className="mx-5 mb-5">
          <div className="bg-red-50 border border-red-100 rounded-lg px-4 py-3">
            <div className="flex items-start gap-2.5">
              <XCircle size={16} className="text-red-500 mt-0.5 shrink-0" />
              <div className="flex-1">
                <p className="text-sm font-semibold text-red-700">Payment Rejected</p>
                {booking.payment?.rejectionReason && (
                  <p className="text-xs text-red-600 mt-0.5">Reason: {booking.payment.rejectionReason}</p>
                )}
                <p className="text-xs text-slate-500 mt-1">Please re-submit with the correct UTR or a clearer screenshot.</p>
                <button onClick={() => setShowResubmit(s => !s)}
                  className="mt-2 text-xs text-slate-700 font-semibold hover:text-slate-900 transition flex items-center gap-1">
                  {showResubmit ? 'Hide form' : <><ArrowRight size={12} />Re-submit Payment Proof</>}
                </button>
              </div>
            </div>
          </div>
          {showResubmit && (
            <ResubmitForm bookingId={booking._id} onSuccess={() => { setShowResubmit(false); onRefresh(); }} />
          )}
        </div>
      )}

      {booking.status === 'enquiry' && !rejected && (
        <div className="mx-5 mb-5 bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <AlertCircle size={15} className="text-slate-400 shrink-0" />
              <p className="text-sm text-slate-600">Payment not yet submitted</p>
            </div>
            <Link href={`/projects/${booking.project?._id}/units/${booking.unitType?._id}`}
              className="text-sm font-semibold text-slate-800 hover:text-slate-900 whitespace-nowrap flex items-center gap-1 transition">
              Go back and pay <ArrowRight size={14} />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Main content ── */
export default function MyBookingsContent() {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetch_ = async () => {
    setLoading(true);
    try {
      const data = await bookingApi.getMyBookings();
      if (!data.success) throw new Error(data.message);
      setBookings(data.data);
    } catch (e) {
      setError(e?.response?.data?.message || e.message || 'Failed to load bookings.');
    } finally { setLoading(false); }
  };

  useEffect(() => { fetch_(); }, []);

  return (
    <div className="min-h-screen bg-slate-50 pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto">
        {/* Page header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">My Bookings</h1>
          <p className="text-slate-500 text-sm mt-1">Track your project unit bookings and payment status.</p>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-24 text-slate-400">
            <Loader2 size={28} className="animate-spin mb-3" />
            <p className="text-sm">Loading your bookings...</p>
          </div>
        ) : error ? (
          <div className="bg-white rounded-xl border border-slate-200 p-10 text-center">
            <AlertCircle size={32} className="text-red-400 mx-auto mb-3" />
            <p className="text-red-600 font-semibold text-sm">{error}</p>
            <Link href="/login" className="text-slate-700 text-sm mt-3 inline-flex items-center gap-1 font-semibold hover:text-slate-900 transition">
              Login to view your bookings <ArrowRight size={14} />
            </Link>
          </div>
        ) : bookings.length === 0 ? (
          <div className="bg-white rounded-xl border border-slate-200 p-16 text-center">
            <div className="w-14 h-14 bg-slate-100 rounded-xl flex items-center justify-center mx-auto mb-4">
              <Building2 size={24} className="text-slate-400" />
            </div>
            <p className="font-semibold text-slate-800 text-lg">No bookings yet</p>
            <p className="text-slate-500 text-sm mt-1.5 max-w-xs mx-auto">Browse builder projects and book a unit to get started.</p>
            <Link href="/projects" className="mt-6 inline-flex items-center gap-2 px-5 py-2.5 bg-slate-900 text-white rounded-lg font-semibold text-sm hover:bg-slate-800 transition">
              Browse Projects <ArrowRight size={15} />
            </Link>
          </div>
        ) : (
          <div className="space-y-4">
            {bookings.map(b => <BookingCard key={b._id} booking={b} onRefresh={fetch_} />)}
          </div>
        )}
      </div>
    </div>
  );
}
