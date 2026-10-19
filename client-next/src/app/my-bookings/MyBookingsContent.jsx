'use client';
import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  CheckCircle, Clock, XCircle, Loader2, Building2, AlertCircle,
  ArrowRight, Calendar, ExternalLink,
} from 'lucide-react';
import { useRouter } from 'next/navigation';
import { toast } from 'react-toastify';
import { bookingApi } from '../../utils/api';
import { useAuth } from '../../context/AuthContext';

/* ── Status labels ──
   A buyer's enquiry has three states that mean something to them: still open,
   closed by our team, or withdrawn. Records from the old paid-booking flow can
   still carry `payment_submitted` or `confirmed`. Neither is a state a buyer
   can act on any more, so both read as Closed rather than as a payment step
   that no longer exists. */
const STATUS = {
  enquiry:   { label: 'Sent',      icon: Clock,       color: 'text-blue-700',    bg: 'bg-blue-50',    border: 'border-blue-200' },
  completed: { label: 'Closed',    icon: CheckCircle, color: 'text-emerald-700', bg: 'bg-emerald-50', border: 'border-emerald-200' },
  cancelled: { label: 'Withdrawn', icon: XCircle,     color: 'text-slate-600',   bg: 'bg-slate-50',   border: 'border-slate-200' },
};
const statusOf = (status) => STATUS[status] || STATUS.completed;

const formatDate = (value) => {
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? null
    : d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
};

/* ── Enquiry Card ── */
function EnquiryCard({ enquiry, onRefresh }) {
  const [withdrawing, setWithdrawing] = useState(false);
  const [confirmWithdraw, setConfirmWithdraw] = useState(false);
  const cfg = statusOf(enquiry.status);
  const Icon = cfg.icon;
  // Mirrors the cancel endpoint, which accepts only an open enquiry. Offering
  // the button on anything else would only produce a 400 NOT_CANCELLABLE.
  const canWithdraw = enquiry.status === 'enquiry';
  const sentOn = formatDate(enquiry.createdAt);
  const projectId = enquiry.project?._id;
  const unitTypeId = enquiry.unitType?._id;

  const details = [
    ['Name', enquiry.clientName],
    ['Phone', enquiry.clientPhone],
    ['Email', enquiry.clientEmail],
    ['Your question', enquiry.notes],
  ].filter(([, value]) => value);

  const doWithdraw = async () => {
    setWithdrawing(true);
    try {
      const res = await bookingApi.cancel(enquiry._id, '');
      if (!res.success) throw new Error(res.message);
      toast.success(res.message || 'Enquiry withdrawn.');
      setConfirmWithdraw(false);
      onRefresh?.();
    } catch (e) {
      toast.error(e?.response?.data?.message || e.message || 'Could not withdraw this enquiry.');
    } finally {
      setWithdrawing(false);
    }
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden hover:shadow-md transition-shadow duration-200">
      <div className="px-5 pt-5 pb-4">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            {projectId && unitTypeId ? (
              <Link href={`/projects/${projectId}/units/${unitTypeId}`}
                className="font-semibold text-slate-900 text-[15px] truncate block hover:text-slate-700">
                {enquiry.unitType?.config?.name || 'Unit'}
              </Link>
            ) : (
              <h3 className="font-semibold text-slate-900 text-[15px] truncate">{enquiry.unitType?.config?.name || 'Unit'}</h3>
            )}
            {projectId ? (
              <Link href={`/projects/${projectId}`}
                className="text-sm text-slate-500 hover:text-slate-700 font-medium flex items-center gap-1.5 mt-0.5 group">
                <Building2 size={13} className="text-slate-400" />
                {enquiry.project?.basics?.name || 'Project'}
                <ExternalLink size={11} className="opacity-0 group-hover:opacity-100 transition-opacity" />
              </Link>
            ) : (
              <p className="text-sm text-slate-400 flex items-center gap-1.5 mt-0.5">
                <Building2 size={13} />Project no longer listed
              </p>
            )}
          </div>
          <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border ${cfg.bg} ${cfg.color} ${cfg.border} shrink-0`}>
            <Icon size={13} />
            {cfg.label}
          </span>
        </div>

        {/* Date and reference. The reference is what a buyer reads out when
            they call us about this enquiry. */}
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-3 text-xs text-slate-500">
          {sentOn && (
            <span className="inline-flex items-center gap-1.5"><Calendar size={12} className="text-slate-400" />Sent {sentOn}</span>
          )}
          <span>Ref <span className="font-mono font-semibold text-slate-700">{enquiry._id?.slice(-8)?.toUpperCase()}</span></span>
        </div>

        {/* What the buyer sent */}
        {details.length > 0 && (
          <dl className="mt-4 bg-slate-50 rounded-lg px-4 py-3 space-y-2 text-sm">
            {details.map(([label, value]) => (
              <div key={label} className="flex flex-col sm:flex-row sm:gap-3">
                <dt className="text-slate-400 sm:w-28 shrink-0">{label}</dt>
                <dd className="text-slate-800 break-words whitespace-pre-line min-w-0">{value}</dd>
              </div>
            ))}
          </dl>
        )}

        {enquiry.status === 'enquiry' && (
          <p className="text-xs text-slate-500 mt-3">Our team will call you back about this unit.</p>
        )}
      </div>

      {/* Withdraw.
          Deliberately quiet: a text button, not a red one. Withdrawing is not
          destructive, the buyer can send a fresh enquiry at any time. */}
      {canWithdraw && (
        <div className="px-5 pb-5">
          {confirmWithdraw ? (
            <div className="bg-slate-50 border border-slate-200 rounded-lg px-4 py-3">
              <p className="text-sm text-slate-700 font-medium">Withdraw this enquiry?</p>
              <p className="text-xs text-slate-500 mt-1">Our team will stop following it up. You can send a new one later.</p>
              <div className="flex items-center gap-2 mt-3">
                <button
                  onClick={doWithdraw}
                  disabled={withdrawing}
                  className="px-3 py-1.5 bg-slate-800 text-white rounded-lg text-xs font-semibold hover:bg-slate-900 transition disabled:opacity-60 inline-flex items-center gap-1.5"
                >
                  {withdrawing ? <><Loader2 size={12} className="animate-spin" /> Withdrawing…</> : 'Yes, withdraw'}
                </button>
                <button
                  onClick={() => setConfirmWithdraw(false)}
                  disabled={withdrawing}
                  className="px-3 py-1.5 border border-slate-200 text-slate-600 rounded-lg text-xs font-semibold hover:bg-white transition"
                >
                  Keep it
                </button>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setConfirmWithdraw(true)}
              className="text-xs text-slate-400 hover:text-slate-700 font-medium transition"
            >
              Withdraw
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Main content ── */
export default function MyBookingsContent() {
  const router = useRouter();
  const { isAuthenticated, loading: authLoading } = useAuth();
  const [enquiries, setEnquiries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetch_ = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await bookingApi.getMyBookings();
      if (!data.success) throw new Error(data.message);
      setEnquiries(Array.isArray(data.data) ? data.data : []);
    } catch (e) {
      setError(e?.response?.data?.message || e.message || 'Failed to load enquiries.');
    } finally { setLoading(false); }
  };

  // Auth guard, matching the pattern the other seven private screens use.
  //
  // This screen had none. A guest reached it, the effect fired
  // bookingApi.getMyBookings(), the backend returned 401, and the raw error was
  // rendered as a load failure, which reads as a broken page rather than "you
  // need to sign in". The axios interceptor does not redirect either, because
  // it only does so when a user is already in context.
  //
  // The edge middleware now also lists /my-bookings, so a guest is normally
  // redirected before this renders. This is the second layer, and it is what
  // catches the case the middleware itself documents: a cross-origin deployment
  // where `session_exists` is not visible at the edge.
  useEffect(() => {
    if (authLoading) return;
    if (!isAuthenticated) {
      router.push('/login?from=/my-bookings');
      return;
    }
    fetch_();
  }, [authLoading, isAuthenticated]);

  return (
    <div className="min-h-screen bg-slate-50 pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto">
        {/* Page header */}
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">My Enquiries</h1>
          <p className="text-slate-500 text-sm mt-1">Enquiries you have sent about builder project units, and where each one stands.</p>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-24 text-slate-400">
            <Loader2 size={28} className="animate-spin mb-3" />
            <p className="text-sm">Loading your enquiries...</p>
          </div>
        ) : error ? (
          /* Only authenticated users reach the fetch (2.4 added the guard
             above), so a failure here is a request problem, not a sign-in
             problem. The old CTA sent the user to /login, which for someone
             already signed in is a dead end that implies their session broke. */
          <div className="bg-white rounded-xl border border-slate-200 p-10 text-center">
            <AlertCircle size={32} className="text-red-400 mx-auto mb-3" />
            <p className="text-red-600 font-semibold text-sm">{error}</p>
            <p className="text-slate-500 text-xs mt-1.5">
              Your enquiries are safe. This is a problem loading them.
            </p>
            <button
              type="button"
              onClick={() => fetch_()}
              className="mt-4 inline-flex items-center gap-1.5 px-5 py-2.5 bg-slate-900 text-white rounded-lg font-semibold text-sm hover:bg-slate-800 transition"
            >
              Try again <ArrowRight size={14} />
            </button>
          </div>
        ) : enquiries.length === 0 ? (
          <div className="bg-white rounded-xl border border-slate-200 p-16 text-center">
            <div className="w-14 h-14 bg-slate-100 rounded-xl flex items-center justify-center mx-auto mb-4">
              <Building2 size={24} className="text-slate-400" />
            </div>
            <p className="font-semibold text-slate-800 text-lg">No enquiries yet</p>
            <p className="text-slate-500 text-sm mt-1.5 max-w-xs mx-auto">Browse builder projects and send an enquiry about any unit you like.</p>
            <Link href="/projects" className="mt-6 inline-flex items-center gap-2 px-5 py-2.5 bg-slate-900 text-white rounded-lg font-semibold text-sm hover:bg-slate-800 transition">
              Browse Projects <ArrowRight size={15} />
            </Link>
          </div>
        ) : (
          <div className="space-y-4">
            {enquiries.map(e => <EnquiryCard key={e._id} enquiry={e} onRefresh={fetch_} />)}
          </div>
        )}
      </div>
    </div>
  );
}
