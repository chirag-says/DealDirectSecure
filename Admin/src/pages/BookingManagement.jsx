import React, { useEffect, useState, useCallback } from 'react';
import {
  CheckCircle, XCircle, Eye, Clock, Search, Filter,
  Building2, Phone, Mail, FileText, ExternalLink, RefreshCw,
} from 'lucide-react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:9000/api';

const STATUS_CONFIG = {
  enquiry:           { label: 'Enquiry',            color: 'bg-slate-100 text-slate-600' },
  payment_submitted: { label: 'Payment Submitted',  color: 'bg-amber-100 text-amber-700' },
  confirmed:         { label: 'Confirmed',           color: 'bg-emerald-100 text-emerald-700' },
  cancelled:         { label: 'Cancelled',           color: 'bg-red-100 text-red-600' },
  completed:         { label: 'Completed',           color: 'bg-blue-100 text-blue-700' },
};

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || { label: status, color: 'bg-slate-100 text-slate-500' };
  return <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${cfg.color}`}>{cfg.label}</span>;
}

function fmtAmt(n) {
  if (!n) return '—';
  return `₹${n >= 1e7 ? (n/1e7).toFixed(2)+'Cr' : (n/1e5).toFixed(2)+'L'}`;
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ── Payment Proof Modal ──────────────────────────────────────────────────────
function PaymentProofModal({ booking, onClose, onAction, loading }) {
  const [action, setAction] = useState(null); // 'approve' | 'reject'
  const [adminNotes, setAdminNotes] = useState('');

  const handleSubmit = () => {
    if (!action) return;
    onAction(booking._id, action, adminNotes);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-indigo-700 px-6 py-4 text-white">
          <h2 className="font-bold text-lg">Payment Verification</h2>
          <p className="text-indigo-200 text-sm mt-0.5">Booking #{booking._id?.slice(-8)?.toUpperCase()}</p>
        </div>

        <div className="p-6 space-y-4 overflow-y-auto max-h-[70vh]">
          {/* Project + Unit */}
          <div className="bg-slate-50 rounded-xl p-4 grid grid-cols-2 gap-3 text-sm">
            <div><p className="text-slate-400 text-xs">Project</p><p className="font-semibold text-slate-800">{booking.project?.basics?.name || '—'}</p></div>
            <div><p className="text-slate-400 text-xs">Unit Type</p><p className="font-semibold text-slate-800">{booking.unitType?.config?.name || '—'}</p></div>
            <div><p className="text-slate-400 text-xs">Token Amount</p><p className="font-bold text-indigo-700 text-base">₹{booking.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}</p></div>
            <div><p className="text-slate-400 text-xs">Submitted</p><p className="font-semibold text-slate-800">{fmtDate(booking.payment?.submittedAt)}</p></div>
          </div>

          {/* Client */}
          <div className="border border-slate-200 rounded-xl p-4 text-sm">
            <p className="text-xs font-bold text-slate-400 uppercase mb-3">Client Details</p>
            <div className="space-y-2">
              <div className="flex items-center gap-2"><span className="text-slate-500 w-16">Name</span><span className="font-semibold">{booking.clientName}</span></div>
              <div className="flex items-center gap-2"><Phone size={12} className="text-slate-400" /><a href={`tel:${booking.clientPhone}`} className="text-indigo-600 font-semibold">{booking.clientPhone}</a></div>
              {booking.clientEmail && <div className="flex items-center gap-2"><Mail size={12} className="text-slate-400" /><a href={`mailto:${booking.clientEmail}`} className="text-indigo-600">{booking.clientEmail}</a></div>}
              {booking.notes && <div className="flex items-start gap-2"><FileText size={12} className="text-slate-400 mt-0.5" /><span className="text-slate-600 text-xs">{booking.notes}</span></div>}
            </div>
          </div>

          {/* Payment Proof */}
          <div className="border border-amber-200 bg-amber-50 rounded-xl p-4">
            <p className="text-xs font-bold text-amber-700 uppercase mb-3">Payment Proof</p>
            {booking.payment?.utrNumber ? (
              <div className="mb-3">
                <p className="text-xs text-slate-500 mb-1">UTR / Transaction Reference</p>
                <div className="bg-amber-100 border border-amber-300 rounded-lg px-4 py-3 font-mono font-bold text-amber-800 text-lg tracking-widest text-center">
                  {booking.payment.utrNumber}
                </div>
              </div>
            ) : <p className="text-sm text-slate-500 mb-3">No UTR provided</p>}

            {booking.payment?.screenshotUrl ? (
              <div>
                <p className="text-xs text-slate-500 mb-2">Payment Screenshot</p>
                <a href={booking.payment.screenshotUrl} target="_blank" rel="noopener noreferrer" className="block group">
                  <img src={booking.payment.screenshotUrl} alt="Payment screenshot" className="w-full rounded-lg border border-slate-200 object-contain max-h-48 group-hover:opacity-90 transition" />
                  <p className="text-xs text-indigo-600 mt-1 flex items-center gap-1"><ExternalLink size={11} /> Open full size</p>
                </a>
              </div>
            ) : <p className="text-sm text-slate-500">No screenshot uploaded</p>}
          </div>

          {/* Action */}
          {booking.status === 'payment_submitted' && (
            <div className="border border-slate-200 rounded-xl p-4">
              <p className="text-xs font-bold text-slate-400 uppercase mb-3">Admin Action</p>
              <div className="flex gap-3 mb-3">
                <button onClick={() => setAction('approve')}
                  className={`flex-1 py-2.5 rounded-xl text-sm font-bold border-2 transition flex items-center justify-center gap-2 ${action === 'approve' ? 'bg-emerald-600 text-white border-emerald-600' : 'border-emerald-300 text-emerald-700 hover:bg-emerald-50'}`}>
                  <CheckCircle size={16} /> Approve & Confirm
                </button>
                <button onClick={() => setAction('reject')}
                  className={`flex-1 py-2.5 rounded-xl text-sm font-bold border-2 transition flex items-center justify-center gap-2 ${action === 'reject' ? 'bg-red-600 text-white border-red-600' : 'border-red-300 text-red-600 hover:bg-red-50'}`}>
                  <XCircle size={16} /> Reject
                </button>
              </div>
              <textarea value={adminNotes} onChange={e => setAdminNotes(e.target.value)} placeholder={action === 'reject' ? 'Rejection reason (required)...' : 'Notes (optional)...'} rows={2}
                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-indigo-300 mb-3" />
              <button onClick={handleSubmit} disabled={!action || loading || (action === 'reject' && !adminNotes.trim())}
                className="w-full py-3 bg-indigo-600 text-white rounded-xl font-bold text-sm hover:bg-indigo-700 transition disabled:opacity-50">
                {loading ? 'Processing...' : action === 'approve' ? '✓ Confirm Booking & Allot Unit' : '✕ Reject Payment'}
              </button>
              {action === 'reject' && !adminNotes.trim() && <p className="text-xs text-red-500 mt-1">Please provide a rejection reason.</p>}
            </div>
          )}

          {/* Status History */}
          {booking.statusHistory?.length > 0 && (
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-2">Status History</p>
              <div className="space-y-1.5">
                {[...booking.statusHistory].reverse().map((h, i) => (
                  <div key={i} className="flex items-center justify-between text-xs text-slate-600 bg-slate-50 rounded-lg px-3 py-2">
                    <span className="font-semibold capitalize">{h.status?.replace('_', ' ')}</span>
                    <span className="text-slate-400">{h.note}</span>
                    <span className="text-slate-400">{fmtDate(h.changedAt)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="px-6 py-4 border-t border-slate-100">
          <button onClick={onClose} className="w-full py-2.5 border border-slate-200 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50 transition">Close</button>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────────────────
export default function BookingManagement() {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [toast, setToast] = useState(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const showToast = (msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3500);
  };

  const fetchBookings = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, limit: 20 });
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(`${API}/bookings?${params}`, { credentials: 'include' });
      const data = await res.json();
      if (data.success) {
        setBookings(data.data);
        setTotal(data.total || 0);
      }
    } catch (e) {
      showToast('Failed to load bookings', 'error');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => { fetchBookings(); }, [fetchBookings]);

  const handleAction = async (bookingId, action, adminNotes) => {
    setActionLoading(true);
    try {
      const res = await fetch(`${API}/bookings/${bookingId}/verify`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ action, adminNotes }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      showToast(action === 'approve' ? 'Booking confirmed & unit allotted!' : 'Payment rejected.');
      setSelected(null);
      fetchBookings();
    } catch (e) {
      showToast(e.message || 'Action failed', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStatusUpdate = async (bookingId, status) => {
    try {
      const res = await fetch(`${API}/bookings/${bookingId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ status }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      showToast(`Booking marked as ${status}`);
      fetchBookings();
    } catch (e) {
      showToast(e.message || 'Failed to update', 'error');
    }
  };

  const filtered = bookings.filter(b => {
    if (!search) return true;
    const s = search.toLowerCase();
    return b.clientName?.toLowerCase().includes(s) ||
      b.clientPhone?.includes(s) ||
      b.project?.basics?.name?.toLowerCase().includes(s) ||
      b.unitType?.config?.name?.toLowerCase().includes(s) ||
      b._id?.slice(-8).toLowerCase().includes(s);
  });

  const pendingCount = bookings.filter(b => b.status === 'payment_submitted').length;

  return (
    <div className="min-h-screen bg-slate-50 p-6">
      {/* Toast */}
      {toast && (
        <div className={`fixed top-5 right-5 z-50 px-5 py-3 rounded-xl shadow-xl text-white text-sm font-semibold transition-all ${toast.type === 'error' ? 'bg-red-600' : 'bg-emerald-600'}`}>
          {toast.msg}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-900 flex items-center gap-3">
            <Building2 size={24} className="text-indigo-600" /> Booking Management
          </h1>
          <p className="text-slate-500 text-sm mt-1">{total} total bookings{pendingCount > 0 && <span className="ml-2 bg-amber-100 text-amber-700 px-2 py-0.5 rounded-full text-xs font-bold">{pendingCount} pending verification</span>}</p>
        </div>
        <button onClick={fetchBookings} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50 transition">
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-2xl border border-slate-200 p-4 mb-5 flex flex-wrap gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[200px]">
          <Search size={16} className="text-slate-400 flex-shrink-0" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search client, project, booking ID..."
            className="flex-1 text-sm focus:outline-none text-slate-700" />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-slate-400" />
          <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
            className="text-sm border-0 focus:outline-none text-slate-700 bg-transparent cursor-pointer">
            <option value="">All Statuses</option>
            <option value="enquiry">Enquiry</option>
            <option value="payment_submitted">Payment Submitted</option>
            <option value="confirmed">Confirmed</option>
            <option value="cancelled">Cancelled</option>
            <option value="completed">Completed</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-400">Loading bookings...</div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <Building2 size={40} className="mb-3 opacity-30" />
            <p className="font-medium">No bookings found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  {['Booking ID', 'Client', 'Project / Unit', 'Token Amount', 'Status', 'Date', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-bold text-slate-400 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {filtered.map(b => (
                  <tr key={b._id} className="hover:bg-slate-50/60 transition">
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs font-bold text-slate-700 bg-slate-100 px-2 py-1 rounded">
                        #{b._id?.slice(-8)?.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-semibold text-slate-800">{b.clientName}</p>
                      <a href={`tel:${b.clientPhone}`} className="text-xs text-indigo-600">{b.clientPhone}</a>
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-semibold text-slate-800">{b.project?.basics?.name || '—'}</p>
                      <p className="text-xs text-slate-400">{b.unitType?.config?.name || '—'}</p>
                    </td>
                    <td className="px-4 py-3 font-bold text-indigo-700">
                      ₹{b.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={b.status} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{fmtDate(b.createdAt)}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button onClick={() => setSelected(b)}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${b.status === 'payment_submitted' ? 'bg-amber-100 text-amber-700 hover:bg-amber-200' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}>
                          <Eye size={12} /> {b.status === 'payment_submitted' ? 'Verify' : 'View'}
                        </button>
                        {b.status === 'confirmed' && (
                          <button onClick={() => handleStatusUpdate(b._id, 'completed')}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-100 text-blue-700 hover:bg-blue-200 transition">
                            Mark Done
                          </button>
                        )}
                        {(b.status === 'enquiry' || b.status === 'payment_submitted') && (
                          <button onClick={() => handleStatusUpdate(b._id, 'cancelled')}
                            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-50 text-red-500 hover:bg-red-100 transition">
                            Cancel
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {total > 20 && (
        <div className="flex justify-center gap-2 mt-4">
          <button onClick={() => setPage(p => Math.max(1, p-1))} disabled={page === 1} className="px-4 py-2 rounded-xl border border-slate-200 text-sm font-semibold disabled:opacity-40">← Prev</button>
          <span className="px-4 py-2 text-sm text-slate-500">Page {page} of {Math.ceil(total/20)}</span>
          <button onClick={() => setPage(p => p+1)} disabled={page >= Math.ceil(total/20)} className="px-4 py-2 rounded-xl border border-slate-200 text-sm font-semibold disabled:opacity-40">Next →</button>
        </div>
      )}

      {/* Modal */}
      {selected && (
        <PaymentProofModal
          booking={selected}
          onClose={() => setSelected(null)}
          onAction={handleAction}
          loading={actionLoading}
        />
      )}
    </div>
  );
}
