import React, { useEffect, useState, useCallback } from 'react';
import {
  CheckCircle, XCircle, Eye, Search, Filter,
  Inbox, Phone, Mail, FileText, RefreshCw,
} from 'lucide-react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:9000/api';

/**
 * Enquiry inbox for builder project units.
 *
 * DealDirect takes no money from buyers (owner decision, 2026-10-19), so every
 * new record is an enquiry and the team's only job is to call the buyer back
 * and then close it. Records from the old paid-booking flow can still carry
 * `payment_submitted` or `confirmed`; they are shown under plain labels so they
 * can be closed out, and nothing here asks anyone to verify a payment.
 */
const STATUS_CONFIG = {
  enquiry:           { label: 'New',                        color: 'bg-indigo-100 text-indigo-700' },
  completed:         { label: 'Done',                       color: 'bg-emerald-100 text-emerald-700' },
  cancelled:         { label: 'Cancelled',                  color: 'bg-red-100 text-red-600' },
  payment_submitted: { label: 'Payment submitted (legacy)', color: 'bg-slate-100 text-slate-600' },
  confirmed:         { label: 'Confirmed (legacy)',         color: 'bg-slate-100 text-slate-600' },
};

const statusLabel = (status) => STATUS_CONFIG[status]?.label || status || 'Unknown';

/**
 * The moves PUT /bookings/:id/status accepts from each state. 'completed' and
 * 'cancelled' are final, so they have no entry. Offering a button the API
 * would refuse only produces an error toast.
 */
const NEXT_STATUSES = {
  enquiry:           ['completed', 'cancelled'],
  payment_submitted: ['cancelled'],
  confirmed:         ['completed', 'cancelled'],
};

const ACTION_LABEL = { completed: 'Mark Done', cancelled: 'Cancel' };

function StatusBadge({ status }) {
  const cfg = STATUS_CONFIG[status] || { label: status, color: 'bg-slate-100 text-slate-500' };
  return <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold ${cfg.color}`}>{cfg.label}</span>;
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ── Enquiry Detail Modal ─────────────────────────────────────────────────────
function EnquiryDetailModal({ enquiry, onClose, onStatusChange, loading }) {
  const [adminNotes, setAdminNotes] = useState('');
  const nextStatuses = NEXT_STATUSES[enquiry.status] || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 to-indigo-700 px-6 py-4 text-white flex items-start justify-between gap-3">
          <div>
            <h2 className="font-bold text-lg">Enquiry</h2>
            <p className="text-indigo-200 text-sm mt-0.5">#{enquiry._id?.slice(-8)?.toUpperCase()} · {fmtDate(enquiry.createdAt)}</p>
          </div>
          <StatusBadge status={enquiry.status} />
        </div>

        <div className="p-6 space-y-4 overflow-y-auto max-h-[70vh]">
          {/* Project + Unit */}
          <div className="bg-slate-50 rounded-xl p-4 grid grid-cols-2 gap-3 text-sm">
            <div><p className="text-slate-400 text-xs">Project</p><p className="font-semibold text-slate-800">{enquiry.project?.basics?.name || '—'}</p></div>
            <div><p className="text-slate-400 text-xs">Unit Type</p><p className="font-semibold text-slate-800">{enquiry.unitType?.config?.name || '—'}</p></div>
          </div>

          {/* Client */}
          <div className="border border-slate-200 rounded-xl p-4 text-sm">
            <p className="text-xs font-bold text-slate-400 uppercase mb-3">Client Details</p>
            <div className="space-y-2">
              <div className="flex items-center gap-2"><span className="text-slate-500 w-16">Name</span><span className="font-semibold">{enquiry.clientName}</span></div>
              <div className="flex items-center gap-2"><Phone size={12} className="text-slate-400" /><a href={`tel:${enquiry.clientPhone}`} className="text-indigo-600 font-semibold">{enquiry.clientPhone}</a></div>
              {enquiry.clientEmail && <div className="flex items-center gap-2"><Mail size={12} className="text-slate-400" /><a href={`mailto:${enquiry.clientEmail}`} className="text-indigo-600">{enquiry.clientEmail}</a></div>}
              {enquiry.notes && <div className="flex items-start gap-2"><FileText size={12} className="text-slate-400 mt-0.5 shrink-0" /><span className="text-slate-600 text-xs whitespace-pre-line break-words">{enquiry.notes}</span></div>}
            </div>
          </div>

          {enquiry.adminNotes && (
            <div className="border border-slate-200 rounded-xl p-4 text-sm">
              <p className="text-xs font-bold text-slate-400 uppercase mb-2">Team Note</p>
              <p className="text-slate-600 text-xs whitespace-pre-line break-words">{enquiry.adminNotes}</p>
            </div>
          )}

          {/* Action */}
          {nextStatuses.length > 0 && (
            <div className="border border-slate-200 rounded-xl p-4">
              <p className="text-xs font-bold text-slate-400 uppercase mb-3">Close This Enquiry</p>
              <textarea value={adminNotes} onChange={e => setAdminNotes(e.target.value)} placeholder="Note (optional), e.g. called, site visit booked" rows={2}
                className="w-full border border-slate-200 rounded-xl px-3 py-2 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-indigo-300 mb-3" />
              <div className="flex gap-3">
                {nextStatuses.includes('completed') && (
                  <button onClick={() => onStatusChange(enquiry._id, 'completed', adminNotes)} disabled={loading}
                    className="flex-1 py-2.5 rounded-xl text-sm font-bold border-2 border-emerald-300 text-emerald-700 hover:bg-emerald-50 transition flex items-center justify-center gap-2 disabled:opacity-50">
                    <CheckCircle size={16} /> {ACTION_LABEL.completed}
                  </button>
                )}
                {nextStatuses.includes('cancelled') && (
                  <button onClick={() => onStatusChange(enquiry._id, 'cancelled', adminNotes)} disabled={loading}
                    className="flex-1 py-2.5 rounded-xl text-sm font-bold border-2 border-red-300 text-red-600 hover:bg-red-50 transition flex items-center justify-center gap-2 disabled:opacity-50">
                    <XCircle size={16} /> {ACTION_LABEL.cancelled}
                  </button>
                )}
              </div>
              {loading && <p className="text-xs text-slate-400 mt-2">Saving...</p>}
            </div>
          )}

          {/* Status History */}
          {enquiry.statusHistory?.length > 0 && (
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-2">Status History</p>
              <div className="space-y-1.5">
                {[...enquiry.statusHistory].reverse().map((h, i) => (
                  <div key={i} className="flex items-center justify-between gap-3 text-xs text-slate-600 bg-slate-50 rounded-lg px-3 py-2">
                    <span className="font-semibold">{statusLabel(h.status)}</span>
                    <span className="text-slate-400 truncate">{h.note}</span>
                    <span className="text-slate-400 shrink-0">{fmtDate(h.changedAt)}</span>
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
  const [enquiries, setEnquiries] = useState([]);
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

  const fetchEnquiries = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page, limit: 20 });
      if (statusFilter) params.set('status', statusFilter);
      const res = await fetch(`${API}/bookings?${params}`, { credentials: 'include' });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      setEnquiries(data.data || []);
      setTotal(data.total || 0);
    } catch {
      showToast('Failed to load enquiries', 'error');
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter]);

  useEffect(() => { fetchEnquiries(); }, [fetchEnquiries]);

  const handleStatusChange = async (id, status, adminNotes) => {
    setActionLoading(true);
    try {
      const body = { status };
      if (adminNotes?.trim()) body.adminNotes = adminNotes.trim();
      const res = await fetch(`${API}/bookings/${id}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message);
      showToast(status === 'completed' ? 'Enquiry marked done.' : 'Enquiry cancelled.');
      setSelected(null);
      fetchEnquiries();
    } catch (e) {
      showToast(e.message || 'Failed to update', 'error');
    } finally {
      setActionLoading(false);
    }
  };

  const filtered = enquiries.filter(b => {
    if (!search) return true;
    const s = search.toLowerCase();
    return b.clientName?.toLowerCase().includes(s) ||
      b.clientPhone?.includes(s) ||
      b.project?.basics?.name?.toLowerCase().includes(s) ||
      b.unitType?.config?.name?.toLowerCase().includes(s) ||
      b._id?.slice(-8).toLowerCase().includes(s);
  });

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
            <Inbox size={24} className="text-indigo-600" /> Enquiries
          </h1>
          <p className="text-slate-500 text-sm mt-1">{total} total enquiries about builder project units</p>
        </div>
        <button onClick={fetchEnquiries} className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-xl text-sm font-semibold text-slate-600 hover:bg-slate-50 transition">
          <RefreshCw size={15} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-2xl border border-slate-200 p-4 mb-5 flex flex-wrap gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[200px]">
          <Search size={16} className="text-slate-400 flex-shrink-0" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search client, project, enquiry ID..."
            className="flex-1 text-sm focus:outline-none text-slate-700" />
        </div>
        <div className="flex items-center gap-2">
          <Filter size={15} className="text-slate-400" />
          <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }}
            className="text-sm border-0 focus:outline-none text-slate-700 bg-transparent cursor-pointer">
            <option value="">All Statuses</option>
            <option value="enquiry">New</option>
            <option value="completed">Done</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20 text-slate-400">Loading enquiries...</div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <Inbox size={40} className="mb-3 opacity-30" />
            <p className="font-medium">No enquiries found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  {['Enquiry ID', 'Client', 'Project / Unit', 'Status', 'Date', 'Actions'].map(h => (
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
                    <td className="px-4 py-3"><StatusBadge status={b.status} /></td>
                    <td className="px-4 py-3 text-xs text-slate-400">{fmtDate(b.createdAt)}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => setSelected(b)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${b.status === 'enquiry' ? 'bg-indigo-100 text-indigo-700 hover:bg-indigo-200' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'}`}>
                        <Eye size={12} /> {b.status === 'enquiry' ? 'Open' : 'View'}
                      </button>
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
        <EnquiryDetailModal
          enquiry={selected}
          onClose={() => setSelected(null)}
          onStatusChange={handleStatusChange}
          loading={actionLoading}
        />
      )}
    </div>
  );
}
