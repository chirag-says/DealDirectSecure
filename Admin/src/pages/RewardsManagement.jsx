import React, { useState, useEffect, useCallback } from 'react';
import { rewardsManagementApi, userManagementApi } from '../api/adminApi';
import { Search, Gift, TrendingUp, TrendingDown, RefreshCw, CheckCircle, XCircle, Clock, ChevronLeft, ChevronRight, Users, Coins, ArrowUpDown, ChevronUp, ChevronDown, Award } from 'lucide-react';

const tierColors = {
    bronze: 'bg-orange-100 text-orange-700',
    silver: 'bg-slate-100 text-slate-600',
    gold: 'bg-yellow-100 text-yellow-700',
    diamond: 'bg-cyan-100 text-cyan-700',
};

const tierEmoji = { bronze: '🥉', silver: '🥈', gold: '🥇', diamond: '💎' };

const statusColors = {
    pending: 'bg-yellow-100 text-yellow-700',
    processing: 'bg-blue-100 text-blue-700',
    fulfilled: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
    cancelled: 'bg-gray-100 text-gray-500',
};

const statusIcons = {
    pending: <Clock className="w-4 h-4" />,
    processing: <RefreshCw className="w-4 h-4 animate-spin" />,
    fulfilled: <CheckCircle className="w-4 h-4" />,
    failed: <XCircle className="w-4 h-4" />,
};

export default function RewardsManagement() {
    const [activeTab, setActiveTab] = useState('overview');
    const [redemptions, setRedemptions] = useState([]);
    const [rdPagination, setRdPagination] = useState({});
    const [rdPage, setRdPage] = useState(1);
    const [statusFilter, setStatusFilter] = useState('');
    const [loading, setLoading] = useState(false);

    // User wallet lookup
    const [searchUserId, setSearchUserId] = useState('');
    const [userWallet, setUserWallet] = useState(null);
    const [userInfo, setUserInfo] = useState(null);
    const [walletLoading, setWalletLoading] = useState(false);
    const [walletError, setWalletError] = useState('');

    // Adjust points
    const [adjustUserId, setAdjustUserId] = useState('');
    const [adjustPoints, setAdjustPoints] = useState('');
    const [adjustReason, setAdjustReason] = useState('');
    const [adjustLoading, setAdjustLoading] = useState(false);
    const [adjustMessage, setAdjustMessage] = useState('');

    // Overview state
    const [overviewSummary, setOverviewSummary] = useState(null);
    const [overviewWallets, setOverviewWallets] = useState([]);
    const [overviewPagination, setOverviewPagination] = useState({});
    const [overviewPage, setOverviewPage] = useState(1);
    const [overviewSort, setOverviewSort] = useState('totalPoints');
    const [overviewOrder, setOverviewOrder] = useState('desc');
    const [overviewSearch, setOverviewSearch] = useState('');
    const [overviewLoading, setOverviewLoading] = useState(false);

    // Update redemption modal
    const [editRedemption, setEditRedemption] = useState(null);
    const [editStatus, setEditStatus] = useState('');
    const [editNotes, setEditNotes] = useState('');
    const [editVoucher, setEditVoucher] = useState('');

    // Fetch redemptions
    const fetchRedemptions = useCallback(async (page = 1) => {
        setLoading(true);
        try {
            const res = await rewardsManagementApi.getRedemptions({
                status: statusFilter || undefined, page, limit: 15
            });
            if (res.success) {
                setRedemptions(res.requests || []);
                setRdPagination(res.pagination || {});
                setRdPage(page);
            }
        } catch (err) {
            console.error('Failed to load redemptions:', err);
        } finally {
            setLoading(false);
        }
    }, [statusFilter]);

    // Fetch overview
    const fetchOverview = useCallback(async (page = 1) => {
        setOverviewLoading(true);
        try {
            const res = await rewardsManagementApi.getOverview({
                page, limit: 20, sort: overviewSort, order: overviewOrder,
                search: overviewSearch || undefined,
            });
            if (res.success) {
                setOverviewSummary(res.summary);
                setOverviewWallets(res.wallets || []);
                setOverviewPagination(res.pagination || {});
                setOverviewPage(page);
            }
        } catch (err) {
            console.error('Failed to load overview:', err);
        } finally {
            setOverviewLoading(false);
        }
    }, [overviewSort, overviewOrder, overviewSearch]);

    useEffect(() => {
        if (activeTab === 'redemptions') fetchRedemptions(1);
        if (activeTab === 'overview') fetchOverview(1);
    }, [activeTab, fetchRedemptions, fetchOverview]);

    const handleOverviewSort = (field) => {
        if (overviewSort === field) {
            setOverviewOrder(prev => prev === 'desc' ? 'asc' : 'desc');
        } else {
            setOverviewSort(field);
            setOverviewOrder('desc');
        }
    };

    const SortIcon = ({ field }) => {
        if (overviewSort !== field) return <ArrowUpDown className="w-3 h-3 inline ml-1 opacity-30" />;
        return overviewOrder === 'desc'
            ? <ChevronDown className="w-3 h-3 inline ml-1 text-blue-600" />
            : <ChevronUp className="w-3 h-3 inline ml-1 text-blue-600" />;
    };

    // Lookup user wallet
    const lookupWallet = async () => {
        if (!searchUserId.trim()) return;
        setWalletLoading(true);
        setWalletError('');
        try {
            const res = await rewardsManagementApi.getUserWallet(searchUserId.trim());
            if (res.success) {
                setUserWallet(res.wallet);
                setUserInfo(res.user);
            } else {
                setWalletError('User not found');
                setUserWallet(null);
            }
        } catch (err) {
            setWalletError(err.response?.data?.message || 'Failed to fetch wallet');
            setUserWallet(null);
        } finally {
            setWalletLoading(false);
        }
    };

    // Adjust points
    const handleAdjust = async (e) => {
        e.preventDefault();
        if (!adjustUserId || !adjustPoints) return;
        setAdjustLoading(true);
        setAdjustMessage('');
        try {
            const res = await rewardsManagementApi.adjustPoints(
                adjustUserId.trim(),
                parseInt(adjustPoints),
                adjustReason
            );
            if (res.success) {
                setAdjustMessage(`✅ Points adjusted. New balance: ${res.newBalance} pts (${res.tier} tier)`);
                setAdjustPoints('');
                setAdjustReason('');
            } else {
                setAdjustMessage(`❌ ${res.message}`);
            }
        } catch (err) {
            setAdjustMessage(`❌ ${err.response?.data?.message || 'Failed to adjust points'}`);
        } finally {
            setAdjustLoading(false);
        }
    };

    // Update redemption
    const handleUpdateRedemption = async () => {
        if (!editRedemption || !editStatus) return;
        try {
            const res = await rewardsManagementApi.updateRedemption(editRedemption._id, {
                status: editStatus,
                adminNotes: editNotes,
                voucherCode: editVoucher,
            });
            if (res.success) {
                setEditRedemption(null);
                fetchRedemptions(rdPage);
            }
        } catch (err) {
            alert('Failed to update redemption');
        }
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-gray-900">Rewards Management</h1>
                    <p className="text-sm text-gray-500 mt-1">Manage user points, tiers, and redemption requests</p>
                </div>
                <div className="flex items-center gap-2">
                    <Gift className="w-8 h-8 text-amber-500" />
                </div>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 bg-gray-100 rounded-lg p-1">
                {[
                    { id: 'overview', label: 'Overview' },
                    { id: 'redemptions', label: 'Redemption Requests' },
                    { id: 'lookup', label: 'User Wallet Lookup' },
                    { id: 'adjust', label: 'Adjust Points' },
                ].map(tab => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${activeTab === tab.id ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'}`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* ===== OVERVIEW TAB ===== */}
            {activeTab === 'overview' && (
                <div className="space-y-6">
                    {/* Summary Cards */}
                    {overviewSummary && (
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                                <div className="flex items-center gap-3 mb-2">
                                    <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center">
                                        <Users className="w-5 h-5 text-blue-600" />
                                    </div>
                                    <span className="text-sm font-medium text-gray-500">Total Users</span>
                                </div>
                                <p className="text-3xl font-extrabold text-gray-900">{overviewSummary.totalWallets.toLocaleString('en-IN')}</p>
                            </div>
                            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                                <div className="flex items-center gap-3 mb-2">
                                    <div className="w-10 h-10 rounded-lg bg-green-50 flex items-center justify-center">
                                        <Coins className="w-5 h-5 text-green-600" />
                                    </div>
                                    <span className="text-sm font-medium text-gray-500">Points Distributed</span>
                                </div>
                                <p className="text-3xl font-extrabold text-gray-900">{overviewSummary.totalPointsDistributed.toLocaleString('en-IN')}</p>
                                <p className="text-xs text-gray-400 mt-1">≈ ₹{(overviewSummary.totalPointsDistributed * 0.05).toLocaleString('en-IN')}</p>
                            </div>
                            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                                <div className="flex items-center gap-3 mb-2">
                                    <div className="w-10 h-10 rounded-lg bg-amber-50 flex items-center justify-center">
                                        <TrendingUp className="w-5 h-5 text-amber-600" />
                                    </div>
                                    <span className="text-sm font-medium text-gray-500">Available Points</span>
                                </div>
                                <p className="text-3xl font-extrabold text-gray-900">{overviewSummary.totalAvailablePoints.toLocaleString('en-IN')}</p>
                                <p className="text-xs text-gray-400 mt-1">≈ ₹{(overviewSummary.totalAvailablePoints * 0.05).toLocaleString('en-IN')}</p>
                            </div>
                            <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
                                <div className="flex items-center gap-3 mb-2">
                                    <div className="w-10 h-10 rounded-lg bg-purple-50 flex items-center justify-center">
                                        <Award className="w-5 h-5 text-purple-600" />
                                    </div>
                                    <span className="text-sm font-medium text-gray-500">Tier Breakdown</span>
                                </div>
                                <div className="flex flex-wrap gap-2 mt-1">
                                    {Object.entries(overviewSummary.tierBreakdown).map(([tier, count]) => (
                                        <span key={tier} className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold ${tierColors[tier]}`}>
                                            {tierEmoji[tier]} {count}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Wallets Table */}
                    <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
                        {/* Search + Refresh */}
                        <div className="flex items-center gap-3 p-4 border-b border-gray-100">
                            <div className="relative flex-1 max-w-sm">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                                <input
                                    type="text"
                                    placeholder="Search by name or email..."
                                    value={overviewSearch}
                                    onChange={(e) => setOverviewSearch(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && fetchOverview(1)}
                                    className="w-full pl-10 pr-4 py-2 border border-gray-200 rounded-lg text-sm"
                                />
                            </div>
                            <button onClick={() => fetchOverview(1)} className="px-3 py-2 text-sm bg-gray-100 rounded-lg hover:bg-gray-200">
                                <RefreshCw className={`w-4 h-4 ${overviewLoading ? 'animate-spin' : ''}`} />
                            </button>
                        </div>

                        {overviewLoading ? (
                            <div className="p-8 text-center text-gray-400">Loading...</div>
                        ) : overviewWallets.length === 0 ? (
                            <div className="p-8 text-center text-gray-400">No reward wallets found</div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                    <thead className="bg-gray-50 border-b">
                                        <tr>
                                            <th className="text-left p-3 font-medium text-gray-500">User</th>
                                            <th className="text-left p-3 font-medium text-gray-500 cursor-pointer select-none hover:text-gray-700" onClick={() => handleOverviewSort('totalPoints')}>
                                                Total Points <SortIcon field="totalPoints" />
                                            </th>
                                            <th className="text-left p-3 font-medium text-gray-500 cursor-pointer select-none hover:text-gray-700" onClick={() => handleOverviewSort('availablePoints')}>
                                                Available <SortIcon field="availablePoints" />
                                            </th>
                                            <th className="text-left p-3 font-medium text-gray-500 cursor-pointer select-none hover:text-gray-700" onClick={() => handleOverviewSort('tier')}>
                                                Tier <SortIcon field="tier" />
                                            </th>
                                            <th className="text-left p-3 font-medium text-gray-500 cursor-pointer select-none hover:text-gray-700" onClick={() => handleOverviewSort('updatedAt')}>
                                                Last Activity <SortIcon field="updatedAt" />
                                            </th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-50">
                                        {overviewWallets.map(w => (
                                            <tr key={w._id} className="hover:bg-gray-50">
                                                <td className="p-3">
                                                    <p className="font-medium text-gray-800">{w.userName || '—'}</p>
                                                    <p className="text-xs text-gray-400">{w.userEmail || '—'}</p>
                                                </td>
                                                <td className="p-3 font-semibold text-gray-800">{w.totalPoints?.toLocaleString('en-IN')}</td>
                                                <td className="p-3 font-semibold text-amber-600">{w.availablePoints?.toLocaleString('en-IN')}</td>
                                                <td className="p-3">
                                                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold capitalize ${tierColors[w.tier] || ''}`}>
                                                        {tierEmoji[w.tier] || ''} {w.tier}
                                                    </span>
                                                </td>
                                                <td className="p-3 text-gray-500">{w.updatedAt ? new Date(w.updatedAt).toLocaleDateString('en-IN') : '—'}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}

                        {/* Pagination */}
                        {overviewPagination.totalPages > 1 && (
                            <div className="flex items-center justify-between p-4 border-t border-gray-100">
                                <span className="text-sm text-gray-500">Page {overviewPage} of {overviewPagination.totalPages} ({overviewPagination.total} users)</span>
                                <div className="flex gap-2">
                                    <button disabled={overviewPage <= 1} onClick={() => fetchOverview(overviewPage - 1)} className="p-2 border rounded-lg disabled:opacity-40">
                                        <ChevronLeft className="w-4 h-4" />
                                    </button>
                                    <button disabled={overviewPage >= overviewPagination.totalPages} onClick={() => fetchOverview(overviewPage + 1)} className="p-2 border rounded-lg disabled:opacity-40">
                                        <ChevronRight className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* ===== REDEMPTIONS TAB ===== */}
            {activeTab === 'redemptions' && (
                <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
                    {/* Filter bar */}
                    <div className="flex items-center gap-3 p-4 border-b border-gray-100">
                        <select
                            value={statusFilter}
                            onChange={(e) => setStatusFilter(e.target.value)}
                            className="border border-gray-200 rounded-lg px-3 py-2 text-sm"
                        >
                            <option value="">All Statuses</option>
                            <option value="pending">Pending</option>
                            <option value="processing">Processing</option>
                            <option value="fulfilled">Fulfilled</option>
                            <option value="failed">Failed</option>
                        </select>
                        <button onClick={() => fetchRedemptions(1)} className="px-3 py-2 text-sm bg-gray-100 rounded-lg hover:bg-gray-200">
                            <RefreshCw className="w-4 h-4" />
                        </button>
                    </div>

                    {/* Table */}
                    {loading ? (
                        <div className="p-8 text-center text-gray-400">Loading...</div>
                    ) : redemptions.length === 0 ? (
                        <div className="p-8 text-center text-gray-400">No redemption requests found</div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm">
                                <thead className="bg-gray-50 border-b">
                                    <tr>
                                        <th className="text-left p-3 font-medium text-gray-500">User</th>
                                        <th className="text-left p-3 font-medium text-gray-500">Reward</th>
                                        <th className="text-left p-3 font-medium text-gray-500">Points</th>
                                        <th className="text-left p-3 font-medium text-gray-500">Status</th>
                                        <th className="text-left p-3 font-medium text-gray-500">Date</th>
                                        <th className="text-left p-3 font-medium text-gray-500">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-50">
                                    {redemptions.map(rd => (
                                        <tr key={rd._id} className="hover:bg-gray-50">
                                            <td className="p-3">
                                                <p className="font-medium text-gray-800">{rd.user?.name || '-'}</p>
                                                <p className="text-xs text-gray-400">{rd.user?.email || '-'}</p>
                                            </td>
                                            <td className="p-3 text-gray-700">{rd.rewardName}</td>
                                            <td className="p-3 font-semibold text-amber-600">{rd.pointsSpent}</td>
                                            <td className="p-3">
                                                <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium ${statusColors[rd.status] || ''}`}>
                                                    {statusIcons[rd.status]} {rd.status}
                                                </span>
                                            </td>
                                            <td className="p-3 text-gray-500">{new Date(rd.createdAt).toLocaleDateString('en-IN')}</td>
                                            <td className="p-3">
                                                <button
                                                    onClick={() => { setEditRedemption(rd); setEditStatus(rd.status); setEditNotes(rd.adminNotes || ''); setEditVoucher(rd.voucherCode || ''); }}
                                                    className="text-blue-600 hover:text-blue-700 text-xs font-medium"
                                                >
                                                    Update
                                                </button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* Pagination */}
                    {rdPagination.totalPages > 1 && (
                        <div className="flex items-center justify-between p-4 border-t border-gray-100">
                            <span className="text-sm text-gray-500">Page {rdPage} of {rdPagination.totalPages}</span>
                            <div className="flex gap-2">
                                <button disabled={rdPage <= 1} onClick={() => fetchRedemptions(rdPage - 1)} className="p-2 border rounded-lg disabled:opacity-40">
                                    <ChevronLeft className="w-4 h-4" />
                                </button>
                                <button disabled={rdPage >= rdPagination.totalPages} onClick={() => fetchRedemptions(rdPage + 1)} className="p-2 border rounded-lg disabled:opacity-40">
                                    <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ===== WALLET LOOKUP TAB ===== */}
            {activeTab === 'lookup' && (
                <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-6">
                    <div className="flex gap-3">
                        <div className="relative flex-1">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                            <input
                                type="text"
                                placeholder="Enter User ID (MongoDB ObjectId)"
                                value={searchUserId}
                                onChange={(e) => setSearchUserId(e.target.value)}
                                className="w-full pl-10 pr-4 py-2.5 border border-gray-200 rounded-lg text-sm"
                            />
                        </div>
                        <button onClick={lookupWallet} disabled={walletLoading} className="px-5 py-2.5 bg-gray-900 text-white rounded-lg text-sm font-medium hover:bg-gray-800 disabled:opacity-50">
                            {walletLoading ? 'Searching...' : 'Look Up'}
                        </button>
                    </div>

                    {walletError && <p className="text-red-500 text-sm">{walletError}</p>}

                    {userWallet && userInfo && (
                        <div className="space-y-4">
                            <div className="flex items-center gap-4 p-4 bg-gray-50 rounded-xl">
                                <div className="w-12 h-12 rounded-full bg-gradient-to-br from-amber-400 to-orange-500 flex items-center justify-center text-white text-xl font-bold">
                                    {userInfo.name?.charAt(0) || '?'}
                                </div>
                                <div>
                                    <p className="font-semibold text-gray-900">{userInfo.name}</p>
                                    <p className="text-sm text-gray-500">{userInfo.email}</p>
                                    <p className="text-xs text-gray-400">Referral Code: {userInfo.referralCode || 'N/A'}</p>
                                </div>
                            </div>

                            <div className="grid grid-cols-3 gap-4">
                                <div className="bg-green-50 rounded-xl p-4 text-center">
                                    <p className="text-2xl font-extrabold text-green-700">{userWallet.availablePoints}</p>
                                    <p className="text-xs text-green-600">Available</p>
                                </div>
                                <div className="bg-blue-50 rounded-xl p-4 text-center">
                                    <p className="text-2xl font-extrabold text-blue-700">{userWallet.totalPoints}</p>
                                    <p className="text-xs text-blue-600">Lifetime</p>
                                </div>
                                <div className="bg-amber-50 rounded-xl p-4 text-center">
                                    <p className="text-2xl font-extrabold text-amber-700 capitalize">{userWallet.tier}</p>
                                    <p className="text-xs text-amber-600">Tier (×{userWallet.tierMultiplier})</p>
                                </div>
                            </div>

                            {userWallet.recentTransactions?.length > 0 && (
                                <div>
                                    <h4 className="font-semibold text-gray-700 mb-2 text-sm">Recent Transactions</h4>
                                    <div className="space-y-1 max-h-60 overflow-y-auto">
                                        {userWallet.recentTransactions.map((tx, i) => (
                                            <div key={i} className="flex justify-between items-center py-2 px-3 bg-gray-50 rounded-lg text-sm">
                                                <span className="text-gray-700">{tx.description}</span>
                                                <span className={`font-bold ${tx.points >= 0 ? 'text-green-600' : 'text-red-500'}`}>
                                                    {tx.points >= 0 ? '+' : ''}{tx.points}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ===== ADJUST POINTS TAB ===== */}
            {activeTab === 'adjust' && (
                <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
                    <h3 className="font-semibold text-gray-900 mb-4">Manually Adjust User Points</h3>
                    <form onSubmit={handleAdjust} className="space-y-4 max-w-md">
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
                            <input
                                type="text" required
                                placeholder="MongoDB ObjectId"
                                value={adjustUserId}
                                onChange={(e) => setAdjustUserId(e.target.value)}
                                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg text-sm"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Points (positive to add, negative to deduct)</label>
                            <input
                                type="number" required
                                placeholder="e.g. 500 or -200"
                                value={adjustPoints}
                                onChange={(e) => setAdjustPoints(e.target.value)}
                                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg text-sm"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Reason</label>
                            <input
                                type="text"
                                placeholder="Reason for adjustment"
                                value={adjustReason}
                                onChange={(e) => setAdjustReason(e.target.value)}
                                className="w-full px-4 py-2.5 border border-gray-200 rounded-lg text-sm"
                            />
                        </div>
                        <button
                            type="submit" disabled={adjustLoading}
                            className="px-6 py-2.5 bg-gray-900 text-white rounded-lg text-sm font-medium hover:bg-gray-800 disabled:opacity-50"
                        >
                            {adjustLoading ? 'Adjusting...' : 'Adjust Points'}
                        </button>
                        {adjustMessage && <p className="text-sm mt-2">{adjustMessage}</p>}
                    </form>
                </div>
            )}

            {/* ===== UPDATE REDEMPTION MODAL ===== */}
            {editRedemption && (
                <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4" onClick={() => setEditRedemption(null)}>
                    <div className="bg-white rounded-xl shadow-xl max-w-md w-full p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
                        <h3 className="font-bold text-gray-900">Update Redemption</h3>
                        <p className="text-sm text-gray-500">{editRedemption.rewardName} — {editRedemption.pointsSpent} pts</p>

                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                            <select value={editStatus} onChange={(e) => setEditStatus(e.target.value)} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm">
                                <option value="pending">Pending</option>
                                <option value="processing">Processing</option>
                                <option value="fulfilled">Fulfilled</option>
                                <option value="failed">Failed (refunds points)</option>
                                <option value="cancelled">Cancelled</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Voucher Code (if applicable)</label>
                            <input type="text" value={editVoucher} onChange={(e) => setEditVoucher(e.target.value)} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm" />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">Admin Notes</label>
                            <textarea value={editNotes} onChange={(e) => setEditNotes(e.target.value)} rows={2} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm" />
                        </div>
                        <div className="flex gap-3 justify-end">
                            <button onClick={() => setEditRedemption(null)} className="px-4 py-2 border border-gray-200 rounded-lg text-sm">Cancel</button>
                            <button onClick={handleUpdateRedemption} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">Update</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
