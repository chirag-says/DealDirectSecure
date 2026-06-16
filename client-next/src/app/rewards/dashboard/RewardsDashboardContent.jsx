'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '../../../context/AuthContext';
import { rewardsApi } from '../../../utils/api';
import {
    BarChart3, Link2, Gift, ScrollText, Users, CheckCircle,
    Zap, Handshake, Copy, Share2, ArrowUpRight, ArrowDownRight,
    ChevronLeft, ChevronRight, BookOpen, TrendingUp, Wallet,
    Clock, Star, Award, Gem,
} from 'lucide-react';
import HubbleStorefront from './RewardStorefront';

// ============================================
// TIER CONFIG
// ============================================
const TIER_CONFIG = {
    bronze: { icon: Award, color: '#a38b5e', bg: 'from-amber-50 to-orange-50', border: 'border-amber-200', label: 'Bronze' },
    silver: { icon: Award, color: '#7b8a9e', bg: 'from-slate-50 to-gray-50', border: 'border-gray-300', label: 'Silver' },
    gold: { icon: Star, color: '#c5940a', bg: 'from-yellow-50 to-amber-50', border: 'border-yellow-300', label: 'Gold' },
    diamond: { icon: Gem, color: '#3b82f6', bg: 'from-blue-50 to-indigo-50', border: 'border-blue-300', label: 'Diamond' },
};

// ============================================
// MAIN DASHBOARD COMPONENT
// ============================================
export default function RewardsDashboardContent() {
    const router = useRouter();
    const { isAuthenticated, loading: authLoading } = useAuth();
    const [wallet, setWallet] = useState(null);
    const [referral, setReferral] = useState(null);
    const [transactions, setTransactions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('overview');
    const [redeemLoading, setRedeemLoading] = useState(null);
    const [copySuccess, setCopySuccess] = useState(false);
    const [txPage, setTxPage] = useState(1);
    const [txPagination, setTxPagination] = useState({});

    // Redirect if not authenticated
    useEffect(() => {
        if (!authLoading && !isAuthenticated) {
            router.push('/login?redirect=/rewards/dashboard');
        }
    }, [authLoading, isAuthenticated, router]);

    // Fetch data
    const fetchData = useCallback(async () => {
        if (!isAuthenticated) return;
        setLoading(true);
        try {
            const [walletRes, referralRes] = await Promise.all([
                rewardsApi.getWallet(),
                rewardsApi.getReferralCode(),
            ]);
            if (walletRes.success) setWallet(walletRes.wallet);
            if (referralRes.success) setReferral(referralRes);
        } catch (err) {
            console.error('Failed to load rewards data:', err);
        } finally {
            setLoading(false);
        }
    }, [isAuthenticated]);

    useEffect(() => { fetchData(); }, [fetchData]);

    // Fetch transactions (paginated)
    const fetchTransactions = useCallback(async (page = 1) => {
        try {
            const res = await rewardsApi.getTransactions({ page, limit: 15 });
            if (res.success) {
                setTransactions(res.transactions || []);
                setTxPagination(res.pagination || {});
                setTxPage(page);
            }
        } catch (err) {
            console.error('Failed to load transactions:', err);
        }
    }, []);

    useEffect(() => {
        if (activeTab === 'history' && isAuthenticated) fetchTransactions(1);
    }, [activeTab, isAuthenticated, fetchTransactions]);

    // Copy referral code
    const copyReferralCode = async () => {
        if (!referral?.referralCode) return;
        try {
            await navigator.clipboard.writeText(referral.referralCode);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        } catch {
            const input = document.createElement('input');
            input.value = referral.referralCode;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        }
    };

    // Share referral link
    const shareReferral = async () => {
        if (!referral?.referralLink) return;
        if (navigator.share) {
            try {
                await navigator.share({
                    title: 'Join DealDirect',
                    text: `Use my referral code ${referral.referralCode} to join DealDirect and start earning rewards!`,
                    url: referral.referralLink,
                });
            } catch { }
        } else {
            await navigator.clipboard.writeText(referral.referralLink);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        }
    };

    // Redeem
    const handleRedeem = async (slug) => {
        if (redeemLoading) return;
        setRedeemLoading(slug);
        try {
            const res = await rewardsApi.redeem({ rewardSlug: slug });
            if (res.success) {
                alert(`✅ ${res.message}`);
                fetchData();
            } else {
                alert(`❌ ${res.message}`);
            }
        } catch (err) {
            alert('Redemption failed. Please try again.');
        } finally {
            setRedeemLoading(null);
        }
    };

    if (authLoading || loading) {
        return (
            <div className="min-h-screen bg-gray-50 pt-28 flex items-center justify-center">
                <div className="text-center">
                    <div className="w-12 h-12 border-4 border-red-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
                    <p className="text-gray-500 mt-4">Loading your rewards...</p>
                </div>
            </div>
        );
    }

    if (!isAuthenticated) return null;

    const tc = wallet ? TIER_CONFIG[wallet.tier] || TIER_CONFIG.bronze : TIER_CONFIG.bronze;
    const TierIcon = tc.icon;

    return (
        <div className="min-h-screen bg-gray-50 pt-28 pb-20">
            <div className="max-w-5xl mx-auto px-4 sm:px-6">
                {/* Header */}
                <div className="flex items-center justify-between mb-8">
                    <div>
                        <h1 className="text-2xl sm:text-3xl font-extrabold text-gray-900">My Rewards</h1>
                        <p className="text-gray-500 text-sm mt-1">Your wallet, your way.</p>
                    </div>
                    <Link href="/rewards" className="text-red-600 hover:text-red-700 text-sm font-medium">
                        How It Works →
                    </Link>
                </div>

                {/* ===== WALLET CARD ===== */}
                {wallet && (
                    <div className={`rounded-2xl border ${tc.border} bg-gradient-to-br ${tc.bg} p-6 sm:p-8 mb-8 shadow-sm`}>
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-6">
                            {/* Left */}
                            <div>
                                <div className="flex items-center gap-3 mb-4">
                                    <div className="w-10 h-10 rounded-full flex items-center justify-center" style={{ backgroundColor: tc.color + '20' }}>
                                        <TierIcon className="w-5 h-5" style={{ color: tc.color }} />
                                    </div>
                                    <div>
                                        <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: tc.color }}>
                                            {wallet.tier} Tier
                                        </p>
                                        <p className="text-sm text-gray-500">
                                            {wallet.tierMultiplier > 1
                                                ? `+${Math.round((wallet.tierMultiplier - 1) * 100)}% bonus on all actions`
                                                : 'Standard rewards'}
                                        </p>
                                    </div>
                                </div>

                                <div className="mt-2">
                                    <p className="text-xs text-gray-400 uppercase tracking-wider font-semibold">Available Balance</p>
                                    <p className="text-4xl sm:text-5xl font-extrabold text-gray-900 mt-1">
                                        {wallet.availablePoints.toLocaleString()}
                                        <span className="text-lg text-gray-400 ml-1">pts</span>
                                    </p>
                                </div>
                            </div>

                            {/* Right – Progress */}
                            {wallet.nextTierProgress && wallet.nextTierProgress.nextTier && (
                                <div className="bg-white/60 backdrop-blur-sm rounded-xl p-4 sm:min-w-[220px]">
                                    <p className="text-xs text-gray-500 mb-2">
                                        Progress to <span className="font-semibold capitalize">{wallet.nextTierProgress.nextTier}</span>
                                    </p>
                                    <div className="w-full h-2.5 bg-gray-200 rounded-full overflow-hidden">
                                        <div
                                            className="h-full bg-gradient-to-r from-red-500 to-red-600 rounded-full transition-all duration-1000"
                                            style={{ width: `${wallet.nextTierProgress.progress}%` }}
                                        ></div>
                                    </div>
                                    <p className="text-xs text-gray-400 mt-1.5">
                                        {wallet.nextTierProgress.pointsNeeded.toLocaleString()} pts to go
                                    </p>
                                    <p className="text-xs text-gray-400 mt-0.5">
                                        Lifetime: {wallet.totalPoints.toLocaleString()} pts
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* ===== TABS ===== */}
                <div className="flex gap-1 bg-white rounded-xl border border-gray-100 p-1 mb-8 shadow-sm overflow-x-auto">
                    {[
                        { id: 'overview', label: 'Overview', icon: BarChart3 },
                        { id: 'referrals', label: 'Referrals', icon: Link2 },
                        { id: 'redeem', label: 'Redeem', icon: Gift },
                        { id: 'history', label: 'History', icon: ScrollText },
                    ].map(tab => {
                        const TabIcon = tab.icon;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${activeTab === tab.id
                                    ? 'bg-red-600 text-white shadow-sm'
                                    : 'text-gray-600 hover:bg-gray-100'
                                    }`}
                            >
                                <TabIcon className="w-4 h-4" />
                                {tab.label}
                            </button>
                        );
                    })}
                </div>

                {/* ===== TAB CONTENT ===== */}

                {/* OVERVIEW */}
                {activeTab === 'overview' && wallet && (
                    <div className="space-y-6">
                        {/* Recent Activity */}
                        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                            <h3 className="font-bold text-gray-900 mb-4 flex items-center gap-2">
                                <Clock className="w-4 h-4 text-gray-400" />
                                Recent Activity
                            </h3>
                            {wallet.recentTransactions && wallet.recentTransactions.length > 0 ? (
                                <div className="space-y-3">
                                    {wallet.recentTransactions.slice(0, 5).map((tx, i) => (
                                        <div key={i} className="flex items-center justify-between py-2 border-b border-gray-50 last:border-0">
                                            <div>
                                                <p className="text-sm font-medium text-gray-700">{tx.description}</p>
                                                <p className="text-xs text-gray-400">{new Date(tx.createdAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}</p>
                                            </div>
                                            <span className={`text-sm font-bold ${tx.points >= 0 ? 'text-green-600' : 'text-red-500'}`}>
                                                {tx.points >= 0 ? '+' : ''}{tx.points} pts
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            ) : (
                                <p className="text-gray-400 text-sm">No activity yet. Start earning by listing a property or sending an enquiry!</p>
                            )}
                        </div>

                        {/* Quick links */}
                        <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                            <button onClick={() => setActiveTab('referrals')} className="bg-white rounded-xl border border-gray-100 p-5 text-center hover:shadow-md transition-all group">
                                <Link2 className="w-6 h-6 mx-auto text-red-500 group-hover:scale-110 transition-transform" />
                                <p className="font-semibold text-gray-800 text-sm mt-2">Share & Earn</p>
                                <p className="text-xs text-gray-400">Refer friends</p>
                            </button>
                            <button onClick={() => setActiveTab('redeem')} className="bg-white rounded-xl border border-gray-100 p-5 text-center hover:shadow-md transition-all group">
                                <Gift className="w-6 h-6 mx-auto text-amber-500 group-hover:scale-110 transition-transform" />
                                <p className="font-semibold text-gray-800 text-sm mt-2">Redeem Points</p>
                                <p className="text-xs text-gray-400">Vouchers & cash</p>
                            </button>
                            <Link href="/rewards" className="bg-white rounded-xl border border-gray-100 p-5 text-center hover:shadow-md transition-all group">
                                <BookOpen className="w-6 h-6 mx-auto text-blue-500 group-hover:scale-110 transition-transform" />
                                <p className="font-semibold text-gray-800 text-sm mt-2">Learn More</p>
                                <p className="text-xs text-gray-400">How rewards work</p>
                            </Link>
                        </div>
                    </div>
                )}

                {/* REFERRALS */}
                {activeTab === 'referrals' && (
                    <div className="space-y-6">
                        {/* Referral code card */}
                        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                            <h3 className="font-bold text-gray-900 mb-2 flex items-center gap-2">
                                <Link2 className="w-4 h-4 text-gray-400" />
                                Your Referral Code
                            </h3>
                            <p className="text-gray-500 text-sm mb-5">Share this code with friends and earn points at every milestone of their journey.</p>

                            <div className="flex items-center gap-3 flex-wrap">
                                <div className="bg-gray-50 border-2 border-dashed border-gray-200 rounded-xl px-6 py-3">
                                    <span className="text-2xl font-mono font-bold text-gray-900 tracking-wider">
                                        {referral?.referralCode || '------'}
                                    </span>
                                </div>
                                <button
                                    onClick={copyReferralCode}
                                    className={`inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all ${copySuccess ? 'bg-green-100 text-green-700' : 'bg-red-600 text-white hover:bg-red-700'}`}
                                >
                                    <Copy className="w-4 h-4" />
                                    {copySuccess ? 'Copied!' : 'Copy Code'}
                                </button>
                                <button
                                    onClick={shareReferral}
                                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold bg-gray-100 text-gray-700 hover:bg-gray-200 transition-all"
                                >
                                    <Share2 className="w-4 h-4" />
                                    Share Link
                                </button>
                            </div>
                        </div>

                        {/* Referral stats */}
                        {referral?.stats && (
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                                {[
                                    { label: 'Total Referred', value: referral.stats.totalReferred, icon: Users, color: 'text-blue-600', bg: 'bg-blue-50' },
                                    { label: 'Signed Up', value: referral.stats.signups, icon: CheckCircle, color: 'text-green-600', bg: 'bg-green-50' },
                                    { label: 'First Action', value: referral.stats.firstActions, icon: Zap, color: 'text-amber-600', bg: 'bg-amber-50' },
                                    { label: 'Deals Closed', value: referral.stats.dealClosures, icon: Handshake, color: 'text-purple-600', bg: 'bg-purple-50' },
                                ].map((stat, i) => {
                                    const StatIcon = stat.icon;
                                    return (
                                        <div key={i} className="bg-white rounded-xl border border-gray-100 p-4 text-center shadow-sm">
                                            <div className={`w-8 h-8 rounded-full ${stat.bg} flex items-center justify-center mx-auto`}>
                                                <StatIcon className={`w-4 h-4 ${stat.color}`} />
                                            </div>
                                            <p className="text-2xl font-extrabold text-gray-900 mt-2">{stat.value}</p>
                                            <p className="text-xs text-gray-400 mt-0.5">{stat.label}</p>
                                        </div>
                                    );
                                })}
                            </div>
                        )}

                        {/* Referred people list */}
                        {referral?.stats?.referrals && referral.stats.referrals.length > 0 && (
                            <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                                <h3 className="font-bold text-gray-900 mb-4">Your Referrals</h3>
                                <div className="space-y-3">
                                    {referral.stats.referrals.map((r, i) => (
                                        <div key={i} className="flex items-center justify-between py-2 border-b border-gray-50 last:border-0">
                                            <div>
                                                <p className="text-sm font-medium text-gray-700">{r.referredUser?.name || 'User'}</p>
                                                <p className="text-xs text-gray-400">
                                                    Joined {r.referredUser?.joinedAt ? new Date(r.referredUser.joinedAt).toLocaleDateString('en-IN') : 'N/A'}
                                                </p>
                                            </div>
                                            <div className="flex gap-2">
                                                {r.milestones.signup && <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full">Signup</span>}
                                                {r.milestones.firstAction && <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">1st Action</span>}
                                                {r.milestones.dealClosure && <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">Deal Closed</span>}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {/* REDEEM — Hubble Gift Card SDK */}
                {activeTab === 'redeem' && (
                    <HubbleStorefront />
                )}

                {/* HISTORY */}
                {activeTab === 'history' && (
                    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
                        <h3 className="font-bold text-gray-900 mb-4 flex items-center gap-2">
                            <ScrollText className="w-4 h-4 text-gray-400" />
                            Transaction History
                        </h3>
                        {transactions.length > 0 ? (
                            <>
                                <div className="divide-y divide-gray-50">
                                    {transactions.map((tx, i) => (
                                        <div key={i} className="flex items-center justify-between py-3">
                                            <div className="flex items-center gap-3">
                                                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm ${tx.type === 'earn' ? 'bg-green-50 text-green-600' :
                                                    tx.type === 'redeem' ? 'bg-red-50 text-red-500' :
                                                        tx.type === 'adjustment' ? 'bg-blue-50 text-blue-600' :
                                                            'bg-gray-50 text-gray-500'
                                                    }`}>
                                                    {tx.type === 'earn' ? <ArrowUpRight className="w-4 h-4" /> :
                                                        tx.type === 'redeem' ? <ArrowDownRight className="w-4 h-4" /> :
                                                            <TrendingUp className="w-4 h-4" />}
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-gray-700">{tx.description}</p>
                                                    <p className="text-xs text-gray-400">
                                                        {new Date(tx.createdAt).toLocaleDateString('en-IN', {
                                                            day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit'
                                                        })}
                                                        {tx.multiplier > 1 && (
                                                            <span className="ml-2 text-amber-500">×{tx.multiplier}</span>
                                                        )}
                                                    </p>
                                                </div>
                                            </div>
                                            <span className={`text-sm font-bold ${tx.points >= 0 ? 'text-green-600' : 'text-red-500'}`}>
                                                {tx.points >= 0 ? '+' : ''}{tx.points} pts
                                            </span>
                                        </div>
                                    ))}
                                </div>

                                {/* Pagination */}
                                {txPagination.totalPages > 1 && (
                                    <div className="flex justify-center gap-2 mt-6">
                                        <button
                                            onClick={() => fetchTransactions(txPage - 1)}
                                            disabled={txPage <= 1}
                                            className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded-lg border border-gray-200 disabled:opacity-40"
                                        >
                                            <ChevronLeft className="w-4 h-4" /> Prev
                                        </button>
                                        <span className="px-3 py-1.5 text-sm text-gray-500">
                                            Page {txPage} of {txPagination.totalPages}
                                        </span>
                                        <button
                                            onClick={() => fetchTransactions(txPage + 1)}
                                            disabled={txPage >= txPagination.totalPages}
                                            className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded-lg border border-gray-200 disabled:opacity-40"
                                        >
                                            Next <ChevronRight className="w-4 h-4" />
                                        </button>
                                    </div>
                                )}
                            </>
                        ) : (
                            <p className="text-gray-400 text-sm text-center py-8">No transactions yet.</p>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
