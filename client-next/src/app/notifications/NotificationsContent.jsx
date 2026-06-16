'use client';

import React, { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { FaBell, FaCheckCircle } from "react-icons/fa";
import { Gift, CheckCircle } from "lucide-react";
import { toast } from "react-toastify";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import RewardRevealRouter from "../../components/Rewards/RewardRevealRouter";

const NotificationsContent = () => {
    const [notifications, setNotifications] = useState([]);
    const [loading, setLoading] = useState(true);
    const [markingAll, setMarkingAll] = useState(false);
    const [markingOneId, setMarkingOneId] = useState(null);
    const [claimingId, setClaimingId] = useState(null);
    const [showDoorGame, setShowDoorGame] = useState(false);
    const [rewardData, setRewardData] = useState(null);
    const router = useRouter();
    const { isAuthenticated, loading: authLoading } = useAuth();

    const fetchNotifications = async () => {
        try {
            setLoading(true);
            const res = await api.get('/notifications');
            if (res.data.success) {
                setNotifications(res.data.notifications || []);
            } else {
                toast.error(res.data.message || "Failed to load notifications");
            }
        } catch (err) {
            console.error("Fetch notifications error", err);
            if (err.response?.status !== 401) {
                toast.error(err.response?.data?.message || "Failed to load notifications");
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (!authLoading) {
            if (isAuthenticated) {
                fetchNotifications();
            } else {
                toast.info("Login to view your notifications");
                router.push("/login?from=/notifications");
            }
        }
    }, [authLoading, isAuthenticated, router]);

    const markOneAsRead = async (id) => {
        try {
            setMarkingOneId(id);
            await api.patch(`/notifications/${id}/read`);
            setNotifications((prev) =>
                prev.map((n) => (n._id === id ? { ...n, isRead: true } : n))
            );
            // Notify Navbar to re-fetch unread count
            window.dispatchEvent(new Event('notifications-updated'));
        } catch (err) {
            console.error("Mark notification read error", err);
        } finally {
            setMarkingOneId(null);
        }
    };

    const handleMarkAllRead = async () => {
        try {
            setMarkingAll(true);
            await api.patch('/notifications/mark-all/read');
            setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
            // Notify Navbar to re-fetch unread count
            window.dispatchEvent(new Event('notifications-updated'));
        } catch (err) {
            console.error("Mark all read error", err);
            toast.error("Failed to mark all as read");
        } finally {
            setMarkingAll(false);
        }
    };

    const handleClaimReward = useCallback(async (notification) => {
        const verificationId = notification.data?.verificationId;
        if (!verificationId) {
            toast.error("Invalid reward notification");
            return;
        }

        setClaimingId(notification._id);
        try {
            const res = await api.post(`/properties/claim-deal-reward/${verificationId}`);
            if (res.data.success) {
                // Mark as read
                if (!notification.isRead) {
                    markOneAsRead(notification._id);
                }

                // Update local state to show it's claimed
                setNotifications((prev) =>
                    prev.map((n) =>
                        n._id === notification._id
                            ? { ...n, data: { ...n.data, isClaimed: true } }
                            : n
                    )
                );

                if (res.data.alreadyClaimed) {
                    toast.info(`You already claimed this reward: ₹${res.data.reward.cashValue} (${res.data.reward.pointsAwarded} pts)`);
                } else {
                    // Show the door game with the reward data
                    setRewardData(res.data.reward);
                    setShowDoorGame(true);
                }
            }
        } catch (err) {
            const msg = err.response?.data?.message || "Failed to claim reward";
            toast.error(msg);
        } finally {
            setClaimingId(null);
        }
    }, []);

    const handleItemClick = async (n) => {
        // For deal_reward notifications, don't navigate — the claim button handles it
        if (n.type === "deal_reward") {
            return;
        }

        if (!n.isRead) {
            markOneAsRead(n._id);
        }

        if (n.type === "saved-search-match" && n.data?.propertyId) {
            router.push(`/properties/${n.data.propertyId}`);
        } else if (n.type === "saved-search" && n.data?.savedSearchId) {
            router.push(`/properties`);
        } else if (n.type === "interest") {
            router.push(`/my-properties`);
        }
    };

    const handleDoorGameClose = () => {
        setShowDoorGame(false);
        setRewardData(null);
    };

    const unreadCount = notifications.filter((n) => !n.isRead).length;

    if (authLoading) {
        return (
            <div className="min-h-screen mt-20 sm:mt-24 px-4 sm:px-8 lg:px-20 bg-slate-50 pb-16">
                <div className="max-w-4xl mx-auto">
                    <div className="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 text-sm text-slate-500 flex items-center justify-center">
                        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-600 mr-3"></div>
                        Loading...
                    </div>
                </div>
            </div>
        );
    }

    return (
        <>
            <div className="min-h-screen mt-20 sm:mt-24 px-4 sm:px-8 lg:px-20 bg-slate-50 pb-16">
                <div className="max-w-4xl mx-auto">
                    <div className="flex items-center justify-between mb-6">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-full bg-red-600 flex items-center justify-center text-white shadow-lg">
                                <FaBell />
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-slate-900">Notifications</h1>
                                <p className="text-xs sm:text-sm text-slate-500">
                                    All your alerts in one place — saved searches, matches and more.
                                </p>
                            </div>
                        </div>
                        {notifications.length > 0 && (
                            <button
                                onClick={handleMarkAllRead}
                                disabled={markingAll || unreadCount === 0}
                                className="text-xs sm:text-sm px-3 py-1.5 rounded-full border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 disabled:opacity-50"
                            >
                                <FaCheckCircle className="inline mr-1" /> Mark all as read
                            </button>
                        )}
                    </div>

                    {loading ? (
                        <div className="bg-white rounded-2xl shadow-sm border border-slate-100 p-6 text-sm text-slate-500">
                            Loading notifications...
                        </div>
                    ) : notifications.length === 0 ? (
                        <div className="bg-white rounded-2xl shadow-sm border border-dashed border-slate-200 p-10 text-center">
                            <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-4">
                                <FaBell className="text-slate-400 text-xl" />
                            </div>
                            <h2 className="font-semibold text-slate-800 mb-1">No notifications yet</h2>
                            <p className="text-xs sm:text-sm text-slate-500 max-w-sm mx-auto">
                                Save a search or interact with properties and we will start showing smart alerts for you here.
                            </p>
                        </div>
                    ) : (
                        <div className="bg-white rounded-2xl shadow-sm border border-slate-100 divide-y divide-slate-100 overflow-hidden">
                            {notifications.map((n) => (
                                <div
                                    key={n._id}
                                    className={`w-full text-left px-5 sm:px-6 py-4 flex gap-3 sm:gap-4 items-start transition-colors ${n.isRead ? "bg-white" : "bg-red-50/60"
                                        }`}
                                >
                                    <div className="mt-1">
                                        <span
                                            className={`inline-block w-2 h-2 rounded-full ${n.isRead ? "bg-slate-300" : "bg-red-500"
                                                }`}
                                        ></span>
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-xs uppercase tracking-wide text-slate-400 mb-0.5">
                                            {n.type === "saved-search-match"
                                                ? "Saved search match"
                                                : n.type === "saved-search"
                                                    ? "Saved search"
                                                    : n.type === "interest"
                                                        ? "New Lead"
                                                        : n.type === "deal_reward"
                                                            ? "Deal Reward"
                                                            : "Notification"}
                                        </p>
                                        <button
                                            onClick={() => handleItemClick(n)}
                                            className={`text-left ${n.type !== "deal_reward" ? "cursor-pointer hover:underline" : "cursor-default"}`}
                                        >
                                            <p className="text-sm font-semibold text-slate-900 mb-0.5 truncate">
                                                {n.title}
                                            </p>
                                            <p className="text-xs text-slate-600 line-clamp-2">{n.message}</p>
                                        </button>
                                        <p className="text-[10px] text-slate-400 mt-1">
                                            {new Date(n.createdAt).toLocaleString("en-IN", {
                                                day: "2-digit",
                                                month: "short",
                                                hour: "2-digit",
                                                minute: "2-digit",
                                            })}
                                        </p>

                                        {/* Claim Reward Button for deal_reward notifications */}
                                        {n.type === "deal_reward" && (
                                            <button
                                                onClick={() => handleClaimReward(n)}
                                                disabled={claimingId === n._id || n.data?.isClaimed}
                                                className={`mt-3 inline-flex items-center gap-2 px-4 py-2 ${n.data?.isClaimed ? "bg-gray-100 text-gray-500 shadow-none border border-gray-200" : "bg-green-600 text-white shadow-sm hover:bg-green-700 hover:shadow"
                                                    } text-sm font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed`}
                                            >
                                                {claimingId === n._id ? (
                                                    <>
                                                        <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
                                                        Claiming...
                                                    </>
                                                ) : n.data?.isClaimed ? (
                                                    <>
                                                        <CheckCircle className="w-4 h-4 text-green-500" />
                                                        Claimed
                                                    </>
                                                ) : (
                                                    <>
                                                        <Gift className="w-4 h-4" />
                                                        Claim Your Reward
                                                    </>
                                                )}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Reward Reveal (doors for Shagun, spin wheel for posting/enquiry) */}
            {showDoorGame && rewardData && (
                <RewardRevealRouter
                    reward={rewardData}
                    onClose={handleDoorGameClose}
                />
            )}
        </>
    );
};

export default NotificationsContent;
