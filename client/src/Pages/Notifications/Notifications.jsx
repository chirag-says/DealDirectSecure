import React, { useEffect, useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { FaBell, FaCheckCircle } from "react-icons/fa";
import { toast } from "react-toastify";

const API_BASE = import.meta.env.VITE_API_BASE;

const Notifications = () => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [markingAll, setMarkingAll] = useState(false);
  const navigate = useNavigate();

  const fetchNotifications = async () => {
    const token = localStorage.getItem("token");
    if (!token) {
      toast.info("Login to view your notifications");
      navigate("/login", { state: { from: "/notifications" } });
      return;
    }
    try {
      setLoading(true);
      const res = await axios.get(`${API_BASE}/api/notifications`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.data.success) {
        setNotifications(res.data.notifications || []);
      } else {
        toast.error(res.data.message || "Failed to load notifications");
      }
    } catch (err) {
      console.error("Fetch notifications error", err);
      toast.error(err.response?.data?.message || "Failed to load notifications");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
  }, []);

  const handleMarkAllRead = async () => {
    const token = localStorage.getItem("token");
    if (!token) return;
    try {
      setMarkingAll(true);
      await axios.patch(`${API_BASE}/api/notifications/mark-all/read`, null, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
    } catch (err) {
      console.error("Mark all read error", err);
      toast.error("Failed to mark all as read");
    } finally {
      setMarkingAll(false);
    }
  };

  const handleItemClick = (n) => {
    if (n.type === "saved-search-match" && n.data?.propertyId) {
      navigate(`/properties/${n.data.propertyId}`);
    } else if (n.type === "saved-search" && n.data?.savedSearchId) {
      navigate(`/properties`);
    }
  };

  const unreadCount = notifications.filter((n) => !n.isRead).length;

  return (
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
              <button
                key={n._id}
                onClick={() => handleItemClick(n)}
                className={`w-full text-left px-5 sm:px-6 py-4 flex gap-3 sm:gap-4 items-start hover:bg-slate-50 transition-colors ${
                  n.isRead ? "bg-white" : "bg-red-50/60"
                }`}
              >
                <div className="mt-1">
                  <span
                    className={`inline-block w-2 h-2 rounded-full ${
                      n.isRead ? "bg-slate-300" : "bg-red-500"
                    }`}
                  ></span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs uppercase tracking-wide text-slate-400 mb-0.5">
                    {n.type === "saved-search-match"
                      ? "Saved search match"
                      : n.type === "saved-search"
                      ? "Saved search"
                      : "Notification"}
                  </p>
                  <p className="text-sm font-semibold text-slate-900 mb-0.5 truncate">
                    {n.title}
                  </p>
                  <p className="text-xs text-slate-600 line-clamp-2">{n.message}</p>
                  <p className="text-[10px] text-slate-400 mt-1">
                    {new Date(n.createdAt).toLocaleString("en-IN", {
                      day: "2-digit",
                      month: "short",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </p>
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Notifications;
