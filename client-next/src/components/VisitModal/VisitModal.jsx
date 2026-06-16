'use client';

import React, { useState } from 'react';
import { XMarkIcon, CalendarDaysIcon, ClockIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-toastify';

// Optional onConfirm allows callers (like chat) to hook into the
// selected date/time instead of using the built-in mock API.
const VisitModal = ({ isOpen, onClose, propertyTitle, onConfirm }) => {
    const [selectedDate, setSelectedDate] = useState('');
    const [selectedTime, setSelectedTime] = useState('');
    const [loading, setLoading] = useState(false);

    if (!isOpen) return null;

    const timeSlots = [
        "10:00 AM", "11:00 AM", "12:00 PM",
        "02:00 PM", "04:00 PM", "06:00 PM"
    ];

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!selectedDate || !selectedTime) {
            toast.error("Please select both date and time.");
            return;
        }

        setLoading(true);

        if (onConfirm) {
            Promise.resolve(
                onConfirm({ date: selectedDate, time: selectedTime })
            )
                .then(() => {
                    toast.success("Visit scheduled successfully!");
                    onClose();
                })
                .catch(() => {
                    toast.error("Failed to schedule visit. Please try again.");
                })
                .finally(() => setLoading(false));
            return;
        }

        // Fallback: simulate API call when no onConfirm handler is provided
        setTimeout(() => {
            setLoading(false);
            toast.success("Visit scheduled successfully! Check your email for details.");
            onClose();
        }, 1500);
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fadeIn">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden transform transition-all animate-scaleIn">

                {/* Header */}
                <div className="bg-gradient-to-r from-blue-600 to-blue-700 p-6 text-white flex justify-between items-start">
                    <div>
                        <h2 className="text-xl font-bold flex items-center gap-2">
                            <CalendarDaysIcon className="w-6 h-6" /> Schedule a Visit
                        </h2>
                        <p className="text-blue-100 text-sm mt-1 opacity-90 line-clamp-1">
                            {propertyTitle}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="text-white/80 hover:text-white hover:bg-white/20 rounded-full p-1 transition"
                    >
                        <XMarkIcon className="w-6 h-6" />
                    </button>
                </div>

                {/* Body */}
                <div className="p-6">
                    <form onSubmit={handleSubmit} className="space-y-6">

                        {/* Date Selection */}
                        <div>
                            <label className="block text-sm font-semibold text-gray-700 mb-2">Select Date</label>
                            <input
                                type="date"
                                min={new Date().toISOString().split('T')[0]}
                                value={selectedDate}
                                onChange={(e) => setSelectedDate(e.target.value)}
                                className="w-full border-gray-300 rounded-xl shadow-sm focus:ring-blue-500 focus:border-blue-500 p-3 border"
                                required
                            />
                        </div>

                        {/* Time Selection */}
                        <div>
                            <label className="block text-sm font-semibold text-gray-700 mb-2">Select Time Slot</label>
                            <div className="grid grid-cols-3 gap-3">
                                {timeSlots.map((slot) => (
                                    <button
                                        key={slot}
                                        type="button"
                                        onClick={() => setSelectedTime(slot)}
                                        className={`py-2 px-3 rounded-lg text-sm font-medium transition-all border ${selectedTime === slot
                                                ? "bg-blue-600 text-white border-blue-600 shadow-md scale-105"
                                                : "bg-white text-gray-600 border-gray-200 hover:border-blue-400 hover:bg-blue-50"
                                            }`}
                                    >
                                        {slot}
                                    </button>
                                ))}
                            </div>
                        </div>

                        {/* Submit Button */}
                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl shadow-lg transition-all transform active:scale-95 flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
                        >
                            {loading ? (
                                <span className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            ) : (
                                <>
                                    <ClockIcon className="w-5 h-5" /> Confirm Visit
                                </>
                            )}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
};

export default VisitModal;
