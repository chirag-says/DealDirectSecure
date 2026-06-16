'use client';

import React, { useState, useEffect } from 'react';
import { Home, Castle, Hotel, DoorOpen, X, Sparkles, Gift, Star } from 'lucide-react';

/**
 * PropertyHuntGame — Interactive door-reveal mini-game modal.
 * Shows 3 doors. User taps one to reveal their reward (all doors hide the same reward).
 * 
 * Props:
 *   reward: { pointsAwarded, rewardTier, action, cashValue } — from backend
 *   onClose: () => void — called when user dismisses
 */
export default function PropertyHuntGame({ reward, onClose }) {
    const [selectedDoor, setSelectedDoor] = useState(null);
    const [revealed, setRevealed] = useState(false);
    const [showConfetti, setShowConfetti] = useState(false);

    const doors = [
        { id: 0, icon: Home, label: 'Door A', color: 'from-blue-500 to-blue-600' },
        { id: 1, icon: Castle, label: 'Door B', color: 'from-red-500 to-red-600' },
        { id: 2, icon: Hotel, label: 'Door C', color: 'from-amber-500 to-amber-600' },
    ];

    const tierEmoji = {
        common: { icon: Star, label: 'Common', bg: 'bg-gray-100 text-gray-700', glow: '' },
        uncommon: { icon: Star, label: 'Uncommon', bg: 'bg-green-100 text-green-700', glow: '' },
        rare: { icon: Sparkles, label: 'Rare', bg: 'bg-blue-100 text-blue-700', glow: 'shadow-blue-200' },
        epic: { icon: Gift, label: 'Epic!', bg: 'bg-purple-100 text-purple-700', glow: 'shadow-purple-300' },
        legendary: { icon: Gift, label: 'LEGENDARY!', bg: 'bg-amber-100 text-amber-700', glow: 'shadow-amber-300' },
    };

    const tier = tierEmoji[reward?.rewardTier] || tierEmoji.common;
    const TierIcon = tier.icon;

    const handleDoorClick = (doorId) => {
        if (selectedDoor !== null) return; // Already picked
        setSelectedDoor(doorId);

        // Reveal after a short suspense delay
        setTimeout(() => {
            setRevealed(true);
            // Confetti for rare+ rewards
            if (['rare', 'epic', 'legendary'].includes(reward?.rewardTier)) {
                setShowConfetti(true);
            }
        }, 800);
    };

    // Generate confetti particles
    const confettiParticles = showConfetti ? Array.from({ length: 30 }, (_, i) => ({
        id: i,
        left: Math.random() * 100,
        delay: Math.random() * 0.5,
        duration: 1.5 + Math.random() * 1.5,
        color: ['#FFD700', '#FF6B6B', '#4ECDC4', '#45B7D1', '#96C93D', '#FF8A65'][i % 6],
        size: 6 + Math.random() * 6,
    })) : [];

    if (!reward) return null;

    return (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[9999] flex items-center justify-center p-4">
            {/* Confetti */}
            {showConfetti && confettiParticles.map(p => (
                <div
                    key={p.id}
                    className="absolute top-0 animate-[confettiFall_linear_forwards]"
                    style={{
                        left: `${p.left}%`,
                        width: `${p.size}px`,
                        height: `${p.size}px`,
                        backgroundColor: p.color,
                        borderRadius: Math.random() > 0.5 ? '50%' : '2px',
                        animationDelay: `${p.delay}s`,
                        animationDuration: `${p.duration}s`,
                    }}
                />
            ))}

            <div className="bg-white rounded-3xl shadow-2xl max-w-md w-full overflow-hidden relative animate-[modalIn_0.3s_ease-out]">
                {/* Close button */}
                {revealed && (
                    <button
                        onClick={onClose}
                        className="absolute top-4 right-4 z-10 w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center hover:bg-gray-200 transition-colors"
                    >
                        <X className="w-4 h-4 text-gray-500" />
                    </button>
                )}

                {/* Header */}
                <div className="bg-gradient-to-br from-red-600 via-red-700 to-red-800 px-6 py-8 text-center">
                    <DoorOpen className="w-10 h-10 text-white/80 mx-auto mb-3" />
                    <h2 className="text-2xl font-extrabold text-white">
                        {!revealed ? 'Property Hunt' : 'Reward Revealed!'}
                    </h2>
                    <p className="text-white/70 text-sm mt-1">
                        {!revealed ? 'Pick a door to discover your reward' : 'Here\'s what you won'}
                    </p>
                </div>

                {/* Doors / Reveal */}
                <div className="px-6 py-8">
                    {!revealed ? (
                        <>
                            <div className="grid grid-cols-3 gap-4">
                                {doors.map(door => {
                                    const isSelected = selectedDoor === door.id;
                                    const DoorIcon = door.icon;

                                    return (
                                        <button
                                            key={door.id}
                                            onClick={() => handleDoorClick(door.id)}
                                            disabled={selectedDoor !== null}
                                            className={`
                                                relative flex flex-col items-center justify-center rounded-2xl border-2 py-6 px-3
                                                transition-all duration-500 cursor-pointer
                                                ${selectedDoor === null
                                                    ? 'border-gray-200 hover:border-red-300 hover:shadow-lg hover:scale-105 hover:bg-red-50/50'
                                                    : isSelected
                                                        ? 'border-red-400 bg-red-50 scale-105 shadow-lg animate-pulse'
                                                        : 'border-gray-100 opacity-40 scale-95'
                                                }
                                            `}
                                        >
                                            <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${door.color} flex items-center justify-center mb-3 shadow-md ${isSelected ? 'animate-bounce' : ''}`}>
                                                <DoorIcon className="w-7 h-7 text-white" />
                                            </div>
                                            <span className="text-sm font-bold text-gray-700">{door.label}</span>
                                            {selectedDoor === null && (
                                                <span className="text-[10px] text-gray-400 mt-1">Tap me</span>
                                            )}
                                            {isSelected && (
                                                <span className="text-xs text-red-500 font-medium mt-1">Opening...</span>
                                            )}
                                        </button>
                                    );
                                })}
                            </div>
                            <p className="text-center text-xs text-gray-400 mt-5">
                                Each door hides your reward. Choose wisely!
                            </p>
                        </>
                    ) : (
                        <div className="text-center animate-[revealIn_0.5s_ease-out]">
                            {/* Tier badge */}
                            <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-full ${tier.bg} mb-4`}>
                                <TierIcon className="w-4 h-4" />
                                <span className="text-sm font-bold">{tier.label}</span>
                            </div>

                            {/* Points display */}
                            <div className={`text-6xl font-black text-gray-900 mb-2 ${tier.glow ? `drop-shadow-lg` : ''}`}>
                                +{reward.pointsAwarded?.toLocaleString()}
                            </div>
                            <p className="text-lg text-gray-500 font-medium mb-6">points earned</p>

                            {/* Action label */}
                            <div className="bg-gray-50 rounded-xl px-4 py-3 mb-6">
                                <p className="text-sm text-gray-600">
                                    {reward.description || 'Login Reward'}
                                </p>
                            </div>

                            {/* Continue button */}
                            <button
                                onClick={onClose}
                                className="w-full bg-gradient-to-r from-red-600 to-red-700 text-white py-3.5 rounded-xl font-bold text-base hover:from-red-700 hover:to-red-800 transition-all shadow-lg hover:shadow-xl"
                            >
                                Continue
                            </button>
                        </div>
                    )}
                </div>
            </div>

            <style jsx>{`
                @keyframes confettiFall {
                    0% { transform: translateY(-20px) rotate(0deg); opacity: 1; }
                    100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
                }
                @keyframes modalIn {
                    0% { transform: scale(0.85) translateY(20px); opacity: 0; }
                    100% { transform: scale(1) translateY(0); opacity: 1; }
                }
                @keyframes revealIn {
                    0% { transform: scale(0.8); opacity: 0; }
                    50% { transform: scale(1.05); }
                    100% { transform: scale(1); opacity: 1; }
                }
            `}</style>
        </div>
    );
}
