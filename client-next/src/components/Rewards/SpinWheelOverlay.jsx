'use client';

import React, { useState, useMemo, useEffect, useCallback } from 'react';

const WHEEL_SEGMENTS = {
  property_posting: [
    { points: 40, label: '40', color: '#2563EB' },
    { points: 100, label: '100', color: '#7C3AED' },
    { points: 200, label: '200', color: '#0891B2' },
    { points: 1000, label: '1K', color: '#7C3AED' },
    { points: 5000, label: '5K', color: '#2563EB' },
    { points: 10000, label: '10K', color: '#7C3AED' },
    { points: 40000, label: '40K', color: '#0891B2' },
    { points: 100000, label: '100K', color: '#7C3AED' },
  ],
  property_enquiry: [
    { points: 20, label: '20', color: '#2563EB' },
    { points: 40, label: '40', color: '#7C3AED' },
    { points: 100, label: '100', color: '#0891B2' },
    { points: 400, label: '400', color: '#7C3AED' },
    { points: 1000, label: '1K', color: '#2563EB' },
    { points: 1600, label: '1.6K', color: '#7C3AED' },
    { points: 2000, label: '2K', color: '#0891B2' },
  ],
};

const TIERS = {
  common: { label: 'Common', color: '#94A3B8' },
  uncommon: { label: 'Uncommon', color: '#34D399' },
  rare: { label: 'Rare', color: '#A78BFA', explosive: true },
  epic: { label: 'Epic', color: '#FB923C', explosive: true },
  legendary: { label: 'Legendary', color: '#FBBF24', explosive: true },
};

function findTarget(segs, pts) {
  const i = segs.findIndex(s => s.points === pts);
  if (i !== -1) return i;
  let b = 0, d = Infinity;
  segs.forEach((s, j) => { const x = Math.abs(s.points - pts); if (x < d) { d = x; b = j; } });
  return b;
}

function arc(cx, cy, r, s, e) {
  const rad = d => ((d - 90) * Math.PI) / 180;
  return `M${cx},${cy} L${cx + r * Math.cos(rad(s))},${cy + r * Math.sin(rad(s))} A${r},${r} 0 ${e - s > 180 ? 1 : 0} 1 ${cx + r * Math.cos(rad(e))},${cy + r * Math.sin(rad(e))} Z`;
}

const W = 340, C = W / 2, R = C - 16, HUB = 40;

export default function SpinWheelOverlay({ reward, onClose, category }) {
  const [phase, setPhase] = useState('idle');
  const [cd, setCd] = useState(null);
  const [rot, setRot] = useState(0);
  const [flash, setFlash] = useState(false);
  const [show, setShow] = useState(false);

  useEffect(() => { requestAnimationFrame(() => setShow(true)); }, []);

  const segs = useMemo(() => WHEEL_SEGMENTS[category] || WHEEL_SEGMENTS.property_posting, [category]);
  const span = 360 / segs.length;
  const tidx = useMemo(() => findTarget(segs, reward?.pointsAwarded || 0), [segs, reward]);
  const tier = TIERS[reward?.rewardTier] || TIERS.common;

  const spin = useCallback(() => {
    if (phase !== 'idle') return;
    setPhase('cd'); setCd(3);
    setTimeout(() => setCd(2), 600);
    setTimeout(() => setCd(1), 1200);
    setTimeout(() => {
      setCd(null); setPhase('spin');
      setRot((6 + Math.floor(Math.random() * 2)) * 360 + (360 - (tidx * span + span / 2)));
      setTimeout(() => {
        if (tier.explosive) { setFlash(true); setTimeout(() => setFlash(false), 500); }
        setTimeout(() => setPhase('done'), tier.explosive ? 400 : 150);
      }, 4800);
    }, 1800);
  }, [phase, tidx, span, tier]);

  const dots = useMemo(() => Array.from({ length: 24 }, (_, i) => {
    const a = ((i * 15 - 90) * Math.PI) / 180, d = R + 10;
    return { x: C + d * Math.cos(a), y: C + d * Math.sin(a) };
  }), []);

  if (!reward) return null;

  const spinning = phase === 'spin';
  const done = phase === 'done';
  const counting = phase === 'cd';

  return (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(12px)' }}>
      {flash && <div className="fixed inset-0 z-[10001] pointer-events-none" style={{ backgroundColor: 'rgba(251,191,36,0.15)', animation: 'swFlash .5s ease-out forwards' }} />}

      {/* Gold confetti for rare+ */}
      {done && tier.explosive && Array.from({ length: 40 }).map((_, i) => (
        <div key={i} className="absolute top-0 pointer-events-none z-[10000] rounded-full" style={{
          left: `${Math.random() * 100}%`, width: 4 + Math.random() * 5, height: 4 + Math.random() * 5,
          backgroundColor: ['#D4AF37', '#FBBF24', '#F59E0B', '#FDE68A'][i % 4],
          animation: `swFall ${2 + Math.random() * 2}s ${Math.random() * .5}s ease-out forwards`,
          '--sw': `${(Math.random() - .5) * 180}px`,
        }} />
      ))}

      <div className={`w-full max-w-md relative transition-all duration-500 ${show ? 'opacity-100 scale-100' : 'opacity-0 scale-95'} ${flash ? 'animate-[swShake_.3s_ease-in-out]' : ''}`}
        style={{ backgroundColor: '#111', borderRadius: '24px', boxShadow: '0 32px 80px rgba(0,0,0,.6)' }}>

        {done && <button onClick={onClose} className="absolute top-4 right-4 z-10 w-8 h-8 rounded-full flex items-center justify-center text-white/40 hover:text-white/70 hover:bg-white/5 transition-colors text-lg font-light">×</button>}

        {/* Header */}
        <div className="pt-8 pb-2 text-center px-6">
          <p className="text-[10px] font-semibold tracking-[.25em] uppercase text-white/25 mb-2">{done ? 'Result' : 'Reward'}</p>
          <h2 className="text-2xl font-bold text-white">{done ? 'You won' : 'Spin the wheel'}</h2>
        </div>

        <div className="px-6 pb-8 pt-4">
          {!done ? (
            <div className="flex flex-col items-center">
              {/* Wheel */}
              <div className="relative" style={{ width: W, height: W }}>
                {/* Glow */}
                <div className="absolute inset-[-30px] rounded-full pointer-events-none" style={{ backgroundColor: 'rgba(124,58,237,.08)', filter: 'blur(40px)', animation: !spinning ? 'swPulse 3s ease-in-out infinite' : 'none' }} />

                {/* Pointer */}
                <div className="absolute top-[-6px] left-1/2 -translate-x-1/2 z-20" style={{ animation: spinning ? 'swTick .1s linear infinite' : 'none' }}>
                  <svg width="32" height="30" viewBox="0 0 32 30"><polygon points="16,30 0,0 32,0" fill="#fff"/></svg>
                </div>

                <svg width={W} height={W} className="cursor-pointer" onClick={spin}
                  style={{ transform: `rotate(${rot}deg)`, transition: spinning ? 'transform 4.8s cubic-bezier(.08,.6,.08,1)' : 'none' }}>

                  {/* Ring */}
                  <circle cx={C} cy={C} r={R + 14} fill="none" stroke="#333" strokeWidth="6"/>
                  <circle cx={C} cy={C} r={R + 3} fill="none" stroke="#222" strokeWidth="1"/>

                  {/* Dots on ring */}
                  {dots.map((d, i) => <circle key={i} cx={d.x} cy={d.y} r="2.5" fill="#555"/>)}

                  {/* Segments */}
                  {segs.map((s, i) => {
                    const a0 = i * span, a1 = a0 + span, mid = a0 + span / 2;
                    const tr = R * .63, rd = ((mid - 90) * Math.PI) / 180;
                    return (
                      <g key={i}>
                        <path d={arc(C, C, R, a0, a1)} fill={s.color} stroke="#111" strokeWidth="1.5"/>
                        <text x={C + tr * Math.cos(rd)} y={C + tr * Math.sin(rd)}
                          textAnchor="middle" dominantBaseline="middle" fill="#fff" fontWeight="700"
                          fontSize={s.label.length > 3 ? 11 : 14} opacity=".9"
                          transform={`rotate(${mid},${C + tr * Math.cos(rd)},${C + tr * Math.sin(rd)})`}>
                          {s.label}
                        </text>
                      </g>
                    );
                  })}

                  {/* Center */}
                  <circle cx={C} cy={C} r={HUB + 4} fill="#333"/>
                  <circle cx={C} cy={C} r={HUB} fill="#111"/>
                  <text x={C} y={C + 1} textAnchor="middle" dominantBaseline="middle"
                    fill="#fff" fontWeight="800" fontSize={counting ? 20 : 13} letterSpacing=".5">
                    {counting ? cd : spinning ? '•••' : 'SPIN'}
                  </text>
                </svg>
              </div>

              {/* Prompt */}
              <p className={`mt-5 text-xs font-medium tracking-wide ${spinning || counting ? 'text-white/40' : 'text-white/20'}`}>
                {counting ? 'Get ready' : spinning ? 'Spinning' : 'Tap the wheel to spin'}
              </p>
            </div>
          ) : (
            /* Reveal */
            <div className="text-center py-6">
              {/* Tier */}
              <div className="inline-block px-4 py-1.5 rounded-full text-xs font-bold tracking-widest uppercase mb-8 border" style={{ color: tier.color, borderColor: `${tier.color}33`, backgroundColor: `${tier.color}0D`, animation: 'swPop .5s cubic-bezier(.34,1.56,.64,1)' }}>
                {tier.label}
              </div>

              {/* Points */}
              <div style={{ animation: 'swPop .6s cubic-bezier(.34,1.56,.64,1) .1s both' }}>
                <div className="text-7xl font-black text-white leading-none tracking-tight">
                  {reward.pointsAwarded?.toLocaleString()}
                </div>
                <p className="text-[11px] font-semibold tracking-[.3em] uppercase text-white/20 mt-3">Points</p>
              </div>

              {/* Desc */}
              {reward.description && (
                <p className="text-sm text-white/30 mt-6 mb-8 px-4" style={{ animation: 'swUp .4s ease-out .3s both' }}>
                  {reward.description}
                </p>
              )}

              {/* CTA */}
              <button onClick={onClose}
                className="w-full py-4 rounded-xl font-semibold text-sm text-black bg-white hover:bg-white/90 active:scale-[.98] transition-all mt-4"
                style={{ animation: 'swUp .4s ease-out .4s both' }}>
                Claim reward
              </button>
            </div>
          )}
        </div>
      </div>

      <style jsx>{`
        @keyframes swFall { 0% { transform: translateY(-10px) translateX(0) rotate(0); opacity:1 } 100% { transform: translateY(100vh) translateX(var(--sw,0)) rotate(540deg); opacity:0 } }
        @keyframes swPulse { 0%,100% { opacity:.5; transform:scale(1) } 50% { opacity:1; transform:scale(1.02) } }
        @keyframes swTick { 0%,100% { transform:translateX(-50%) translateY(0) } 50% { transform:translateX(-50%) translateY(2px) } }
        @keyframes swPop { 0% { transform:scale(0); opacity:0 } 70% { transform:scale(1.08) } 100% { transform:scale(1); opacity:1 } }
        @keyframes swUp { 0% { transform:translateY(12px); opacity:0 } 100% { transform:translateY(0); opacity:1 } }
        @keyframes swFlash { 0% { opacity:1 } 100% { opacity:0 } }
        @keyframes swShake { 0%,100% { transform:translate(0,0) } 20% { transform:translate(-3px,2px) } 40% { transform:translate(3px,-2px) } 60% { transform:translate(-2px,1px) } 80% { transform:translate(1px,-1px) } }
      `}</style>
    </div>
  );
}
