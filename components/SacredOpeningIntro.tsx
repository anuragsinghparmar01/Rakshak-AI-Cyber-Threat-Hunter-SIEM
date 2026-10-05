'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ShieldAlert, Sparkles, ArrowRight, Flame } from 'lucide-react';

interface SacredOpeningIntroProps {
  isOpen: boolean;
  onComplete: () => void;
}

const BOOT_STEPS = [
  'Awakening Kaal Bhairav Temporal Log Sentinels (Linux & Windows Collectors)...',
  'Forging Mahakali Trishul Heuristic & UEBA Z-Score Detection Matrix...',
  'Synchronizing MITRE ATT&CK Kill-Chain & Threat Intelligence Cache...',
  'Rakshak Cyber Defense Sanctum Armed — Always Watching, Always Protecting.',
];

export default function SacredOpeningIntro({
  isOpen,
  onComplete,
}: SacredOpeningIntroProps) {
  const [stepIdx, setStepIdx] = useState<number>(0);
  const [progress, setProgress] = useState<number>(12);

  useEffect(() => {
    if (!isOpen) return;
    setStepIdx(0);
    setProgress(15);

    const stepInterval = setInterval(() => {
      setStepIdx((prev) => (prev < BOOT_STEPS.length - 1 ? prev + 1 : prev));
      setProgress((prev) => Math.min(100, prev + 28));
    }, 850);

    return () => clearInterval(stepInterval);
  }, [isOpen]);

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0, scale: 1.03 }}
          transition={{ duration: 0.45 }}
          className="fixed inset-0 z-50 bg-[#05070B] flex flex-col items-center justify-center overflow-hidden select-none p-4 sm:p-8"
        >
          {/* Background Sacred Guardian Artwork with Measured Dark Scrim & CSS Fallback */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,#2A080C_0%,#05070B_75%)]">
            <motion.img
              initial={{ scale: 1.08, opacity: 0 }}
              animate={{ scale: 1, opacity: 0.42 }}
              transition={{ duration: 2.2, ease: 'easeOut' }}
              src="/src/assets/images/kaal_bhairav_mahakali_trishul_1790866392437.jpg"
              alt="Lord Kaal Bhairav and Goddess Mahakali flanking the sacred Trishul"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover object-center"
            />
            {/* Measured Contrast Scrim ensuring >4.5:1 text legibility */}
            <div className="absolute inset-0 bg-gradient-to-t from-[#05070B] via-[#05070B]/75 to-[#05070B]/80" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_42%,transparent_10%,#05070B_85%)]" />
          </div>

          {/* Sacred Geometric Protection Aura & Animated Trishul */}
          <div className="relative z-10 max-w-3xl w-full flex flex-col items-center text-center">
            {/* Invocation Sanskrit Header */}
            <motion.div
              initial={{ opacity: 0, y: -14 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: 0.1 }}
              className="flex items-center gap-3 text-xs sm:text-sm tracking-[0.28em] text-amber-400 font-semibold mb-4"
            >
              <Flame className="w-4 h-4 text-red-500" />
              <span>ॐ कालभैरवाय नमः · जय महाकाली</span>
              <Flame className="w-4 h-4 text-red-500" />
            </motion.div>

            {/* Animated Fierce Trishul & Chakra Centerpiece */}
            <div className="relative w-44 h-44 sm:w-52 sm:h-52 flex items-center justify-center my-2">
              {/* Outer Rotating Sacred Defense Ring */}
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 24, repeat: Infinity, ease: 'linear' }}
                className="absolute inset-0 rounded-full border border-amber-500/30 border-dashed"
              />
              {/* Inner Crimson Pulse Ring */}
              <motion.div
                animate={{ scale: [0.92, 1.08, 0.92], opacity: [0.35, 0.8, 0.35] }}
                transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
                className="absolute inset-4 rounded-full border-2 border-red-500/50 shadow-[0_0_50px_rgba(239,68,68,0.45)]"
              />

              {/* Animated SVG Trishul (Trident of Mahakali & Kaal Bhairav) */}
              <motion.svg
                initial={{ y: -50, scale: 0.75, opacity: 0 }}
                animate={{ y: 0, scale: 1, opacity: 1 }}
                transition={{
                  type: 'spring',
                  stiffness: 140,
                  damping: 14,
                  delay: 0.2,
                }}
                viewBox="0 0 200 240"
                className="w-36 h-40 sm:w-44 sm:h-48 drop-shadow-[0_0_24px_rgba(245,158,11,0.75)]"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <defs>
                  <linearGradient
                    id="trishulBlade"
                    x1="100"
                    y1="8"
                    x2="100"
                    y2="230"
                    gradientUnits="userSpaceOnUse"
                  >
                    <stop offset="0%" stopColor="#FEF08A" />
                    <stop offset="45%" stopColor="#F59E0B" />
                    <stop offset="85%" stopColor="#DC2626" />
                    <stop offset="100%" stopColor="#7F1D1D" />
                  </linearGradient>
                </defs>

                {/* Central Spear Prong of the Trishul */}
                <path
                  d="M100 6 L114 58 L104 72 L104 228 L96 228 L96 72 L86 58 Z"
                  fill="url(#trishulBlade)"
                />

                {/* Left Curved Fierce Blade */}
                <path
                  d="M96 98 C62 98, 42 74, 46 38 C48 24, 58 14, 66 20 C56 36, 60 64, 82 76 C88 80, 94 82, 96 82 Z"
                  fill="url(#trishulBlade)"
                />
                {/* Left Prong Sharp Tip */}
                <path d="M46 38 L38 22 L66 20 Z" fill="#FDE047" />

                {/* Right Curved Fierce Blade */}
                <path
                  d="M104 98 C138 98, 158 74, 154 38 C152 24, 142 14, 134 20 C144 36, 140 64, 118 76 C112 80, 106 82, 104 82 Z"
                  fill="url(#trishulBlade)"
                />
                {/* Right Prong Sharp Tip */}
                <path d="M154 38 L162 22 L134 20 Z" fill="#FDE047" />

                {/* Sacred Damaru / Cross-Guard at the Neck */}
                <polygon
                  points="72,112 100,124 72,136"
                  fill="#EF4444"
                  stroke="#F59E0B"
                  strokeWidth="2"
                />
                <polygon
                  points="128,112 100,124 128,136"
                  fill="#EF4444"
                  stroke="#F59E0B"
                  strokeWidth="2"
                />
                <circle cx="100" cy="124" r="6" fill="#FEF08A" />
              </motion.svg>
            </div>

            {/* Brand Title & Guardian Creed */}
            <motion.h1
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.35 }}
              className="font-display text-4xl sm:text-6xl font-bold tracking-[0.18em] text-transparent bg-clip-text bg-gradient-to-r from-amber-200 via-amber-400 to-red-500 mt-2"
            >
              RAKSHAK
            </motion.h1>

            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.5, delay: 0.5 }}
              className="text-xs sm:text-sm tracking-[0.22em] text-red-400 font-semibold mt-1"
            >
              KAAL BHAIRAV SENTINEL · MAHAKALI TRISHUL THREAT HUNTER
            </motion.p>

            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.6, delay: 0.65 }}
              className="text-xs sm:text-sm text-slate-300 max-w-xl mt-3 leading-relaxed"
            >
              Unrelenting time-series vigilance of{' '}
              <strong className="text-amber-300">Lord Kaal Bhairav</strong>{' '}
              united with the instantaneous threat-annihilating strike of{' '}
              <strong className="text-red-400">Goddess Mahakali&apos;s Trishul</strong>.
            </motion.p>

            {/* Telemetry Awakening Progress Bar */}
            <div className="w-full max-w-md mt-6 bg-[#0B0F19]/90 border border-red-900/50 rounded-md p-4 space-y-2.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-amber-300 truncate pr-2">
                  {BOOT_STEPS[stepIdx]}
                </span>
                <span className="text-red-400 font-semibold tabular-nums">
                  {progress}%
                </span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                <motion.div
                  className="h-full bg-gradient-to-r from-red-600 via-amber-500 to-yellow-300"
                  initial={{ width: '10%' }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 0.4 }}
                />
              </div>
            </div>

            {/* Enter Command Sanctum CTA */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.75 }}
              className="mt-6 flex items-center gap-4"
            >
              <button
                onClick={onComplete}
                className="px-6 py-3 text-xs sm:text-sm font-semibold tracking-wider rounded-md bg-gradient-to-r from-red-600 via-amber-500 to-amber-400 text-slate-950 hover:brightness-110 transition-all shadow-[0_0_30px_rgba(239,68,68,0.4)] flex items-center gap-2.5 cursor-pointer whitespace-nowrap"
              >
                <ShieldAlert className="w-4 h-4" />
                <span>ENTER RAKSHAK COMMAND SANCTUM</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </motion.div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
