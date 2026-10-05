'use client';

import React, { useEffect, useState } from 'react';
import Image from 'next/image';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, Sparkles, ArrowRight } from 'lucide-react';

interface DivineGuardianIntroProps {
  isOpen: boolean;
  onComplete: () => void;
}

export default function DivineGuardianIntro({
  isOpen,
  onComplete,
}: DivineGuardianIntroProps) {
  const [bootPhase, setBootPhase] = useState<number>(0);

  useEffect(() => {
    if (!isOpen) return;

    const t0 = setTimeout(() => setBootPhase(0), 10);
    const t1 = setTimeout(() => setBootPhase(1), 900);
    const t2 = setTimeout(() => setBootPhase(2), 2000);
    const t3 = setTimeout(() => setBootPhase(3), 3100);
    const t4 = setTimeout(() => {
      onComplete();
    }, 4800);

    return () => {
      clearTimeout(t0);
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, [isOpen, onComplete]);

  const bootMessages = [
    'Awakening Kaal Bhairav Temporal Log Correlator...',
    'Forging Mahakali Trishul Threat Detection Matrix...',
    'Arming Explainable Gemini 3.8 Flash Forensic Sanctum...',
    'Rakshak Cyber Defense Grid: ALWAYS WATCHING · ALWAYS PROTECTING',
  ];

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 1 }}
          exit={{ opacity: 0, transition: { duration: 0.6, ease: 'easeInOut' } }}
          className="fixed inset-0 z-50 bg-[#05060A] flex flex-col items-center justify-center overflow-hidden select-none"
        >
          {/* Background Mythic Guardian Artwork with Measured Dark Vignette Scrim */}
          <motion.div
            initial={{ scale: 1.12, opacity: 0 }}
            animate={{ scale: 1, opacity: 0.42 }}
            transition={{ duration: 2.2, ease: 'easeOut' }}
            className="absolute inset-0 pointer-events-none"
          >
            <Image
              src="/src/assets/images/kaal_bhairav_mahakali_guardian_1790869063422.jpg"
              alt="Lord Kaal Bhairav and Goddess Mahakali Cyber Guardian"
              fill
              referrerPolicy="no-referrer"
              className="object-cover object-center"
            />
            <div className="absolute inset-0 bg-gradient-to-t from-[#05060A] via-[#05060A]/75 to-[#05060A]/90" />
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_15%,#05060A_80%)]" />
          </motion.div>

          {/* Sacred Geometric Yantra Protection Rings */}
          <div className="relative flex items-center justify-center w-80 h-80 sm:w-96 sm:h-96">
            {/* Outer Rotating Crimson-Gold Ring */}
            <motion.div
              initial={{ rotate: 0, scale: 0.6, opacity: 0 }}
              animate={{ rotate: 360, scale: 1, opacity: 0.55 }}
              transition={{
                rotate: { duration: 24, repeat: Infinity, ease: 'linear' },
                scale: { duration: 1.2, ease: 'easeOut' },
                opacity: { duration: 1.2 },
              }}
              className="absolute inset-0 rounded-full border border-amber-500/40 shadow-[0_0_80px_rgba(225,29,72,0.35)]"
            />

            {/* Counter-Rotating Mahakali Crimson Octagon Ring */}
            <motion.div
              initial={{ rotate: 45, scale: 0.5, opacity: 0 }}
              animate={{ rotate: -315, scale: 0.84, opacity: 0.65 }}
              transition={{
                rotate: { duration: 18, repeat: Infinity, ease: 'linear' },
                scale: { duration: 1.1, ease: 'easeOut' },
                opacity: { duration: 1.1 },
              }}
              className="absolute inset-0 rounded-full border-2 border-dashed border-rose-600/50"
            />

            {/* Shockwave Pulse on Trishul Strike */}
            <motion.div
              initial={{ scale: 0.2, opacity: 0.9 }}
              animate={{ scale: [0.3, 1.45, 1.8], opacity: [0.9, 0.35, 0] }}
              transition={{ duration: 2.2, repeat: Infinity, ease: 'easeOut' }}
              className="absolute w-64 h-64 rounded-full border border-amber-400/60 pointer-events-none"
            />

            {/* Fierce Animated SVG Trishul (Trident) of Mahakali & Kaal Bhairav */}
            <motion.svg
              viewBox="0 0 240 280"
              className="w-52 h-60 sm:w-64 sm:h-72 relative z-10 drop-shadow-[0_0_32px_rgba(245,158,11,0.75)]"
              initial={{ y: -90, scale: 0.75, opacity: 0 }}
              animate={{ y: 0, scale: 1, opacity: 1 }}
              transition={{
                type: 'spring',
                stiffness: 140,
                damping: 14,
                delay: 0.15,
              }}
            >
              <defs>
                <linearGradient
                  id="trishulGoldCrimson"
                  x1="0%"
                  y1="0%"
                  x2="100%"
                  y2="100%"
                >
                  <stop offset="0%" stopColor="#FEF08A" />
                  <stop offset="45%" stopColor="#F59E0B" />
                  <stop offset="85%" stopColor="#E11D48" />
                  <stop offset="100%" stopColor="#881337" />
                </linearGradient>
                <linearGradient
                  id="bladeEdge"
                  x1="50%"
                  y1="0%"
                  x2="50%"
                  y2="100%"
                >
                  <stop offset="0%" stopColor="#FFFFFF" />
                  <stop offset="35%" stopColor="#FBBF24" />
                  <stop offset="100%" stopColor="#BE123C" />
                </linearGradient>
              </defs>

              {/* Sacred Aura Arc Behind Trishul */}
              <motion.path
                d="M 35 120 A 85 85 0 1 1 205 120"
                fill="none"
                stroke="url(#trishulGoldCrimson)"
                strokeWidth="2.5"
                strokeDasharray="6 4"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 1.4, ease: 'easeInOut' }}
              />

              {/* Central Spear Prong of the Trishul */}
              <motion.path
                d="M 120 12 L 136 74 L 125 96 L 125 265 L 115 265 L 115 96 L 104 74 Z"
                fill="url(#bladeEdge)"
                stroke="#FDE047"
                strokeWidth="1.5"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
              />

              {/* Left Fierce Curved Prong of the Trishul */}
              <motion.path
                d="M 64 36 C 52 78, 62 118, 92 132 C 102 136, 110 138, 115 138 L 115 124 C 102 122, 82 110, 78 82 C 75 64, 82 48, 88 42 Z"
                fill="url(#trishulGoldCrimson)"
                stroke="#F59E0B"
                strokeWidth="1.5"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ duration: 0.9, delay: 0.25 }}
              />

              {/* Right Fierce Curved Prong of the Trishul */}
              <motion.path
                d="M 176 36 C 188 78, 178 118, 148 132 C 138 136, 130 138, 125 138 L 125 124 C 138 122, 158 110, 162 82 C 165 64, 158 48, 152 42 Z"
                fill="url(#trishulGoldCrimson)"
                stroke="#F59E0B"
                strokeWidth="1.5"
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                transition={{ duration: 0.9, delay: 0.25 }}
              />

              {/* Damaru (Hourglass Drum of Kaal Bhairav) bound to the Trishul Shaft */}
              <motion.polygon
                points="94,152 146,182 146,152 94,182"
                fill="#E11D48"
                stroke="#FBBF24"
                strokeWidth="2"
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.5, type: 'spring' }}
              />

              {/* Blazing Trinetra (Third Eye of Mahakali & Kaal Bhairav) at the Nexus */}
              <motion.ellipse
                cx="120"
                cy="108"
                rx="9"
                ry="16"
                fill="#FFF1F2"
                stroke="#E11D48"
                strokeWidth="3"
                animate={{
                  scale: [1, 1.18, 1],
                }}
                transition={{ duration: 1.4, repeat: Infinity }}
              />
              <circle cx="120" cy="108" r="4" fill="#E11D48" />
            </motion.svg>
          </div>

          {/* Guardian Title & Invocation */}
          <motion.div
            initial={{ y: 24, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.45 }}
            className="relative z-10 text-center px-6 max-w-3xl space-y-3 mt-2"
          >
            <div className="flex items-center justify-center gap-3 text-xs sm:text-sm font-mono tracking-[0.25em] text-rose-400 font-semibold">
              <span>उग्रं कालभैरवं</span>
              <span aria-hidden="true" className="text-amber-400">
                ✦
              </span>
              <span>भद्रकाली महाकाली</span>
              <span aria-hidden="true" className="text-amber-400">
                ✦
              </span>
              <span>त्रिशूल रक्षक</span>
            </div>

            <h1 className="font-display text-4xl sm:text-6xl font-bold tracking-[0.18em] text-transparent bg-clip-text bg-gradient-to-r from-amber-200 via-amber-400 to-rose-500 drop-shadow-[0_4px_24px_rgba(225,29,72,0.5)]">
              RAKSHAK
            </h1>

            <p className="text-xs sm:text-sm tracking-[0.22em] text-slate-300 font-medium">
              FIERCE GUARDIAN OF THE DIGITAL REALM · ALWAYS WATCHING · ALWAYS
              PROTECTING
            </p>

            {/* Telemetry Boot Sequence Progress */}
            <div className="pt-4 max-w-md mx-auto space-y-2">
              <div className="h-1.5 w-full bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <motion.div
                  initial={{ width: '8%' }}
                  animate={{ width: '100%' }}
                  transition={{ duration: 4.2, ease: 'easeInOut' }}
                  className="h-full bg-gradient-to-r from-amber-500 via-rose-500 to-amber-300"
                />
              </div>
              <div className="text-xs font-mono text-amber-300/90 h-5 flex items-center justify-center gap-2">
                <Sparkles className="w-3.5 h-3.5 text-rose-400 animate-pulse" />
                <span>{bootMessages[bootPhase]}</span>
              </div>
            </div>

            <div className="pt-4">
              <button
                onClick={onComplete}
                className="px-6 py-2.5 text-xs font-semibold tracking-wider rounded-md bg-gradient-to-r from-amber-500 to-rose-600 text-slate-950 hover:from-amber-400 hover:to-rose-500 transition-all shadow-[0_0_25px_rgba(245,158,11,0.4)] inline-flex items-center gap-2 cursor-pointer"
              >
                <Shield className="w-4 h-4" />
                <span>ENTER RAKSHAK COMMAND SANCTUM</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
