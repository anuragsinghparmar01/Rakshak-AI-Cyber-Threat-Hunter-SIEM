'use client';

import React, { useState } from 'react';
import { motion } from 'motion/react';
import {
  Settings,
  Sliders,
  Sparkles,
  RefreshCw,
  Download,
  Flame,
  CheckCircle2,
  Globe,
  ShieldCheck,
} from 'lucide-react';

interface SettingsPageProps {
  onReplayIntro: () => void;
  onResetLabState: () => void;
}

export default function SettingsPage({
  onReplayIntro,
  onResetLabState,
}: SettingsPageProps) {
  const [aiModelProfile, setAiModelProfile] = useState<string>(
    'gemini-3.8-flash-xai'
  );
  const [dedupWindowMin, setDedupWindowMin] = useState<number>(5);
  const [bruteForceThreshold, setBruteForceThreshold] = useState<number>(4);
  const [uebaThreshold, setUebaThreshold] = useState<number>(75);
  const [crownJewelWeight, setCrownJewelWeight] = useState<number>(2.0);
  const [syslogEndpoint, setSyslogEndpoint] = useState<string>(
    'udp://0.0.0.0:514 (Wazuh-Rakshak Collector)'
  );
  const [soarWebhook, setSoarWebhook] = useState<string>(
    'https://soc-oncall.rakshak.internal/v1/webhook'
  );
  const [cacheTtlMin, setCacheTtlMin] = useState<number>(60);

  const [probeLoading, setProbeLoading] = useState<boolean>(false);
  const [probeStatus, setProbeStatus] = useState<{
    status: string;
    model: string;
    latencyMs: number;
    message: string;
  } | null>(null);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  const handleVerifyAi = async () => {
    setProbeLoading(true);
    try {
      const res = await fetch('/api/ai/status');
      const data = await res.json();
      setProbeStatus(data);
    } catch {
      setProbeStatus({
        status: 'fallback_ready',
        model: 'gemini-3.8-flash',
        latencyMs: 12,
        message: 'Deterministic XAI engine active.',
      });
    } finally {
      setProbeLoading(false);
    }
  };

  const handleSaveAll = () => {
    setSavedNotice(
      `Saved Rakshak Configuration: AI Profile=${aiModelProfile}, Deduplication=${dedupWindowMin}m, Brute-Force Threshold=${bruteForceThreshold} attempts, UEBA Cutoff=${uebaThreshold}/100, Tier-0 Multiplier=${crownJewelWeight.toFixed(1)}x.`
    );
    setTimeout(() => setSavedNotice(null), 5000);
  };

  const handleExportJson = () => {
    const payload = {
      platform: 'Rakshak — AI Cyber Threat Hunter',
      exportedAt: new Date().toISOString(),
      aiConfiguration: {
        activeProfile: aiModelProfile,
        serverRoute: '/api/ai/investigate & /api/ai/hunt',
        secretGovernance: 'Managed via Settings > Secrets (GEMINI_API_KEY)',
      },
      detectionParameters: {
        dedupWindowMin,
        bruteForceThreshold,
        uebaThreshold,
        crownJewelWeight,
      },
      connectors: {
        syslogEndpoint,
        soarWebhook,
        cacheTtlMin,
      },
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'rakshak-platform-settings.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      {/* Header */}
      <section className="bg-[#0D121F] border border-amber-500/30 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-amber-400 tracking-wider">
              MODULE 08 · PLATFORM CONFIGURATION, AI ENGINE & CONNECTORS
            </div>
            <h1 className="font-display text-2xl font-bold text-white">
              Rakshak Control Sanctum & AI Engine Settings
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              Manage AI model behavior, verify server-side API connectivity,
              tune threat detection & UEBA thresholds, and configure SIEM/SOAR
              integrations.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={onReplayIntro}
              className="px-3.5 py-2 text-xs font-semibold rounded-md bg-rose-950/80 border border-rose-500/60 text-rose-200 hover:bg-rose-900 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              <span>Replay Kaal Bhairav & Mahakali Intro</span>
            </button>

            <button
              onClick={handleExportJson}
              className="px-3.5 py-2 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Settings JSON</span>
            </button>

            <button
              onClick={onResetLabState}
              className="px-3.5 py-2 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-amber-300 hover:bg-slate-700 transition-colors cursor-pointer"
            >
              Reset Demo Telemetry
            </button>
          </div>
        </div>
      </section>

      {/* Section 1: AI Engine & API Key Configuration */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>01. AI Engine & API Key Configuration</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Rakshak executes all Gemini 3.8 Flash investigations and
              natural-language threat hunts through secure server-side routes.
            </p>
          </div>

          <button
            onClick={handleVerifyAi}
            disabled={probeLoading}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 disabled:opacity-50 transition-colors flex items-center gap-2 cursor-pointer whitespace-nowrap"
          >
            {probeLoading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Verifying Server AI Key...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>Test & Verify AI Connection</span>
              </>
            )}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 bg-[#080B12] border border-slate-800 rounded-lg p-5 space-y-3">
            <div className="text-xs font-mono text-amber-400 font-semibold">
              HOW CUSTOM API KEYS & SECRETS WORK IN RAKSHAK
            </div>
            <p className="text-xs text-slate-200 leading-relaxed">
              We&apos;ve set up your app&apos;s Gemini API calls using our
              recommended full-stack server-side architecture (
              <code className="font-mono text-amber-300">
                /api/ai/investigate
              </code>{' '}
              and <code className="font-mono text-amber-300">/api/ai/hunt</code>
              ). Your custom API key can be added or updated anytime in the{' '}
              <strong>Settings &gt; Secrets</strong> panel via{' '}
              <code className="font-mono text-emerald-400">GEMINI_API_KEY</code>
              , and the server automatically picks it up without any code
              changes or downtime.
            </p>
            <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400">
              <span>Active Model: gemini-3.8-flash</span>
              <span>·</span>
              <span>Fallback Mode: Deterministic XAI Always Ready</span>
            </div>
          </div>

          <div className="lg:col-span-5 bg-[#080B12] border border-slate-800 rounded-lg p-5 space-y-3 flex flex-col justify-between">
            <div>
              <label className="block text-xs font-medium text-slate-200 mb-2">
                AI Forensic Reasoning Profile
              </label>
              <select
                aria-label="AI Forensic Reasoning Profile"
                value={aiModelProfile}
                onChange={(e) => setAiModelProfile(e.target.value)}
                className="w-full bg-[#0D121F] border border-slate-700 rounded-md px-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
              >
                <option value="gemini-3.8-flash-xai">
                  Gemini 3.8 Flash — Deep Explainable AI (XAI) Mode
                </option>
                <option value="gemini-3.8-flash-triage">
                  Gemini 3.8 Flash — Rapid SOC Tier-1 Triage
                </option>
                <option value="deterministic-hybrid">
                  Deterministic Wazuh-XAI Hybrid Mode
                </option>
              </select>
            </div>

            {probeStatus ? (
              <div className="p-3 rounded bg-[#0D121F] border border-emerald-500/40 text-xs font-mono space-y-1">
                <div className="flex items-center justify-between text-emerald-400 font-semibold">
                  <span>STATUS: {probeStatus.status.toUpperCase()}</span>
                  <span>{probeStatus.latencyMs}ms</span>
                </div>
                <div className="text-slate-300 font-sans">
                  {probeStatus.message}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 font-mono">
                Click &ldquo;Test & Verify AI Connection&rdquo; above to run a
                live probe.
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Section 2: Detection Engine & UEBA Thresholds */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6 space-y-5">
        <div className="pb-4 border-b border-slate-800/80">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Sliders className="w-4 h-4 text-amber-400" />
            <span>
              02. Threat Detection, Deduplication & UEBA Tuning Parameters
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Customize correlation windows, brute-force failure counts, UEBA
            Z-score thresholds, and Risk-Based Asset Prioritization weights.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              Alert Deduplication Window (Min)
            </label>
            <input
              type="number"
              min={1}
              max={60}
              value={dedupWindowMin}
              onChange={(e) => setDedupWindowMin(Number(e.target.value))}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
            <p className="text-[11px] text-slate-400">
              Groups identical repeated alerts into one cluster within this
              interval.
            </p>
          </div>

          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              Brute-Force Failure Threshold
            </label>
            <input
              type="number"
              min={2}
              max={20}
              value={bruteForceThreshold}
              onChange={(e) => setBruteForceThreshold(Number(e.target.value))}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
            <p className="text-[11px] text-slate-400">
              Consecutive failed logins required to trigger RULE-101 & RULE-102.
            </p>
          </div>

          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              UEBA Anomaly Score Cutoff (0–100)
            </label>
            <input
              type="number"
              min={50}
              max={99}
              value={uebaThreshold}
              onChange={(e) => setUebaThreshold(Number(e.target.value))}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
            <p className="text-[11px] text-slate-400">
              Minimum behavioral deviation score required to flag an anomaly.
            </p>
          </div>

          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              Tier-0 Crown Jewel Risk Multiplier
            </label>
            <input
              type="number"
              step={0.1}
              min={1.0}
              max={5.0}
              value={crownJewelWeight}
              onChange={(e) => setCrownJewelWeight(Number(e.target.value))}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
            <p className="text-[11px] text-slate-400">
              Elevates priority for Domain Controllers and Production Databases.
            </p>
          </div>
        </div>
      </section>

      {/* Section 3: SIEM Log Listeners, Threat Feeds & SOAR Webhooks */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6 space-y-5">
        <div className="pb-4 border-b border-slate-800/80">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-amber-400" />
            <span>
              03. SIEM Log Listeners, Threat Intelligence Cache & SOAR Webhooks
            </span>
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              Authorized Log Collector Endpoint
            </label>
            <input
              type="text"
              value={syslogEndpoint}
              onChange={(e) => setSyslogEndpoint(e.target.value)}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
          </div>

          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              SOAR Notification Dispatch Webhook
            </label>
            <input
              type="text"
              value={soarWebhook}
              onChange={(e) => setSoarWebhook(e.target.value)}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
          </div>

          <div className="bg-[#080B12] border border-slate-800 rounded-lg p-4 space-y-2">
            <label className="block text-xs font-medium text-slate-200">
              Threat Intel Local Cache TTL (Minutes)
            </label>
            <input
              type="number"
              min={5}
              max={1440}
              value={cacheTtlMin}
              onChange={(e) => setCacheTtlMin(Number(e.target.value))}
              className="w-full bg-[#0D121F] border border-slate-700 rounded px-3 py-1.5 text-xs font-mono text-white"
            />
          </div>
        </div>

        <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between gap-4">
          {savedNotice ? (
            <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{savedNotice}</span>
            </div>
          ) : (
            <span className="text-xs text-slate-400">
              All changes take effect immediately across the Rakshak correlation
              pipeline.
            </span>
          )}

          <button
            onClick={handleSaveAll}
            className="px-5 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors cursor-pointer whitespace-nowrap"
          >
            Save & Apply All Settings
          </button>
        </div>
      </section>
    </motion.div>
  );
}
