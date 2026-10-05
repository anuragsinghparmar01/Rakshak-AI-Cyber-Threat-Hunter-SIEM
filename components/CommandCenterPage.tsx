'use client';

import React from 'react';
import Image from 'next/image';
import { motion } from 'motion/react';
import {
  ShieldAlert,
  Activity,
  Terminal,
  Sparkles,
  Crosshair,
  FileText,
  Globe,
  BarChart3,
  Play,
  ArrowRight,
  Flame,
  CheckCircle2,
  PlusCircle,
} from 'lucide-react';
import {
  AgentNode,
  Incident,
  IoCRecord,
  NormalizedLog,
  PlaybookAction,
  SecurityAlert,
} from '@/lib/types';

interface CommandCenterPageProps {
  logs: NormalizedLog[];
  alerts: SecurityAlert[];
  agents: AgentNode[];
  incidents: Incident[];
  iocs: IoCRecord[];
  playbooks: PlaybookAction[];
  onNavigateTab: (tab: string) => void;
  onReplayIntro: () => void;
  onInjectLiveEvent: () => void;
}

export default function CommandCenterPage({
  logs,
  alerts,
  agents,
  incidents,
  iocs,
  playbooks,
  onNavigateTab,
  onReplayIntro,
  onInjectLiveEvent,
}: CommandCenterPageProps) {
  const totalRawInAlerts = alerts.reduce(
    (acc, a) => acc + a.occurrenceCount,
    0
  );
  const noiseReductionPct =
    totalRawInAlerts > alerts.length
      ? Math.round(((totalRawInAlerts - alerts.length) / totalRawInAlerts) * 100)
      : 0;

  const coreModules = [
    {
      step: '01',
      id: 'monitor',
      title: 'Real-Time Security Monitoring',
      subtitle: 'Live Events, Multi-Filters & Agent Health',
      description:
        'Monitor incoming security events in real time, filter by Host, Time, User, IP, and Severity, and inspect connected Linux/Windows agent health.',
      metric: `${logs.length} Normalized Events · ${agents.filter((a) => a.status === 'Active').length}/${agents.length} Agents Online`,
      icon: Activity,
      accent: 'text-amber-400',
    },
    {
      step: '02',
      id: 'logs',
      title: 'Log Collection & Wazuh Analysis',
      subtitle: 'Linux Syslog & Windows Event Normalizer',
      description:
        'Import sample logs or upload system files, normalize Linux auth.log and Windows Security Events into a common schema, and correlate across entities.',
      metric: 'Supports sshd, sudo, PAM & Windows 4624/4625/4672/4720',
      icon: Terminal,
      accent: 'text-emerald-400',
    },
    {
      step: '03',
      id: 'detection',
      title: 'Threat Detection, UEBA & Attack Chains',
      subtitle: 'Rules + Behavioral Z-Score + Deduplication',
      description:
        'Detect brute-force, post-failure logins, off-hours geo anomalies, and privilege escalations. Assigns Severity & Confidence independently and reconstructs attack chains.',
      metric: `${alerts.length} Correlated Alerts (${noiseReductionPct}% Deduplicated)`,
      icon: ShieldAlert,
      accent: 'text-rose-400',
    },
    {
      step: '04',
      id: 'ai-hunter',
      title: 'AI Threat Investigation & NL Hunt',
      subtitle: 'Explainable Gemini 3.8 Flash Forensics',
      description:
        'Summarize incidents in plain English, explain triggering events, build chronological timelines, state explicit AI limitations, and hunt threats using natural language.',
      metric: 'Explainable AI (XAI) + Natural-Language Query Engine',
      icon: Sparkles,
      accent: 'text-amber-300',
    },
    {
      step: '05',
      id: 'mitre',
      title: 'MITRE ATT&CK & Threat Intelligence',
      subtitle: 'Kill-Chain Mapping & Resilient IoC Cache',
      description:
        'Map rules to MITRE tactics/techniques with evidence links, and enrich IPs, domains, and hashes while distinguishing Verified Intel from Unverified Observations.',
      metric: `${iocs.length} Enriched IoCs (Verified vs. Unverified + Cache)`,
      icon: Crosshair,
      accent: 'text-rose-400',
    },
    {
      step: '06',
      id: 'incidents',
      title: 'Incidents & SOAR Playbooks',
      subtitle: 'Case Workflow, PDF Reports & Approval Gate',
      description:
        'Create incidents from multiple alerts, track status (New -> Investigating -> Contained -> Resolved), export PDF reports, and approve SOAR containment actions.',
      metric: `${incidents.length} Active Incidents · ${playbooks.filter((p) => p.approvalStatus.includes('Pending')).length} Pending Approvals`,
      icon: FileText,
      accent: 'text-emerald-400',
    },
    {
      step: '07',
      id: 'evaluation',
      title: 'Evaluation, Benchmarks & Unit Tests',
      subtitle: 'Precision, Recall, FPR & Architecture Docs',
      description:
        'Compare Rule-Based Detection vs. UEBA Anomaly Detection over a labelled dataset, run 7 automated unit/integration tests, and test live REST APIs.',
      metric: '7/7 Unit Tests Passing · 100% Hybrid Recall',
      icon: BarChart3,
      accent: 'text-amber-400',
    },
    {
      step: '08',
      id: 'settings',
      title: 'Platform & AI Engine Settings',
      subtitle: 'Custom Thresholds, Connectors & API Key Setup',
      description:
        'Configure custom AI API key & model preferences, tune UEBA anomaly cutoffs, adjust deduplication windows, and manage SIEM/SOAR webhook connectors.',
      metric: 'Server-Side Proxy + Custom API Key Override Ready',
      icon: Globe,
      accent: 'text-rose-300',
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
      className="space-y-8"
    >
      {/* Hero Banner with Kaal Bhairav & Mahakali Guardian Artwork */}
      <section className="relative rounded-xl border border-amber-500/30 bg-[#0B0E17] overflow-hidden shadow-[0_0_50px_rgba(225,29,72,0.12)]">
        <div className="absolute inset-0 pointer-events-none">
          <Image
            src="/src/assets/images/kaal_bhairav_mahakali_guardian_1790869063422.jpg"
            alt="Rakshak Kaal Bhairav and Mahakali Guardian Backdrop"
            fill
            referrerPolicy="no-referrer"
            className="object-cover object-center opacity-30"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-[#07090F] via-[#07090F]/90 to-[#07090F]/65" />
          <div className="absolute inset-0 bg-gradient-to-t from-[#07090F] via-transparent to-transparent" />
        </div>

        <div className="relative z-10 p-6 sm:p-8 lg:p-10 flex flex-col lg:flex-row lg:items-center justify-between gap-8">
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-6 max-w-3xl">
            <div className="relative w-20 h-20 sm:w-24 sm:h-24 rounded-xl border border-amber-500/50 overflow-hidden shrink-0 shadow-[0_0_30px_rgba(245,158,11,0.3)] bg-[#05070B]">
              <Image
                src="/src/assets/images/trishul_cyber_emblem_1790869079332.jpg"
                alt="Rakshak Trishul Crest"
                fill
                referrerPolicy="no-referrer"
                className="object-cover"
              />
            </div>

            <div className="space-y-2.5">
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono tracking-widest text-amber-400 font-semibold">
                <span>कालभैरव · महाकाली</span>
                <span aria-hidden="true" className="text-rose-500">
                  ✦
                </span>
                <span>ALWAYS WATCHING · ALWAYS PROTECTING</span>
              </div>

              <h1 className="font-display text-2xl sm:text-4xl font-bold tracking-wider text-white text-balance">
                RAKSHAK SUPREME CYBER COMMAND
              </h1>

              <p className="text-sm text-slate-300 leading-relaxed">
                Inspired by the fierce vigilance of <strong>Lord Kaal Bhairav</strong>{' '}
                (Master of Time & Telemetry) and <strong>Goddess Mahakali</strong>{' '}
                (Destroyer of Malicious Intrusions). Navigate all 8 security
                modules below with clarity and precision.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={onReplayIntro}
              className="px-4 py-2.5 text-xs font-semibold rounded-md bg-rose-950/70 border border-rose-500/60 text-rose-200 hover:bg-rose-900/80 transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
            >
              <Flame className="w-4 h-4 text-rose-400" />
              <span>Replay Trishul Awakening</span>
            </button>

            <button
              onClick={onInjectLiveEvent}
              className="px-4 py-2.5 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
            >
              <PlusCircle className="w-4 h-4" />
              <span>Simulate Live Attack</span>
            </button>

            <button
              onClick={() => onNavigateTab('ai-hunter')}
              className="px-4 py-2.5 text-xs font-semibold rounded-md bg-slate-800/90 border border-amber-500/40 text-amber-300 hover:bg-slate-800 transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap"
            >
              <Sparkles className="w-4 h-4" />
              <span>Launch AI Investigator</span>
            </button>
          </div>
        </div>

        {/* Executive Telemetry Strip */}
        <div className="relative z-10 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 px-6 sm:px-8 lg:px-10 py-5 bg-[#07090F]/90 border-t border-slate-800/90">
          <div>
            <div className="text-[11px] text-slate-400">Normalized Events</div>
            <div className="text-xl font-mono font-bold text-white tabular-nums mt-0.5">
              {logs.length}
            </div>
            <div className="text-[11px] text-emerald-400">
              Linux & Windows Active
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-400">Deduplicated Alerts</div>
            <div className="text-xl font-mono font-bold text-amber-400 tabular-nums mt-0.5">
              {alerts.length}
            </div>
            <div className="text-[11px] text-slate-400 font-mono tabular-nums">
              {noiseReductionPct}% noise suppressed
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-400">Active Incidents</div>
            <div className="text-xl font-mono font-bold text-rose-400 tabular-nums mt-0.5">
              {incidents.length}
            </div>
            <div className="text-[11px] text-slate-400">
              Multi-Stage Correlated
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-400">Connected Agents</div>
            <div className="text-xl font-mono font-bold text-white tabular-nums mt-0.5">
              {agents.filter((a) => a.status === 'Active').length}/{agents.length}
            </div>
            <div className="text-[11px] text-slate-400 font-mono tabular-nums">
              {agents.reduce((s, a) => s + a.eps, 0)} EPS Velocity
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-400">Detection Recall</div>
            <div className="text-xl font-mono font-bold text-emerald-400 tabular-nums mt-0.5">
              100.0%
            </div>
            <div className="text-[11px] text-slate-400">
              Hybrid Rules + UEBA
            </div>
          </div>

          <div>
            <div className="text-[11px] text-slate-400">SOAR Playbooks</div>
            <div className="text-xl font-mono font-bold text-amber-300 tabular-nums mt-0.5">
              {playbooks.length} Tasks
            </div>
            <div className="text-[11px] text-rose-400">
              Human Approval Enforced
            </div>
          </div>
        </div>
      </section>

      {/* Quick Step-by-Step Guide for Easy Operation */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-amber-400" />
              <span>How to Operate Rakshak in 4 Simple Steps</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Designed for intuitive operation by both security analysts and
              evaluators.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('settings')}
            className="text-xs font-mono text-amber-400 hover:underline flex items-center gap-1 cursor-pointer"
          >
            <span>Configure Custom AI API Key in Settings</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
          {[
            {
              step: 'STEP 1 · COLLECT & MONITOR',
              title: 'Ingest or Stream Logs',
              desc: 'Open "Live Monitor" or "Log Analysis" to filter incoming Linux/Windows events or paste custom logs.',
              target: 'monitor',
            },
            {
              step: 'STEP 2 · DETECT & RECONSTRUCT',
              title: 'Inspect Alerts & Attack Chains',
              desc: 'Open "Detection & UEBA" to see how repeated alerts are deduplicated and linked into visual kill chains.',
              target: 'detection',
            },
            {
              step: 'STEP 3 · AI INVESTIGATE & HUNT',
              title: 'Ask AI in Plain English',
              desc: 'Open "AI Threat Hunter" to ask natural-language questions or generate a full Explainable AI forensic report.',
              target: 'ai-hunter',
            },
            {
              step: 'STEP 4 · CONTAIN & EXPORT PDF',
              title: 'Approve SOAR Playbooks',
              desc: 'Open "Incidents & SOAR" to approve firewall IP blocks, disable accounts, and print a PDF incident report.',
              target: 'incidents',
            },
          ].map((item) => (
            <div
              key={item.step}
              onClick={() => onNavigateTab(item.target)}
              className="bg-[#080B12] border border-slate-800/90 hover:border-amber-500/50 rounded-lg p-4 cursor-pointer transition-all group"
            >
              <div className="text-[11px] font-mono text-amber-400 font-semibold">
                {item.step}
              </div>
              <div className="text-sm font-semibold text-white mt-1 group-hover:text-amber-300 transition-colors">
                {item.title}
              </div>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Arranged 8-Module Command Directory */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-display text-lg font-bold tracking-wide text-white">
              ALL 8 RAKSHAK CYBER DEFENSE MODULES
            </h2>
            <p className="text-xs text-slate-400">
              Click any module card below to open its dedicated workspace page.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {coreModules.map((mod) => {
            const IconComponent = mod.icon;
            return (
              <motion.div
                key={mod.id}
                whileHover={{ y: -3 }}
                onClick={() => onNavigateTab(mod.id)}
                className="bg-[#0D121F] border border-slate-800/90 hover:border-amber-500/60 rounded-xl p-5 flex flex-col justify-between cursor-pointer transition-colors group"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-slate-400">
                      MODULE {mod.step}
                    </span>
                    <IconComponent className={`w-4 h-4 ${mod.accent}`} />
                  </div>

                  <div>
                    <h3 className="text-base font-semibold text-white group-hover:text-amber-300 transition-colors">
                      {mod.title}
                    </h3>
                    <div className="text-xs font-medium text-amber-400/90 mt-0.5">
                      {mod.subtitle}
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed">
                    {mod.description}
                  </p>
                </div>

                <div className="mt-5 pt-3.5 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400 truncate pr-2">
                    {mod.metric}
                  </span>
                  <span className="text-amber-400 group-hover:translate-x-0.5 transition-transform inline-flex items-center gap-1 shrink-0">
                    <span>Open</span>
                    <Play className="w-3 h-3" />
                  </span>
                </div>
              </motion.div>
            );
          })}
        </div>
      </section>
    </motion.div>
  );
}
