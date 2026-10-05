'use client';

import React, { useState, useMemo } from 'react';
import { motion } from 'motion/react';
import {
  ShieldAlert,
  GitBranch,
  UserCheck,
  Sparkles,
  Layers,
  CheckCircle2,
  Sliders,
} from 'lucide-react';
import {
  DetectionRule,
  NormalizedLog,
  SecurityAlert,
  SeverityLevel,
  UEBAProfile,
} from '@/lib/types';
import { reconstructAttackChains } from '@/lib/detection-engine';

interface DetectionAndUebaPageProps {
  logs: NormalizedLog[];
  alerts: SecurityAlert[];
  rules: DetectionRule[];
  uebaProfiles: UEBAProfile[];
  onToggleRule: (ruleId: string) => void;
  onInvestigateAlert: (alert: SecurityAlert) => void;
  onCreateIncidentFromAlert: (alert: SecurityAlert) => void;
  onCreateIncidentFromMultipleAlerts: (selectedAlerts: SecurityAlert[]) => void;
}

export default function DetectionAndUebaPage({
  logs,
  alerts,
  rules,
  uebaProfiles,
  onToggleRule,
  onInvestigateAlert,
  onCreateIncidentFromAlert,
  onCreateIncidentFromMultipleAlerts,
}: DetectionAndUebaPageProps) {
  const [activeChainIdx, setActiveChainIdx] = useState<number>(0);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(
    'ALT-401'
  );
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);

  const attackChains = useMemo(() => reconstructAttackChains(logs), [logs]);

  const toggleSelectAlert = (id: string) => {
    setSelectedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleGroupSelected = () => {
    const chosen = alerts.filter((a) => selectedAlertIds.includes(a.id));
    if (chosen.length === 0) return;
    onCreateIncidentFromMultipleAlerts(chosen);
    setSelectedAlertIds([]);
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'Critical':
        return 'text-rose-400 font-semibold';
      case 'High':
        return 'text-amber-400 font-semibold';
      case 'Medium':
        return 'text-yellow-300 font-medium';
      default:
        return 'text-slate-400';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      {/* Page Header & Plain-English Explanation */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-amber-400 tracking-wider">
              MODULE 03 · THREAT DETECTION ENGINE, ATTACK CHAINS & UEBA
            </div>
            <h1 className="font-display text-2xl font-bold text-white">
              Multi-Layer Threat Detection & Behavioral Analytics
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              Detects repeated failed logins, successful logins after failures,
              off-hours/unusual geolocation access, and suspicious privilege
              changes. Assigns <strong>Severity</strong> and{' '}
              <strong>Confidence (%)</strong> separately, deduplicates repeated
              alerts, and reconstructs multi-host attack chains.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-4 shrink-0 bg-[#080B12] border border-slate-800 rounded-lg p-3.5 text-center font-mono tabular-nums">
            <div>
              <div className="text-[11px] text-slate-400">Active Rules</div>
              <div className="text-lg font-bold text-emerald-400">
                {rules.filter((r) => r.enabled).length}/{rules.length}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-400">Attack Chains</div>
              <div className="text-lg font-bold text-amber-400">
                {attackChains.length}
              </div>
            </div>
            <div>
              <div className="text-[11px] text-slate-400">UEBA Entities</div>
              <div className="text-lg font-bold text-rose-400">
                {uebaProfiles.length}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 1: Attack-Chain Reconstruction Graph */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-amber-400" />
              <span>01. Automated Attack-Chain Reconstruction</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Connects separate events across hosts, users, and time windows into
              a chronological sequence of suspicious activity.
            </p>
          </div>

          <div className="flex items-center gap-1.5 p-1 bg-[#080B12] border border-slate-800 rounded-lg">
            {attackChains.map((chain, idx) => (
              <button
                key={chain.chainId}
                onClick={() => setActiveChainIdx(idx)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors cursor-pointer whitespace-nowrap ${
                  activeChainIdx === idx
                    ? 'bg-amber-500 text-slate-950 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {chain.chainId}: {chain.actorIp} ({chain.primaryUser})
              </button>
            ))}
          </div>
        </div>

        {attackChains[activeChainIdx] && (
          <div className="mt-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="text-slate-300">
                <span className="font-semibold text-white">
                  {attackChains[activeChainIdx].title}
                </span>
                <span className="mx-2 text-slate-600">·</span>
                <span className="font-mono text-amber-400">
                  Source IP: {attackChains[activeChainIdx].actorIp}
                </span>
                <span className="mx-2 text-slate-600">·</span>
                <span className="font-mono text-slate-300">
                  Compromised Identity: {attackChains[activeChainIdx].primaryUser}
                </span>
              </div>
              <span className="font-mono text-rose-400 font-semibold tabular-nums">
                End-to-End Chain Risk: {attackChains[activeChainIdx].overallRisk}
                /100
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {attackChains[activeChainIdx].stages.slice(-4).map((stage) => (
                <div
                  key={stage.eventId}
                  className="bg-[#080B12] border border-slate-800/90 hover:border-amber-500/50 rounded-lg p-4 flex flex-col justify-between transition-colors"
                >
                  <div>
                    <div className="flex items-center justify-between text-xs font-mono text-slate-400 tabular-nums">
                      <span className="text-amber-400 font-semibold">
                        STEP 0{stage.stageOrder}
                      </span>
                      <span>{stage.timestamp.slice(11, 19)} UTC</span>
                    </div>
                    <div className="text-xs font-semibold text-white mt-1.5">
                      {stage.phaseName}
                    </div>
                    <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                      {stage.summary}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>{stage.host.split('.')[0]}</span>
                    <span>·</span>
                    <span className="text-amber-300">{stage.eventId}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Section 2: Alert Deduplication & Separate Severity / Confidence Scoring */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <span>
                02. Deduplicated Alerts with Separate Severity & Confidence
                Scoring
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Groups repeated alerts into single clusters to reduce analyst
              fatigue. Check multiple alerts to combine them into a single
              incident.
            </p>
          </div>

          {selectedAlertIds.length > 0 && (
            <button
              onClick={handleGroupSelected}
              className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>
                Combine {selectedAlertIds.length} Alert
                {selectedAlertIds.length > 1 ? 's' : ''} into Incident
              </span>
            </button>
          )}
        </div>

        <div className="divide-y divide-slate-800/80 mt-2">
          {alerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.id;
            const isSelected = selectedAlertIds.includes(alert.id);
            return (
              <div key={alert.id} className="py-4 first:pt-2 last:pb-0">
                <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                  <div className="flex items-start gap-3 flex-1">
                    <input
                      type="checkbox"
                      aria-label={`Select alert ${alert.id}`}
                      checked={isSelected}
                      onChange={() => toggleSelectAlert(alert.id)}
                      className="mt-1 rounded border-slate-700 bg-[#080B12] text-amber-500 cursor-pointer"
                    />

                    <div
                      onClick={() =>
                        setExpandedAlertId(isExpanded ? null : alert.id)
                      }
                      className="cursor-pointer space-y-1.5 flex-1"
                    >
                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                        <span className="text-amber-300 font-semibold">
                          {alert.id} ({alert.ruleId})
                        </span>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className={getSeverityBadge(alert.severity)}>
                          Severity: {alert.severity}
                        </span>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="text-emerald-400 font-semibold">
                          Confidence: {alert.confidence}%
                        </span>
                        <span aria-hidden="true" className="text-slate-600">
                          ·
                        </span>
                        <span className="text-amber-200">
                          Deduplicated Count: {alert.occurrenceCount}x
                        </span>
                      </div>

                      <h3 className="text-sm font-semibold text-white hover:text-amber-300 transition-colors">
                        {alert.title}
                      </h3>

                      <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
                        <span>Host: {alert.host}</span>
                        <span aria-hidden="true">·</span>
                        <span>User: {alert.user}</span>
                        <span aria-hidden="true">·</span>
                        <span>Source IP: {alert.sourceIp}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-amber-300">
                          {alert.assetCriticality}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 pl-6 lg:pl-0 shrink-0">
                    <button
                      onClick={() => onInvestigateAlert(alert)}
                      className="px-3 py-1.5 text-xs font-medium rounded-md bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25 transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Explainable AI Report</span>
                    </button>
                    {alert.status === 'Open' ? (
                      <button
                        onClick={() => onCreateIncidentFromAlert(alert)}
                        className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer whitespace-nowrap"
                      >
                        Create Incident
                      </button>
                    ) : (
                      <span className="text-xs font-mono text-slate-400 px-2">
                        Linked: {alert.incidentId}
                      </span>
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-slate-800/80 bg-[#080B12] p-4 rounded-lg space-y-3 text-xs">
                    <div className="flex items-center justify-between font-mono">
                      <span className="text-amber-400 font-semibold">
                        EXPLAINABLE AI (XAI) REASONING & CONFIDENCE WEIGHTS
                      </span>
                      <span className="text-slate-400">
                        Correlated Events: {alert.triggeringEventIds.join(', ')}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-300">
                      <div>
                        <div className="text-slate-400 font-medium mb-1">
                          Why the Rule Triggered:
                        </div>
                        <p className="leading-relaxed">
                          {alert.xaiReasoning.ruleTriggerExplanation}
                        </p>
                      </div>
                      <div>
                        <div className="text-slate-400 font-medium mb-1">
                          UEBA Baseline Deviation:
                        </div>
                        <p className="leading-relaxed">
                          {alert.xaiReasoning.uebaDeviationSummary}
                        </p>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-4 font-mono text-[11px]">
                      {alert.xaiReasoning.confidenceBreakdown.map((c) => (
                        <span key={c.factor} className="text-slate-300">
                          <strong className="text-emerald-400">
                            {c.weight}
                          </strong>{' '}
                          {c.factor}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Section 3: UEBA Behavioral Profiles & Detection Rule Engine Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* UEBA Profiles */}
        <section className="lg:col-span-7 bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
          <div className="pb-4 border-b border-slate-800/80">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-amber-400" />
              <span>03. User & Entity Behavior Analytics (UEBA)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Learns typical login hours, known hosts, and privilege frequency to
              flag statistical Z-score ($\sigma$) deviations.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
            {uebaProfiles.map((prof) => (
              <div
                key={prof.user}
                className="bg-[#080B12] border border-slate-800/90 rounded-lg p-4 space-y-2.5"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-mono text-sm font-semibold text-white">
                      {prof.user}
                    </div>
                    <div className="text-[11px] text-slate-400">{prof.role}</div>
                  </div>
                  <div className="text-right font-mono tabular-nums">
                    <div
                      className={`text-xs font-semibold ${
                        prof.uebaRiskScore >= 85
                          ? 'text-rose-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      Risk: {prof.uebaRiskScore}/100
                    </div>
                    <div className="text-[11px] text-amber-300">
                      +{prof.zScoreDeviation.toFixed(1)}σ deviation
                    </div>
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-400 pt-2 border-t border-slate-800/80">
                  Usual Hours: {prof.typicalHours} · Geo:{' '}
                  {prof.usualCountries.join(', ')}
                </div>

                <div className="space-y-1 pt-1">
                  {prof.detectedAnomalies.map((anom, i) => (
                    <div
                      key={i}
                      className="text-xs text-slate-300 flex items-start gap-1.5"
                    >
                      <span className="text-rose-400 font-mono">•</span>
                      <span>{anom}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Rule Engine Toggles */}
        <section className="lg:col-span-5 bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
          <div className="pb-4 border-b border-slate-800/80">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-amber-400" />
              <span>04. Active Threat Detection Rules</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Toggle individual Wazuh-pattern correlation rules on or off.
            </p>
          </div>

          <div className="divide-y divide-slate-800/80 mt-2">
            {rules.map((r) => (
              <div
                key={r.id}
                className="py-3 first:pt-2 last:pb-0 flex items-start justify-between gap-3"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-amber-300 font-semibold">{r.id}</span>
                    <span className="text-slate-500">·</span>
                    <span className="text-slate-400">
                      {r.mitreTechniqueId}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-white">
                    {r.name}
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    {r.description}
                  </p>
                </div>

                <button
                  onClick={() => onToggleRule(r.id)}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded border shrink-0 cursor-pointer ${
                    r.enabled
                      ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400'
                  }`}
                >
                  {r.enabled ? (
                    <span className="flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> ENABLED
                    </span>
                  ) : (
                    'MUTED'
                  )}
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>
    </motion.div>
  );
}
