'use client';

import React, { useState } from 'react';
import {
  Crosshair,
  ExternalLink,
  Globe,
  Search,
  UserCheck,
  Wifi,
  WifiOff,
  Database,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import {
  DetectionRule,
  IoCRecord,
  SecurityAlert,
  UEBAProfile,
} from '@/lib/types';

interface MitreAndIntelProps {
  rules: DetectionRule[];
  alerts: SecurityAlert[];
  iocs: IoCRecord[];
  uebaProfiles: UEBAProfile[];
  onAddOrEnrichIoc: (indicator: string, isOfflineMode: boolean) => void;
  onToggleRule: (ruleId: string) => void;
}

const ATTACK_STAGES = [
  'Reconnaissance & Initial Access',
  'Credential Access',
  'Privilege Escalation',
  'Lateral Movement',
  'Collection & Exfiltration',
] as const;

export default function MitreAndIntel({
  rules,
  alerts,
  iocs,
  uebaProfiles,
  onAddOrEnrichIoc,
  onToggleRule,
}: MitreAndIntelProps) {
  const [lookupInput, setLookupInput] = useState<string>('');
  const [simulateFeedOutage, setSimulateFeedOutage] = useState<boolean>(false);
  const [verificationFilter, setVerificationFilter] = useState<
    'ALL' | 'Verified Intelligence' | 'Unverified Observation'
  >('ALL');

  const filteredIocs = iocs.filter((item) => {
    if (
      verificationFilter !== 'ALL' &&
      item.verificationStatus !== verificationFilter
    ) {
      return false;
    }
    return true;
  });

  const handleEnrichSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupInput.trim()) return;
    onAddOrEnrichIoc(lookupInput.trim(), simulateFeedOutage);
    setLookupInput('');
  };

  return (
    <div className="space-y-8">
      {/* Section 1: MITRE ATT&CK Kill-Chain Stage Progression & Rule Mapping */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-amber-400" />
              <span>
                01. MITRE ATT&CK Enterprise Matrix & Suspected Attack Stage
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Maps Rakshak detection rules and active alerts to MITRE ATT&CK
              Tactics & Techniques with direct evidence references and official
              documentation links.
            </p>
          </div>
          <a
            href="https://attack.mitre.org/matrices/enterprise/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-amber-400 hover:underline flex items-center gap-1 whitespace-nowrap"
          >
            <span>MITRE ATT&CK v16 Knowledge Base</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </div>

        {/* Suspected Attack Stage Progression Bar */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mt-5">
          {ATTACK_STAGES.map((stage, idx) => {
            const matchingAlerts = alerts.filter(
              (a) => a.attackStage === stage
            );
            const isActiveStage = matchingAlerts.length > 0;
            return (
              <div
                key={stage}
                className={`p-3.5 rounded-md border ${
                  isActiveStage
                    ? 'bg-[#0B0F19] border-amber-500/60'
                    : 'bg-[#0B0F19]/60 border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>STAGE 0{idx + 1}</span>
                  <span
                    className={
                      isActiveStage ? 'text-amber-400 font-semibold' : ''
                    }
                  >
                    {matchingAlerts.length} Active Alert(s)
                  </span>
                </div>
                <div className="text-xs font-semibold text-white mt-1">
                  {stage}
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-2">
                  {matchingAlerts.length > 0
                    ? matchingAlerts
                        .map((a) => `${a.mitreTechniqueId} (${a.id})`)
                        .join(', ')
                    : 'No active detections'}
                </div>
              </div>
            );
          })}
        </div>

        {/* Mapped Detection Rules Table */}
        <div className="overflow-x-auto mt-6">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                <th className="py-2.5 pr-4 font-medium">Rule ID & State</th>
                <th className="py-2.5 px-3 font-medium">Detection Rule Name</th>
                <th className="py-2.5 px-3 font-medium">
                  MITRE Tactic & Technique
                </th>
                <th className="py-2.5 px-3 font-medium">
                  Evidence Behind Mapping
                </th>
                <th className="py-2.5 pl-3 font-medium text-right">
                  Documentation
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {rules.map((rule) => (
                <tr
                  key={rule.id}
                  className="hover:bg-slate-800/30 transition-colors"
                >
                  <td className="py-3 pr-4 font-mono whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => onToggleRule(rule.id)}
                        className={`px-2 py-0.5 text-[11px] rounded border cursor-pointer ${
                          rule.enabled
                            ? 'bg-emerald-950/60 border-emerald-700/80 text-emerald-300'
                            : 'bg-slate-800 border-slate-700 text-slate-400'
                        }`}
                      >
                        {rule.enabled ? 'ACTIVE' : 'MUTED'}
                      </button>
                      <span className="text-amber-300 font-semibold">
                        {rule.id}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1">
                      {rule.wazuhRuleEquivalent}
                    </div>
                  </td>

                  <td className="py-3 px-3">
                    <div className="font-semibold text-white">{rule.name}</div>
                    <div className="text-slate-400 text-[11px] mt-0.5">
                      Default Severity: {rule.defaultSeverity} · Base
                      Confidence: {rule.baseConfidence}%
                    </div>
                  </td>

                  <td className="py-3 px-3 font-mono whitespace-nowrap">
                    <div className="text-amber-300 font-semibold">
                      {rule.mitreTechniqueId}: {rule.mitreTechniqueName}
                    </div>
                    <div className="text-slate-400 text-[11px] mt-0.5">
                      Tactic: {rule.mitreTactic}
                    </div>
                  </td>

                  <td className="py-3 px-3 text-slate-300 max-w-md">
                    {rule.evidenceCriteria}
                  </td>

                  <td className="py-3 pl-3 text-right whitespace-nowrap">
                    <a
                      href={rule.mitreUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-amber-400 hover:underline font-mono text-xs"
                    >
                      <span>{rule.mitreTechniqueId} Docs</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Section 2: User & Entity Behavior Analytics (UEBA) */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="pb-4 border-b border-slate-800/80">
          <h2 className="text-base font-semibold text-white flex items-center gap-2">
            <UserCheck className="w-4 h-4 text-amber-400" />
            <span>
              02. User & Entity Behavior Analytics (UEBA) Baseline vs. Deviation
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Learns typical login hours, known hosts, geolocations, and privilege
            invocation rates per identity to flag statistical Z-score ($\sigma$)
            deviations.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          {uebaProfiles.map((prof) => (
            <div
              key={prof.user}
              className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-3"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-white">
                      {prof.user}
                    </span>
                    <span className="text-slate-500">·</span>
                    <span className="text-xs text-slate-400">{prof.role}</span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-1">
                    Baseline Hours: {prof.typicalHours} · Known Geo:{' '}
                    {prof.usualCountries.join(', ')}
                  </div>
                </div>

                <div className="text-right font-mono tabular-nums">
                  <div
                    className={`text-sm font-semibold ${
                      prof.uebaRiskScore >= 85
                        ? 'text-red-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    UEBA Risk: {prof.uebaRiskScore}/100
                  </div>
                  <div className="text-[11px] text-amber-300">
                    Z-Score: +{prof.zScoreDeviation.toFixed(1)}σ
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800/80 text-xs font-mono tabular-nums">
                <div>
                  <span className="text-slate-500">Auth Failures (Day):</span>{' '}
                  <span className="text-slate-300">
                    Baseline {prof.baselineDailyAuthFailures} vs{' '}
                    <strong className="text-white">
                      Now {prof.currentSessionAuthFailures}
                    </strong>
                  </span>
                </div>
                <div>
                  <span className="text-slate-500">Priv Commands:</span>{' '}
                  <span className="text-slate-300">
                    Baseline {prof.baselinePrivilegeCommands} vs{' '}
                    <strong className="text-amber-300">
                      Now {prof.currentPrivilegeCommands}
                    </strong>
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 space-y-1">
                {prof.detectedAnomalies.map((anom, idx) => (
                  <div
                    key={idx}
                    className="text-xs text-slate-300 flex items-start gap-1.5"
                  >
                    <span className="text-amber-400 font-mono">•</span>
                    <span>{anom}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Section 3: Threat Intelligence Enrichment & IoC Cache */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-amber-400" />
              <span>
                03. Threat Intelligence Enrichment & Resilient IoC Cache
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Enriches IPv4 addresses, domains, and SHA-256 hashes. Explicitly
              distinguishes Verified Intelligence from Unverified Observations
              and caches results for offline resilience.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={() => setSimulateFeedOutage((prev) => !prev)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border flex items-center gap-1.5 cursor-pointer whitespace-nowrap ${
                simulateFeedOutage
                  ? 'bg-amber-950/60 border-amber-600 text-amber-300'
                  : 'bg-[#0B0F19] border-slate-700 text-slate-300 hover:border-slate-600'
              }`}
            >
              {simulateFeedOutage ? (
                <>
                  <WifiOff className="w-3.5 h-3.5 text-amber-400" />
                  <span>Upstream Feed Outage Simulated (Using Local Cache)</span>
                </>
              ) : (
                <>
                  <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                  <span>External Intel Feeds Online</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Enrich Custom IoC Input & Verification Filter */}
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 mt-4">
          <form
            onSubmit={handleEnrichSubmit}
            className="flex items-center gap-2 flex-1"
          >
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={lookupInput}
                onChange={(e) => setLookupInput(e.target.value)}
                placeholder="Enrich IPv4, Domain, or SHA-256 hash (e.g. 193.42.33.18 or evil-c2.net)..."
                className="w-full bg-[#0B0F19] border border-slate-700 rounded-md pl-9 pr-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-amber-500"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors cursor-pointer whitespace-nowrap"
            >
              Enrich & Cache IoC
            </button>
          </form>

          <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
            {(
              [
                'ALL',
                'Verified Intelligence',
                'Unverified Observation',
              ] as const
            ).map((mode) => (
              <button
                key={mode}
                onClick={() => setVerificationFilter(mode)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  verificationFilter === mode
                    ? 'bg-amber-500 text-slate-950 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {mode === 'ALL' ? 'All Indicators' : mode}
              </button>
            ))}
          </div>
        </div>

        {/* IoC Table */}
        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                <th className="py-2.5 pr-4 font-medium">Indicator & Type</th>
                <th className="py-2.5 px-3 font-medium">
                  Reputation & Confidence
                </th>
                <th className="py-2.5 px-3 font-medium">
                  Verification Classification
                </th>
                <th className="py-2.5 px-3 font-medium">
                  Intelligence Source & Cache
                </th>
                <th className="py-2.5 pl-3 font-medium">
                  Threat Context & Attribution
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredIocs.map((ioc) => (
                <tr
                  key={ioc.id}
                  className="hover:bg-slate-800/30 transition-colors"
                >
                  <td className="py-3 pr-4 font-mono">
                    <div className="text-amber-300 font-semibold break-all max-w-xs">
                      {ioc.indicator}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {ioc.type} · {ioc.country} · Sightings: {ioc.sightingsCount}
                    </div>
                  </td>

                  <td className="py-3 px-3 font-mono whitespace-nowrap tabular-nums">
                    <span
                      className={
                        ioc.reputation === 'Malicious'
                          ? 'text-red-400 font-semibold'
                          : ioc.reputation === 'Suspicious'
                            ? 'text-amber-400 font-semibold'
                            : 'text-emerald-400'
                      }
                    >
                      {ioc.reputation} ({ioc.confidenceScore}%)
                    </span>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {ioc.asnOrRegistrar}
                    </div>
                  </td>

                  <td className="py-3 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1.5 font-medium">
                      {ioc.verificationStatus === 'Verified Intelligence' ? (
                        <>
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                          <span className="text-emerald-300">
                            Verified Intelligence
                          </span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                          <span className="text-amber-300">
                            Unverified Observation
                          </span>
                        </>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {ioc.verificationStatus === 'Verified Intelligence'
                        ? 'Multi-feed cryptographic consensus'
                        : 'Single heuristic sighting — corroborate first'}
                    </div>
                  </td>

                  <td className="py-3 px-3 font-mono whitespace-nowrap">
                    <div className="text-slate-200">{ioc.source}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-1.5 tabular-nums">
                      <Database className="w-3 h-3 text-amber-400" />
                      <span>
                        {simulateFeedOutage
                          ? 'OFFLINE_CACHE_FALLBACK'
                          : ioc.cacheStatus}
                      </span>
                      <span>·</span>
                      <span>{ioc.retrievedAt.slice(11, 19)} UTC</span>
                    </div>
                  </td>

                  <td className="py-3 pl-3 text-slate-300 max-w-sm">
                    <div className="font-medium text-white">
                      {ioc.threatActorOrCampaign}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                      {ioc.summary}
                    </p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
