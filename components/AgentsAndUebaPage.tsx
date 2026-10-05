'use client';

import React, { useState } from 'react';
import {
  Server,
  UserCheck,
  ShieldAlert,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Sliders,
  Activity,
  HelpCircle,
} from 'lucide-react';
import { AgentNode, NormalizedLog, UEBAProfile } from '@/lib/types';

interface AgentsAndUebaPageProps {
  agents: AgentNode[];
  uebaProfiles: UEBAProfile[];
  logs: NormalizedLog[];
  onToggleIsolateAgent: (agentId: string) => void;
}

export default function AgentsAndUebaPage({
  agents,
  uebaProfiles,
  logs,
  onToggleIsolateAgent,
}: AgentsAndUebaPageProps) {
  const [selectedTierFilter, setSelectedTierFilter] = useState<string>('ALL');
  const [selectedUserProfile, setSelectedUserProfile] = useState<UEBAProfile>(
    uebaProfiles[0]
  );

  const filteredAgents = agents.filter((a) =>
    selectedTierFilter === 'ALL' ? true : a.criticality === selectedTierFilter
  );

  const userLogs = logs.filter((l) => l.user === selectedUserProfile.user);

  return (
    <div className="space-y-8">
      {/* Page Header & Plain-English Operator Guide */}
      <section className="bg-[#0D1322] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <div className="text-xs font-mono text-amber-400 tracking-wider">
              PAGE 02 · ENDPOINT HEALTH, ASSET PRIORITIZATION & UEBA
            </div>
            <h1 className="font-display text-2xl font-bold text-white mt-1">
              Connected Agent Fleet & Behavioral Analytics (UEBA)
            </h1>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-300 bg-[#070A12] border border-slate-800 px-3.5 py-2 rounded-md">
            <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>
              <strong>Operator Guide:</strong> Isolate compromised hosts in one
              click below, or select any user profile to inspect their Z-score
              behavioral baseline deviations.
            </span>
          </div>
        </div>

        {/* Risk-Based Asset Prioritization Summary */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
          <div className="bg-[#070A12] border border-red-900/50 rounded-md p-4">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-red-400 font-semibold">
                TIER-0 CROWN JEWEL ASSETS
              </span>
              <span className="text-amber-300 font-semibold">
                2.0x Risk Multiplier
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
              Primary Active Directory Domain Controllers (`dc-win-01`) and
              Production Databases (`prd-db-01`). Any suspicious activity here
              is automatically elevated to Critical severity.
            </p>
          </div>

          <div className="bg-[#070A12] border border-amber-900/40 rounded-md p-4">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-amber-400 font-semibold">
                TIER-1 PRODUCTION INFRASTRUCTURE
              </span>
              <span className="text-slate-300 font-semibold">
                1.5x Risk Multiplier
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
              Identity Gateways (`auth-sso-01`) and Kubernetes Ingress nodes
              (`k8s-ingress-02`). Monitored for lateral pivot attempts and SSH
              key abuse.
            </p>
          </div>

          <div className="bg-[#070A12] border border-slate-800 rounded-md p-4">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-300 font-semibold">
                TIER-2 STANDARD WORKSTATIONS
              </span>
              <span className="text-slate-400 font-semibold">
                1.0x Baseline Weight
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1.5 leading-relaxed">
              Employee endpoints (`fin-wks-14`). Monitored via UEBA peer-group
              analytics to catch encoded PowerShell stagers and phishing
              payloads.
            </p>
          </div>
        </div>
      </section>

      {/* Section 1: Connected Agents Fleet Table */}
      <section className="bg-[#0D1322] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-400" />
              <span>01. Connected Endpoint Agents Health & Telemetry</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Real-time heartbeat, CPU/Memory load, Events Per Second (EPS), and
              lab network containment controls.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#070A12] border border-slate-800 rounded-md">
            {(
              [
                'ALL',
                'Tier-0 Crown Jewel',
                'Tier-1 Production',
                'Tier-2 Standard',
              ] as const
            ).map((tier) => (
              <button
                key={tier}
                onClick={() => setSelectedTierFilter(tier)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  selectedTierFilter === tier
                    ? 'bg-amber-500 text-slate-950 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tier === 'ALL' ? 'All Asset Tiers' : tier}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                <th className="py-2.5 pr-4 font-medium">Agent ID & Hostname</th>
                <th className="py-2.5 px-3 font-medium">Operating System</th>
                <th className="py-2.5 px-3 font-medium">
                  Asset Tier & Risk Weight
                </th>
                <th className="py-2.5 px-3 font-medium">Privileged Accounts</th>
                <th className="py-2.5 px-3 font-medium text-right">
                  CPU / Memory / EPS
                </th>
                <th className="py-2.5 px-3 font-medium">Health Status</th>
                <th className="py-2.5 pl-3 font-medium text-right">
                  Containment Action
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredAgents.map((agent) => (
                <tr
                  key={agent.id}
                  className="hover:bg-slate-800/30 transition-colors"
                >
                  <td className="py-3.5 pr-4 font-mono">
                    <div className="text-white font-semibold">
                      {agent.hostname}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {agent.id} · IP: {agent.ip}
                    </div>
                  </td>

                  <td className="py-3.5 px-3">
                    <div className="text-slate-200">{agent.os}</div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                      {agent.version}
                    </div>
                  </td>

                  <td className="py-3.5 px-3 font-mono whitespace-nowrap">
                    <span
                      className={
                        agent.criticality === 'Tier-0 Crown Jewel'
                          ? 'text-red-400 font-semibold'
                          : agent.criticality === 'Tier-1 Production'
                            ? 'text-amber-300 font-semibold'
                            : 'text-slate-300'
                      }
                    >
                      {agent.criticality}
                    </span>
                    <div className="text-[11px] text-slate-400 mt-0.5 tabular-nums">
                      Multiplier: {agent.riskMultiplier.toFixed(1)}x
                    </div>
                  </td>

                  <td className="py-3.5 px-3 font-mono text-slate-300">
                    {agent.privilegedUsers.join(', ')}
                  </td>

                  <td className="py-3.5 px-3 font-mono text-right whitespace-nowrap tabular-nums">
                    <div className="text-slate-200">
                      CPU {agent.cpuLoad}% · Mem {agent.memUsage}%
                    </div>
                    <div className="text-[11px] text-amber-400 mt-0.5">
                      {agent.eps} Events/sec
                    </div>
                  </td>

                  <td className="py-3.5 px-3 font-mono whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      {agent.status === 'Active' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      ) : agent.status === 'Isolated' ? (
                        <Lock className="w-3.5 h-3.5 text-red-400" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      )}
                      <span
                        className={
                          agent.status === 'Active'
                            ? 'text-emerald-400'
                            : agent.status === 'Isolated'
                              ? 'text-red-400 font-semibold'
                              : 'text-amber-400'
                        }
                      >
                        {agent.status}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 tabular-nums">
                      Heartbeat: {agent.lastHeartbeatSec}s ago
                    </div>
                  </td>

                  <td className="py-3.5 pl-3 text-right whitespace-nowrap">
                    <button
                      onClick={() => onToggleIsolateAgent(agent.id)}
                      className={`px-3 py-1.5 text-xs font-medium rounded border transition-colors cursor-pointer ${
                        agent.status === 'Isolated'
                          ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300 hover:bg-emerald-900/60'
                          : 'bg-red-950/40 border-red-800/70 text-red-300 hover:bg-red-900/50'
                      }`}
                    >
                      {agent.status === 'Isolated'
                        ? 'Restore Network Access'
                        : 'Isolate Host in Lab'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Section 2: User & Entity Behavior Analytics (UEBA) Interactive Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <section className="lg:col-span-5 bg-[#0D1322] border border-slate-800/90 rounded-lg p-6">
          <div className="pb-4 border-b border-slate-800/80">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-amber-400" />
              <span>02. UEBA Monitored Identities</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select any user or service account to compare their 90-day learned
              baseline against current session behavior.
            </p>
          </div>

          <div className="divide-y divide-slate-800/80 mt-2">
            {uebaProfiles.map((prof) => {
              const isSelected = prof.user === selectedUserProfile.user;
              return (
                <div
                  key={prof.user}
                  onClick={() => setSelectedUserProfile(prof)}
                  className={`py-3.5 px-3 rounded-md cursor-pointer transition-colors ${
                    isSelected
                      ? 'bg-amber-500/10 border border-amber-500/40'
                      : 'hover:bg-slate-800/40'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="font-mono text-sm font-semibold text-white">
                        {prof.user}
                      </span>
                      {prof.isPrivileged && (
                        <span className="ml-2 text-[11px] font-mono text-amber-400">
                          [Privileged]
                        </span>
                      )}
                      <div className="text-xs text-slate-400 mt-0.5">
                        {prof.role}
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
                        Risk: {prof.uebaRiskScore}/100
                      </div>
                      <div className="text-[11px] text-amber-300">
                        +{prof.zScoreDeviation.toFixed(1)}σ deviation
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Detailed UEBA Profile Breakdown */}
        <section className="lg:col-span-7 bg-[#0D1322] border border-slate-800/90 rounded-lg p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-4 border-b border-slate-800/80">
            <div>
              <div className="text-xs font-mono text-amber-400">
                UEBA BEHAVIORAL BASELINE VS. LIVE SESSION
              </div>
              <h3 className="text-lg font-semibold text-white font-mono mt-0.5">
                {selectedUserProfile.user} — {selectedUserProfile.role}
              </h3>
            </div>
            <div className="font-mono text-xs tabular-nums text-red-400 font-semibold">
              Statistical Z-Score: +{selectedUserProfile.zScoreDeviation}σ
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div className="bg-[#070A12] border border-slate-800 rounded-md p-3.5">
              <div className="text-slate-400">Learned Typical Login Hours</div>
              <div className="text-white font-semibold mt-1">
                {selectedUserProfile.typicalHours}
              </div>
              <div className="text-slate-400 mt-2">Known Authorized Hosts</div>
              <div className="text-slate-200 mt-0.5">
                {selectedUserProfile.knownHosts
                  .map((h) => h.split('.')[0])
                  .join(', ')}
              </div>
            </div>

            <div className="bg-[#070A12] border border-slate-800 rounded-md p-3.5 tabular-nums">
              <div className="text-slate-400">Daily Auth Failures</div>
              <div className="text-white mt-1">
                90d Baseline: {selectedUserProfile.baselineDailyAuthFailures}/day
                ·{' '}
                <strong className="text-amber-300">
                  Current: {selectedUserProfile.currentSessionAuthFailures}
                </strong>
              </div>
              <div className="text-slate-400 mt-2">
                Privileged Commands Executed
              </div>
              <div className="text-white mt-0.5">
                90d Baseline: {selectedUserProfile.baselinePrivilegeCommands}/day
                ·{' '}
                <strong className="text-red-400">
                  Current: {selectedUserProfile.currentPrivilegeCommands}
                </strong>
              </div>
            </div>
          </div>

          <div className="bg-[#070A12] border border-slate-800 rounded-md p-4 space-y-2">
            <div className="text-xs font-mono text-amber-400">
              DETECTED BEHAVIORAL DEVIATIONS
            </div>
            <ul className="space-y-1.5 text-xs text-slate-200">
              {selectedUserProfile.detectedAnomalies.map((anom, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="text-red-400 font-mono">•</span>
                  <span>{anom}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="space-y-2">
            <div className="text-xs font-mono text-slate-400">
              Associated Session Telemetry ({userLogs.length} events for{' '}
              {selectedUserProfile.user}):
            </div>
            <div className="space-y-1.5 max-h-44 overflow-y-auto">
              {userLogs.map((l) => (
                <div
                  key={l.id}
                  className="bg-[#070A12] border border-slate-800/80 rounded px-3 py-2 text-xs font-mono flex items-center justify-between gap-2"
                >
                  <span className="text-amber-300">{l.id}</span>
                  <span className="text-slate-300 truncate flex-1">
                    {l.normalizedSummary}
                  </span>
                  <span className="text-red-400 tabular-nums">
                    UEBA {l.anomalyScore}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
