'use client';

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Activity,
  Server,
  Search,
  Play,
  Pause,
  Sparkles,
  ArrowUpRight,
  Lock,
  CheckCircle2,
  AlertTriangle,
  SlidersHorizontal,
  GitBranch,
  PlusCircle,
  Layers,
  Crosshair,
} from 'lucide-react';
import {
  AgentNode,
  NormalizedLog,
  SecurityAlert,
  SeverityLevel,
} from '@/lib/types';
import { reconstructAttackChains } from '@/lib/detection-engine';

interface OverviewMonitorProps {
  logs: NormalizedLog[];
  alerts: SecurityAlert[];
  agents: AgentNode[];
  isStreaming: boolean;
  onToggleStream: () => void;
  onInjectLiveEvent: () => void;
  onInvestigateAlert: (alert: SecurityAlert) => void;
  onCreateIncidentFromAlert: (alert: SecurityAlert) => void;
  onCreateIncidentFromMultipleAlerts?: (selectedAlerts: SecurityAlert[]) => void;
  onToggleIsolateAgent: (agentId: string) => void;
  onNavigateTab: (tab: string) => void;
}

export default function OverviewMonitor({
  logs,
  alerts,
  agents,
  isStreaming,
  onToggleStream,
  onInjectLiveEvent,
  onInvestigateAlert,
  onCreateIncidentFromAlert,
  onCreateIncidentFromMultipleAlerts,
  onToggleIsolateAgent,
  onNavigateTab,
}: OverviewMonitorProps) {
  // Multi-dimensional filters: Host, Time Window, User, IP Address, Severity
  const [selectedHost, setSelectedHost] = useState<string>('ALL');
  const [selectedTimeWindow, setSelectedTimeWindow] = useState<string>('ALL');
  const [selectedUser, setSelectedUser] = useState<string>('ALL');
  const [ipSearch, setIpSearch] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>('ALT-401');
  const [activeChainIdx, setActiveChainIdx] = useState<number>(0);
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [activeScenarioPreset, setActiveScenarioPreset] =
    useState<string>('ALL');

  const uniqueHosts = useMemo(
    () => Array.from(new Set(logs.map((l) => l.host))),
    [logs]
  );
  const uniqueUsers = useMemo(
    () => Array.from(new Set(logs.map((l) => l.user))),
    [logs]
  );

  // Apply 1-click guided scenario filter if chosen
  const applyScenarioPreset = (preset: string) => {
    setActiveScenarioPreset(preset);
    if (preset === 'ALL') {
      setSelectedHost('ALL');
      setSelectedTimeWindow('ALL');
      setSelectedUser('ALL');
      setSelectedSeverity('ALL');
      setIpSearch('');
    } else if (preset === 'LINUX_BREACH') {
      setSelectedHost('ALL');
      setSelectedUser('admin_akhtar');
      setSelectedTimeWindow('ALL');
      setSelectedSeverity('ALL');
      setIpSearch('');
      setActiveChainIdx(0);
    } else if (preset === 'WINDOWS_DC') {
      setSelectedHost('dc-win-01.rakshak.internal');
      setSelectedUser('svc-backup');
      setSelectedTimeWindow('ALL');
      setSelectedSeverity('ALL');
      setIpSearch('');
      setActiveChainIdx(1);
    } else if (preset === 'UEBA_INSIDER') {
      setSelectedHost('fin-wks-14.rakshak.internal');
      setSelectedUser('m_chen');
      setSelectedTimeWindow('ALL');
      setSelectedSeverity('ALL');
      setIpSearch('');
    }
  };

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (selectedHost !== 'ALL' && log.host !== selectedHost) return false;
      if (selectedUser !== 'ALL' && log.user !== selectedUser) return false;
      if (
        ipSearch.trim() !== '' &&
        !log.sourceIp.toLowerCase().includes(ipSearch.trim().toLowerCase()) &&
        !log.rawLog.toLowerCase().includes(ipSearch.trim().toLowerCase())
      ) {
        return false;
      }
      if (selectedTimeWindow === '03_04_UTC') {
        if (!log.timestamp.includes('T03:') && !log.timestamp.includes('T04:'))
          return false;
      } else if (selectedTimeWindow === '06_08_UTC') {
        if (
          !log.timestamp.includes('T06:') &&
          !log.timestamp.includes('T07:') &&
          !log.timestamp.includes('T08:')
        )
          return false;
      }
      if (selectedSeverity !== 'ALL') {
        const derivedSev: SeverityLevel =
          log.anomalyScore >= 92
            ? 'Critical'
            : log.anomalyScore >= 80
              ? 'High'
              : log.anomalyScore >= 50
                ? 'Medium'
                : 'Low';
        if (derivedSev !== selectedSeverity) return false;
      }
      return true;
    });
  }, [
    logs,
    selectedHost,
    selectedUser,
    ipSearch,
    selectedTimeWindow,
    selectedSeverity,
  ]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (selectedHost !== 'ALL' && alert.host !== selectedHost) return false;
      if (selectedUser !== 'ALL' && alert.user !== selectedUser) return false;
      if (
        ipSearch.trim() !== '' &&
        !alert.sourceIp.toLowerCase().includes(ipSearch.trim().toLowerCase())
      ) {
        return false;
      }
      if (selectedSeverity !== 'ALL' && alert.severity !== selectedSeverity)
        return false;
      return true;
    });
  }, [alerts, selectedHost, selectedUser, ipSearch, selectedSeverity]);

  const attackChains = useMemo(() => reconstructAttackChains(logs), [logs]);

  const totalRawEventsInAlerts = useMemo(
    () => alerts.reduce((acc, a) => acc + a.occurrenceCount, 0),
    [alerts]
  );
  const deduplicatedNoiseReductionPct = useMemo(() => {
    if (totalRawEventsInAlerts <= alerts.length) return 0;
    return Math.round(
      ((totalRawEventsInAlerts - alerts.length) / totalRawEventsInAlerts) * 100
    );
  }, [totalRawEventsInAlerts, alerts.length]);

  const authFailureCount = useMemo(
    () =>
      logs.filter(
        (l) => l.category === 'Authentication' && l.outcome === 'Failure'
      ).length,
    [logs]
  );

  const privEscCount = useMemo(
    () =>
      logs.filter(
        (l) =>
          l.category === 'PrivilegeChange' || l.category === 'AccountManagement'
      ).length,
    [logs]
  );

  // Time-series velocity buckets for the Real-Time Threat Visualization Chart
  const velocityBuckets = useMemo(() => {
    const buckets = [
      { label: '03:00', malicious: 0, benign: 0, maxAnomaly: 0 },
      { label: '03:10', malicious: 0, benign: 0, maxAnomaly: 0 },
      { label: '04:20', malicious: 0, benign: 0, maxAnomaly: 0 },
      { label: '06:10', malicious: 0, benign: 0, maxAnomaly: 0 },
      { label: '06:45', malicious: 0, benign: 0, maxAnomaly: 0 },
      { label: '07:10+', malicious: 0, benign: 0, maxAnomaly: 0 },
    ];
    for (const l of logs) {
      let idx = 5;
      if (l.timestamp.includes('T03:08') || l.timestamp.includes('T03:09'))
        idx = 0;
      else if (l.timestamp.includes('T03:12') || l.timestamp.includes('T03:15'))
        idx = 1;
      else if (l.timestamp.includes('T04:')) idx = 2;
      else if (l.timestamp.includes('T06:10')) idx = 3;
      else if (l.timestamp.includes('T06:45') || l.timestamp.includes('T06:50'))
        idx = 4;

      if (l.groundTruthMalicious) buckets[idx].malicious += 1;
      else buckets[idx].benign += 1;
      if (l.anomalyScore > buckets[idx].maxAnomaly) {
        buckets[idx].maxAnomaly = l.anomalyScore;
      }
    }
    return buckets;
  }, [logs]);

  const toggleAlertSelection = (id: string) => {
    setSelectedAlertIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleGroupSelectedIntoIncident = () => {
    const chosen = alerts.filter((a) => selectedAlertIds.includes(a.id));
    if (chosen.length === 0) return;
    if (onCreateIncidentFromMultipleAlerts) {
      onCreateIncidentFromMultipleAlerts(chosen);
      setSelectedAlertIds([]);
    } else {
      onCreateIncidentFromAlert(chosen[0]);
      setSelectedAlertIds([]);
    }
  };

  const getSeverityStyle = (sev: SeverityLevel) => {
    switch (sev) {
      case 'Critical':
        return 'text-red-400 font-semibold';
      case 'High':
        return 'text-amber-400 font-semibold';
      case 'Medium':
        return 'text-yellow-300 font-medium';
      default:
        return 'text-slate-400';
    }
  };

  return (
    <div className="space-y-8">
      {/* Hero Banner with Rakshak Crest & Quick-Start Scenario Controls */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6 lg:p-8 relative overflow-hidden">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-3 text-xs tracking-widest text-amber-400 font-medium">
              <span>ALWAYS WATCHING</span>
              <span aria-hidden="true">✦</span>
              <span>ALWAYS PROTECTING</span>
              <span aria-hidden="true">·</span>
              <span className="text-slate-400 font-normal tracking-normal">
                Wazuh-Pattern SIEM + Explainable Gemini 3.8 Threat Hunter
              </span>
            </div>
            <h1 className="font-display text-2xl sm:text-3xl font-bold tracking-wide text-white text-balance">
              Rakshak Autonomous Cyber Defense & Threat Hunting Console
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed max-w-2xl">
              Real-time Linux and Windows log normalization, behavioral UEBA
              anomaly detection, multi-host attack-chain reconstruction, and
              explainable AI incident forensics with human-in-the-loop response
              playbooks.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={onToggleStream}
              className={`px-4 py-2 text-xs font-medium rounded-md border transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer ${
                isStreaming
                  ? 'bg-emerald-950/50 border-emerald-700/70 text-emerald-300 hover:bg-emerald-900/50'
                  : 'bg-slate-800/80 border-slate-700 text-slate-300 hover:bg-slate-800'
              }`}
            >
              {isStreaming ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>Live Telemetry Active</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Resume Live Stream</span>
                </>
              )}
            </button>

            <button
              onClick={onInjectLiveEvent}
              className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Inject Synthetic Threat Event</span>
            </button>

            <button
              onClick={() => onNavigateTab('logs')}
              className="px-4 py-2 text-xs font-medium rounded-md bg-slate-800/90 border border-slate-700 text-slate-200 hover:bg-slate-700/80 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Natural-Language Hunt</span>
            </button>
          </div>
        </div>

        {/* 1-Click Guided Threat Scenarios Bar (Makes Rakshak Effortless to Operate) */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <span className="text-xs font-medium text-slate-300 whitespace-nowrap">
            1-Click Guided Threat Scenarios:
          </span>
          <div className="flex flex-wrap items-center gap-2">
            {[
              { id: 'ALL', label: 'All Live Telemetry (100%)' },
              {
                id: 'LINUX_BREACH',
                label: 'Scenario 1: Linux SSH Brute Force -> Sudo Root -> DB Exfil',
              },
              {
                id: 'WINDOWS_DC',
                label: 'Scenario 2: Windows AD RDP Spray -> Backdoor Admin',
              },
              {
                id: 'UEBA_INSIDER',
                label: 'Scenario 3: Stealth PowerShell Anomaly (UEBA Catch)',
              },
            ].map((sc) => (
              <button
                key={sc.id}
                onClick={() => applyScenarioPreset(sc.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors cursor-pointer whitespace-nowrap ${
                  activeScenarioPreset === sc.id
                    ? 'bg-amber-500/20 border-amber-500 text-amber-300 font-semibold'
                    : 'bg-[#0B0F19] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {sc.label}
              </button>
            ))}
          </div>
        </div>

        {/* Key Quantitative Telemetry Strip */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-6 mt-6 pt-6 border-t border-slate-800/80">
          <div>
            <div className="text-xs text-slate-400">Normalized Events</div>
            <div className="text-2xl font-mono font-semibold text-white tabular-nums mt-1">
              {logs.length}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Linux Syslog · Windows Security
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400">Correlated Alerts</div>
            <div className="text-2xl font-mono font-semibold text-amber-400 tabular-nums mt-1">
              {alerts.length}
            </div>
            <div className="text-xs text-emerald-400 mt-1 font-mono tabular-nums">
              {deduplicatedNoiseReductionPct}% noise reduced (
              {totalRawEventsInAlerts} raw)
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400">
              Auth Failures & PrivEsc
            </div>
            <div className="text-2xl font-mono font-semibold text-red-400 tabular-nums mt-1">
              {authFailureCount} / {privEscCount}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              Failed Logins · Sudo / Event 4672
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400">Connected Agents</div>
            <div className="text-2xl font-mono font-semibold text-white tabular-nums mt-1">
              {agents.filter((a) => a.status === 'Active').length} /{' '}
              {agents.length}
            </div>
            <div className="text-xs text-slate-400 mt-1">
              {agents.reduce((s, a) => s + a.eps, 0)} EPS aggregate throughput
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400">Crown-Jewel Exposure</div>
            <div className="text-2xl font-mono font-semibold text-amber-300 tabular-nums mt-1">
              2 Tier-0 Hosts
            </div>
            <div className="text-xs text-slate-400 mt-1">
              2.0x Risk-Based Asset Multiplier
            </div>
          </div>
        </div>
      </section>

      {/* Real-Time Threat Visualization Dashboard (Velocity Chart + Live Threat Topology) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left 6 Cols: Time-Series Threat & UEBA Anomaly Velocity Chart */}
        <section className="lg:col-span-6 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-amber-400" />
                  <span>Threat Event Velocity & UEBA Anomaly Timeline</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Real-time distribution of malicious threat bursts vs. benign
                  baseline traffic across UTC intervals.
                </p>
              </div>
              <span className="text-xs font-mono text-amber-400 tabular-nums">
                Peak Anomaly: 99/100
              </span>
            </div>

            <div className="mt-6 grid grid-cols-6 gap-3 items-end h-44 pt-4 px-2 bg-[#0B0F19] border border-slate-800/80 rounded-md">
              {velocityBuckets.map((b) => {
                const total = b.malicious + b.benign;
                const malHeight = Math.min(100, b.malicious * 22);
                const benHeight = Math.min(100, b.benign * 22);
                return (
                  <div
                    key={b.label}
                    className="flex flex-col items-center justify-end h-full pb-2"
                  >
                    <div className="text-[10px] font-mono text-slate-400 mb-1 tabular-nums">
                      {b.maxAnomaly > 0 ? `${b.maxAnomaly}%` : '0%'}
                    </div>
                    <div className="w-full max-w-[36px] flex flex-col justify-end gap-0.5 h-28">
                      {b.malicious > 0 && (
                        <div
                          style={{ height: `${Math.max(16, malHeight)}%` }}
                          title={`${b.malicious} Malicious Events`}
                          className="w-full bg-red-500/80 border border-red-400 rounded-t transition-all"
                        />
                      )}
                      {b.benign > 0 && (
                        <div
                          style={{ height: `${Math.max(14, benHeight)}%` }}
                          title={`${b.benign} Benign Events`}
                          className="w-full bg-emerald-500/60 border border-emerald-400 rounded-b transition-all"
                        />
                      )}
                      {total === 0 && (
                        <div className="w-full h-1 bg-slate-800 rounded" />
                      )}
                    </div>
                    <div className="text-[11px] font-mono text-slate-300 mt-2 tabular-nums">
                      {b.label}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
            <div className="flex items-center gap-4">
              <span>Red Bar: Flagged Threat Events</span>
              <span>·</span>
              <span>Green Bar: Benign Baseline</span>
            </div>
            <span>Top Label: Max UEBA Score</span>
          </div>
        </section>

        {/* Right 6 Cols: Live Lateral Movement & Asset Risk Topology Map */}
        <section className="lg:col-span-6 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Crosshair className="w-4 h-4 text-amber-400" />
                  <span>Live Threat Vector & Crown-Jewel Topology Map</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Visualizes active external adversary IPs pivoting into Tier-1
                  and Tier-0 Crown Jewel assets.
                </p>
              </div>
              <span className="text-xs font-mono text-red-400">
                3 Active Threat Vectors
              </span>
            </div>

            <div className="mt-4 bg-[#0B0F19] border border-slate-800/80 rounded-md p-4 space-y-3 text-xs font-mono">
              {/* Path 1 */}
              <div
                onClick={() => applyScenarioPreset('LINUX_BREACH')}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded border border-slate-800 hover:border-amber-500/50 cursor-pointer transition-colors"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-red-400 font-semibold">
                    185.220.101.44 (Tor DE)
                  </span>
                  <span className="text-slate-500">──SSH Brute──&gt;</span>
                  <span className="text-amber-300">auth-sso-01</span>
                  <span className="text-slate-500">──Lateral Sudo──&gt;</span>
                  <span className="text-white font-semibold">
                    prd-db-01 (Tier-0)
                  </span>
                </div>
                <span className="text-red-400 font-semibold tabular-nums">
                  48.9 MB Exfil
                </span>
              </div>

              {/* Path 2 */}
              <div
                onClick={() => applyScenarioPreset('WINDOWS_DC')}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded border border-slate-800 hover:border-amber-500/50 cursor-pointer transition-colors"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-red-400 font-semibold">
                    91.214.124.88 (RU ASN)
                  </span>
                  <span className="text-slate-500">──RDP Type 10──&gt;</span>
                  <span className="text-white font-semibold">
                    dc-win-01 (Tier-0 AD)
                  </span>
                  <span className="text-slate-500">──Event 4720──&gt;</span>
                  <span className="text-amber-300">support_adm$</span>
                </div>
                <span className="text-amber-400 font-semibold">
                  Domain Admin
                </span>
              </div>

              {/* Path 3 */}
              <div
                onClick={() => applyScenarioPreset('UEBA_INSIDER')}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded border border-slate-800 hover:border-amber-500/50 cursor-pointer transition-colors"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-amber-300">45.155.205.19 (SG)</span>
                  <span className="text-slate-500">──m_chen──&gt;</span>
                  <span className="text-slate-200">fin-wks-14 (Tier-2)</span>
                  <span className="text-slate-500">──Event 4688──&gt;</span>
                  <span className="text-red-400">powershell -Enc</span>
                </div>
                <span className="text-emerald-400">UEBA 4.4σ Catch</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
            <span>Click any vector path above to isolate its logs and alerts.</span>
            <button
              onClick={() => applyScenarioPreset('ALL')}
              className="text-amber-400 hover:underline cursor-pointer font-mono"
            >
              Show All Vectors
            </button>
          </div>
        </section>
      </div>

      {/* Multi-Dimensional Filter Controls (Host, Time, User, IP, Severity) */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <SlidersHorizontal className="w-4 h-4 text-amber-400" />
            <span>Real-Time Telemetry Filter Bar</span>
            <span className="text-xs font-normal text-slate-400 ml-2 font-mono tabular-nums">
              Showing {filteredLogs.length} of {logs.length} events ·{' '}
              {filteredAlerts.length} alerts
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Host Filter */}
            <select
              aria-label="Filter by Host"
              value={selectedHost}
              onChange={(e) => setSelectedHost(e.target.value)}
              className="bg-[#0B0F19] border border-slate-700/90 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
            >
              <option value="ALL">All Hosts ({uniqueHosts.length})</option>
              {uniqueHosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>

            {/* Time Window Filter */}
            <select
              aria-label="Filter by Time Window"
              value={selectedTimeWindow}
              onChange={(e) => setSelectedTimeWindow(e.target.value)}
              className="bg-[#0B0F19] border border-slate-700/90 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
            >
              <option value="ALL">All Time Windows (24h)</option>
              <option value="03_04_UTC">
                Off-Hours Window (03:00–04:59 UTC)
              </option>
              <option value="06_08_UTC">Morning Shift (06:00–08:00 UTC)</option>
            </select>

            {/* User Filter */}
            <select
              aria-label="Filter by User"
              value={selectedUser}
              onChange={(e) => setSelectedUser(e.target.value)}
              className="bg-[#0B0F19] border border-slate-700/90 rounded-md px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-amber-500"
            >
              <option value="ALL">All Users ({uniqueUsers.length})</option>
              {uniqueUsers.map((u) => (
                <option key={u} value={u}>
                  {u}
                </option>
              ))}
            </select>

            {/* Severity Filter */}
            <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
              {(['ALL', 'Critical', 'High', 'Medium', 'Low'] as const).map(
                (sev) => (
                  <button
                    key={sev}
                    onClick={() => setSelectedSeverity(sev)}
                    className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                      selectedSeverity === sev
                        ? 'bg-amber-500 text-slate-950 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev === 'ALL' ? 'All Severities' : sev}
                  </button>
                )
              )}
            </div>

            {/* IP / Keyword Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={ipSearch}
                onChange={(e) => setIpSearch(e.target.value)}
                placeholder="Filter IP (e.g. 185.220.101.44)..."
                className="bg-[#0B0F19] border border-slate-700/90 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500 w-52 font-mono"
              />
            </div>

            {(selectedHost !== 'ALL' ||
              selectedTimeWindow !== 'ALL' ||
              selectedUser !== 'ALL' ||
              selectedSeverity !== 'ALL' ||
              ipSearch !== '') && (
              <button
                onClick={() => applyScenarioPreset('ALL')}
                className="text-xs text-amber-400 hover:underline px-2 py-1 cursor-pointer whitespace-nowrap"
              >
                Reset Filters
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Attack-Chain Reconstruction Panel */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-amber-400" />
              <span>01. Automated Attack-Chain Reconstruction</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Connects separate security events across hosts, users, and network
              segments into a chronological adversary kill-chain sequence.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
            {attackChains.map((chain, idx) => (
              <button
                key={chain.chainId}
                onClick={() => setActiveChainIdx(idx)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap cursor-pointer ${
                  activeChainIdx === idx
                    ? 'bg-slate-800 text-amber-300 border border-amber-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {chain.chainId}: {chain.actorIp} ({chain.primaryUser})
              </button>
            ))}
          </div>
        </div>

        {attackChains[activeChainIdx] && (
          <div className="mt-5">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4 text-xs text-slate-300">
              <div>
                <span className="font-semibold text-white">
                  {attackChains[activeChainIdx].title}
                </span>
                <span className="mx-2 text-slate-600">·</span>
                <span className="font-mono text-amber-400">
                  Origin IP: {attackChains[activeChainIdx].actorIp}
                </span>
                <span className="mx-2 text-slate-600">·</span>
                <span className="font-mono text-slate-300">
                  Target Identity: {attackChains[activeChainIdx].primaryUser}
                </span>
              </div>
              <div className="font-mono tabular-nums text-red-400 font-semibold">
                Chain Risk Score: {attackChains[activeChainIdx].overallRisk}/100
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {attackChains[activeChainIdx].stages.slice(-4).map((stage) => (
                <div
                  key={stage.eventId}
                  className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 flex flex-col justify-between hover:border-amber-500/40 transition-colors"
                >
                  <div>
                    <div className="flex items-center justify-between text-xs text-slate-400 font-mono tabular-nums">
                      <span>STAGE 0{stage.stageOrder}</span>
                      <span>{stage.timestamp.slice(11, 19)} UTC</span>
                    </div>
                    <div className="text-xs font-semibold text-amber-400 mt-1.5">
                      {stage.phaseName}
                    </div>
                    <p className="text-xs text-slate-200 mt-2 leading-relaxed">
                      {stage.summary}
                    </p>
                  </div>
                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                    <span>{stage.host.split('.')[0]}</span>
                    <span>·</span>
                    <span className="text-slate-300">{stage.eventId}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Main Two-Column Grid: Live Deduplicated Alerts & Connected Agents */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left 7 Cols: Live Alerts with Multi-Select Incident Grouping + XAI */}
        <section className="lg:col-span-7 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <span>02. Live Deduplicated Threat Alerts</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Assigns Severity (impact) and Confidence (evidence certainty)
                independently. Select one or more alerts to group into an
                incident.
              </p>
            </div>

            {selectedAlertIds.length > 0 && (
              <button
                onClick={handleGroupSelectedIntoIncident}
                className="px-3.5 py-1.5 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
              >
                <Layers className="w-3.5 h-3.5" />
                <span>
                  Create Incident from {selectedAlertIds.length} Selected Alert
                  {selectedAlertIds.length > 1 ? 's' : ''}
                </span>
              </button>
            )}
          </div>

          <div className="divide-y divide-slate-800/80 mt-2">
            {filteredAlerts.length === 0 ? (
              <div className="py-12 text-center">
                <p className="text-sm text-slate-400">
                  No alerts match the current filter criteria.
                </p>
              </div>
            ) : (
              filteredAlerts.map((alert) => {
                const isExpanded = expandedAlertId === alert.id;
                const isSelected = selectedAlertIds.includes(alert.id);
                return (
                  <div key={alert.id} className="py-4 first:pt-2 last:pb-0">
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                      <div className="flex items-start gap-3 flex-1">
                        <input
                          type="checkbox"
                          aria-label={`Select alert ${alert.id}`}
                          checked={isSelected}
                          onChange={() => toggleAlertSelection(alert.id)}
                          className="mt-1 rounded border-slate-700 bg-[#0B0F19] text-amber-500 focus:ring-amber-500 cursor-pointer"
                        />
                        <div
                          onClick={() =>
                            setExpandedAlertId(isExpanded ? null : alert.id)
                          }
                          className="cursor-pointer space-y-1.5 flex-1"
                        >
                          {/* Clean unboxed metadata line */}
                          <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums">
                            <span className={getSeverityStyle(alert.severity)}>
                              {alert.severity} Severity
                            </span>
                            <span aria-hidden="true" className="text-slate-600">
                              ·
                            </span>
                            <span className="text-emerald-400 font-semibold">
                              {alert.confidence}% Confidence
                            </span>
                            <span aria-hidden="true" className="text-slate-600">
                              ·
                            </span>
                            <span className="text-amber-300">
                              {alert.occurrenceCount}x Deduplicated Events
                            </span>
                            <span aria-hidden="true" className="text-slate-600">
                              ·
                            </span>
                            <span className="text-slate-400">
                              MITRE {alert.mitreTechniqueId}
                            </span>
                          </div>

                          <h3 className="text-sm font-semibold text-white hover:text-amber-300 transition-colors">
                            {alert.title}
                          </h3>

                          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono">
                            <span>Host: {alert.host}</span>
                            <span aria-hidden="true">·</span>
                            <span>User: {alert.user}</span>
                            <span aria-hidden="true">·</span>
                            <span>Source IP: {alert.sourceIp}</span>
                            <span aria-hidden="true">·</span>
                            <span>{alert.assetCriticality}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0 pl-6 sm:pl-0">
                        <button
                          onClick={() => onInvestigateAlert(alert)}
                          className="px-3 py-1.5 text-xs font-medium rounded-md bg-amber-500/15 border border-amber-500/40 text-amber-300 hover:bg-amber-500/25 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
                        >
                          <Sparkles className="w-3.5 h-3.5" />
                          <span>AI Investigate</span>
                        </button>
                        {alert.status === 'Open' ? (
                          <button
                            onClick={() => onCreateIncidentFromAlert(alert)}
                            className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors whitespace-nowrap cursor-pointer"
                          >
                            Create Incident
                          </button>
                        ) : (
                          <span className="text-[11px] font-mono text-slate-400 px-2 py-1">
                            {alert.incidentId}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Explainable AI (XAI) Drawer */}
                    {isExpanded && (
                      <div className="mt-4 pt-4 border-t border-slate-800/80 bg-[#0B0F19] p-4 rounded-md space-y-3 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-amber-400">
                            Explainable AI (XAI) Evidence & Reasoning Breakdown
                          </span>
                          <span className="font-mono text-slate-400 tabular-nums">
                            Events: {alert.triggeringEventIds.join(', ')}
                          </span>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-slate-300">
                          <div>
                            <div className="text-slate-400 font-medium mb-1">
                              Rule Trigger & Log Evidence:
                            </div>
                            <p className="leading-relaxed">
                              {alert.xaiReasoning.ruleTriggerExplanation}
                            </p>
                          </div>
                          <div>
                            <div className="text-slate-400 font-medium mb-1">
                              UEBA Behavioral Deviation:
                            </div>
                            <p className="leading-relaxed">
                              {alert.xaiReasoning.uebaDeviationSummary}
                            </p>
                          </div>
                        </div>
                        <div className="pt-2 border-t border-slate-800/70 flex flex-wrap items-center gap-4 font-mono text-[11px] text-slate-300">
                          {alert.xaiReasoning.confidenceBreakdown.map((item) => (
                            <span key={item.factor}>
                              <strong className="text-emerald-400">
                                {item.weight}
                              </strong>{' '}
                              {item.factor}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </section>

        {/* Right 5 Cols: Connected Agents Health & Risk-Based Asset Prioritization */}
        <section className="lg:col-span-5 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
          <div className="pb-4 border-b border-slate-800/80">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-amber-400" />
              <span>03. Connected Agents & Risk Prioritization</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Monitors agent heartbeat, CPU/Memory, EPS, and applies Risk-Based
              Asset Multipliers to sensitive servers.
            </p>
          </div>

          <div className="divide-y divide-slate-800/80 mt-2">
            {agents.map((agent) => (
              <div key={agent.id} className="py-3.5 first:pt-2 last:pb-0">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      {agent.status === 'Active' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : agent.status === 'Isolated' ? (
                        <Lock className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      )}
                      <span className="text-sm font-semibold text-white font-mono">
                        {agent.hostname}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400 mt-1 flex flex-wrap items-center gap-1.5">
                      <span>{agent.os}</span>
                      <span aria-hidden="true">·</span>
                      <span className="font-mono">{agent.ip}</span>
                    </div>

                    <div className="text-xs mt-1.5 flex flex-wrap items-center gap-2 font-mono tabular-nums">
                      <span
                        className={
                          agent.criticality === 'Tier-0 Crown Jewel'
                            ? 'text-amber-400 font-semibold'
                            : 'text-slate-300'
                        }
                      >
                        {agent.criticality} ({agent.riskMultiplier.toFixed(1)}x
                        Risk)
                      </span>
                      <span aria-hidden="true" className="text-slate-600">
                        ·
                      </span>
                      <span className="text-slate-400">
                        {agent.eps} EPS · CPU {agent.cpuLoad}% · Mem{' '}
                        {agent.memUsage}%
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      Privileged Accounts: {agent.privilegedUsers.join(', ')}
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <span
                      className={`text-xs font-mono ${
                        agent.status === 'Active'
                          ? 'text-emerald-400'
                          : agent.status === 'Isolated'
                            ? 'text-red-400 font-semibold'
                            : 'text-amber-400'
                      }`}
                    >
                      {agent.status} ({agent.lastHeartbeatSec}s ago)
                    </span>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => setSelectedHost(agent.hostname)}
                        className="px-2.5 py-1 text-[11px] font-medium rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white cursor-pointer whitespace-nowrap"
                      >
                        Filter Host
                      </button>
                      <button
                        onClick={() => onToggleIsolateAgent(agent.id)}
                        className={`px-2.5 py-1 text-[11px] font-medium rounded border cursor-pointer whitespace-nowrap ${
                          agent.status === 'Isolated'
                            ? 'bg-emerald-950/60 border-emerald-700 text-emerald-300'
                            : 'bg-red-950/40 border-red-800/70 text-red-300 hover:bg-red-900/50'
                        }`}
                      >
                        {agent.status === 'Isolated'
                          ? 'Restore Network'
                          : 'Simulate Isolate'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      {/* Live Incoming Normalized Security Event Stream Table */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-amber-400" />
              <span>
                04. Real-Time Security Event Stream (Normalized Schema)
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Unified Wazuh-style event table showing authentication failures,
              privilege escalations, and UEBA anomaly scores across Linux and
              Windows hosts.
            </p>
          </div>
          <button
            onClick={() => onNavigateTab('logs')}
            className="text-xs text-amber-400 hover:underline flex items-center gap-1 cursor-pointer whitespace-nowrap"
          >
            <span>Open Full Log Collector & Normalizer</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto mt-3">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                <th className="py-2.5 pr-4 font-medium">Event ID</th>
                <th className="py-2.5 px-3 font-medium">Timestamp (UTC)</th>
                <th className="py-2.5 px-3 font-medium">Host & OS</th>
                <th className="py-2.5 px-3 font-medium">User</th>
                <th className="py-2.5 px-3 font-medium">Source IP / Geo</th>
                <th className="py-2.5 px-3 font-medium">
                  Event Code & Outcome
                </th>
                <th className="py-2.5 px-3 font-medium text-right">
                  UEBA Score
                </th>
                <th className="py-2.5 pl-3 font-medium">Normalized Summary</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs">
              {filteredLogs.map((log) => (
                <tr
                  key={log.id}
                  className="hover:bg-slate-800/30 transition-colors"
                >
                  <td className="py-2.5 pr-4 font-mono text-amber-300 whitespace-nowrap tabular-nums">
                    {log.id}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap tabular-nums">
                    {log.timestamp.replace('T', ' ').replace('Z', '')}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-200 whitespace-nowrap">
                    {log.host.split('.')[0]} ·{' '}
                    <span className="text-slate-400">{log.os}</span>
                  </td>
                  <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                    <span
                      className={
                        log.isPrivilegedAccount
                          ? 'text-amber-300 font-semibold'
                          : 'text-slate-300'
                      }
                    >
                      {log.user}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-slate-300 whitespace-nowrap tabular-nums">
                    {log.sourceIp}{' '}
                    <span className="text-slate-500">({log.geoCountry})</span>
                  </td>
                  <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                    <span className="text-slate-200">{log.eventCode}</span>
                    <span className="mx-1.5 text-slate-600">·</span>
                    <span
                      className={
                        log.outcome === 'Failure'
                          ? 'text-red-400'
                          : log.outcome === 'Elevated'
                            ? 'text-amber-400 font-semibold'
                            : 'text-emerald-400'
                      }
                    >
                      {log.outcome}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-right whitespace-nowrap tabular-nums">
                    <span
                      className={
                        log.anomalyScore >= 85
                          ? 'text-red-400 font-semibold'
                          : log.anomalyScore >= 60
                            ? 'text-amber-400'
                            : 'text-slate-400'
                      }
                    >
                      {log.anomalyScore}/100
                    </span>
                  </td>
                  <td className="py-2.5 pl-3 text-slate-300 max-w-md truncate">
                    {log.normalizedSummary}
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
