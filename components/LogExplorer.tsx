'use client';

import React, { useState } from 'react';
import {
  Terminal,
  Upload,
  Sparkles,
  Search,
  Layers,
  CheckCircle2,
  FileCode2,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import { NormalizedLog } from '@/lib/types';
import { SAMPLE_RAW_LOG_PACKETS } from '@/lib/security-data';
import { executeLocalNaturalLanguageHunt } from '@/lib/detection-engine';

interface LogExplorerProps {
  logs: NormalizedLog[];
  onIngestRawLogs: (rawText: string) => void;
}

const PRESET_NL_HUNTS = [
  'Show failed logins followed by a successful login',
  'Show privilege escalations and sudo root commands on Crown Jewel assets',
  'Show stealth PowerShell or UEBA anomalies missed by static rules',
  'Show all Windows Domain Controller security events (4625, 4624, 4672, 4720)',
];

export default function LogExplorer({
  logs,
  onIngestRawLogs,
}: LogExplorerProps) {
  const [rawInput, setRawInput] = useState<string>(
    SAMPLE_RAW_LOG_PACKETS[0].rawText
  );
  const [ingestFeedback, setIngestFeedback] = useState<string | null>(null);
  const [selectedLog, setSelectedLog] = useState<NormalizedLog>(logs[0]);

  // Natural Language Threat Hunting state
  const [nlQuery, setNlQuery] = useState<string>(PRESET_NL_HUNTS[0]);
  const [isHunting, setIsHunting] = useState<boolean>(false);
  const [huntResult, setHuntResult] = useState<{
    translatedQueryDsl: string;
    analystNarrative: string;
    mitreMapping: string;
    matchedLogs: NormalizedLog[];
  }>(() => {
    const initial = executeLocalNaturalLanguageHunt(PRESET_NL_HUNTS[0], logs);
    return {
      translatedQueryDsl: initial.translatedFilterSummary,
      analystNarrative: initial.correlationExplanation,
      mitreMapping: 'T1110.001 -> T1078 (Brute Force to Valid Accounts)',
      matchedLogs: initial.matchedLogs,
    };
  });

  // Multi-entity correlation pivot
  const [correlationPivot, setCorrelationPivot] = useState<
    'user' | 'sourceIp' | 'host'
  >('user');

  const handleIngest = () => {
    if (!rawInput.trim()) return;
    onIngestRawLogs(rawInput);
    const lineCount = rawInput
      .split('\n')
      .filter((l) => l.trim().length > 0).length;
    setIngestFeedback(
      `Normalized & correlated ${lineCount} raw log events into Rakshak SIEM pipeline.`
    );
    setTimeout(() => setIngestFeedback(null), 5000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result;
      if (typeof content === 'string') {
        setRawInput(content);
      }
    };
    reader.readAsText(file);
  };

  const handleRunHunt = async (queryText?: string) => {
    const activeQuery = queryText ?? nlQuery;
    if (queryText) setNlQuery(queryText);

    setIsHunting(true);
    const localResult = executeLocalNaturalLanguageHunt(activeQuery, logs);

    try {
      const res = await fetch('/api/ai/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: activeQuery, logs }),
      });
      const data = await res.json();

      if (data.result && data.result.translatedQueryDsl) {
        const aiMatchedIds = new Set<string>(data.result.matchedEventIds || []);
        const combinedLogs =
          aiMatchedIds.size > 0
            ? logs.filter((l) => aiMatchedIds.has(l.id))
            : localResult.matchedLogs;

        setHuntResult({
          translatedQueryDsl: data.result.translatedQueryDsl,
          analystNarrative: data.result.analystNarrative,
          mitreMapping: data.result.mitreMapping || 'T1078 / T1110',
          matchedLogs:
            combinedLogs.length > 0 ? combinedLogs : localResult.matchedLogs,
        });
      } else {
        setHuntResult({
          translatedQueryDsl: localResult.translatedFilterSummary,
          analystNarrative: localResult.correlationExplanation,
          mitreMapping: 'T1110.001 / T1078 / T1548.003',
          matchedLogs: localResult.matchedLogs,
        });
      }
    } catch {
      setHuntResult({
        translatedQueryDsl: localResult.translatedFilterSummary,
        analystNarrative: localResult.correlationExplanation,
        mitreMapping: 'T1110.001 / T1078 / T1548.003',
        matchedLogs: localResult.matchedLogs,
      });
    } finally {
      setIsHunting(false);
    }
  };

  // Group logs by correlation pivot
  const correlatedGroups = React.useMemo(() => {
    const map = new Map<
      string,
      {
        key: string;
        events: NormalizedLog[];
        hosts: Set<string>;
        users: Set<string>;
        ips: Set<string>;
      }
    >();
    for (const l of logs) {
      const k = l[correlationPivot];
      const existing = map.get(k) || {
        key: k,
        events: [],
        hosts: new Set<string>(),
        users: new Set<string>(),
        ips: new Set<string>(),
      };
      existing.events.push(l);
      existing.hosts.add(l.host.split('.')[0]);
      existing.users.add(l.user);
      existing.ips.add(l.sourceIp);
      map.set(k, existing);
    }
    return Array.from(map.values());
  }, [logs, correlationPivot]);

  return (
    <div className="space-y-8">
      {/* Section 1: Natural-Language Threat Hunting */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>01. Natural-Language Threat Hunting Engine</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Ask plain-English behavioral or sequence questions across normalized
              Linux and Windows telemetry.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Powered by Server-Side Gemini 3.8 Flash + Wazuh Sequence Correlator
          </span>
        </div>

        <div className="mt-4 space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-amber-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={nlQuery}
                onChange={(e) => setNlQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRunHunt()}
                placeholder='Ask e.g. "Show failed logins followed by a successful login"'
                className="w-full bg-[#0B0F19] border border-slate-700/90 rounded-md pl-10 pr-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
            <button
              onClick={() => handleRunHunt()}
              disabled={isHunting}
              className="px-5 py-2.5 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 disabled:opacity-50 transition-colors flex items-center justify-center gap-2 whitespace-nowrap cursor-pointer"
            >
              {isHunting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Correlating Logs...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Execute Threat Hunt</span>
                </>
              )}
            </button>
          </div>

          {/* Preset Hunt Queries */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400">Quick Queries:</span>
            {PRESET_NL_HUNTS.map((q) => (
              <button
                key={q}
                onClick={() => handleRunHunt(q)}
                className={`px-2.5 py-1 text-xs rounded border transition-colors cursor-pointer ${
                  nlQuery === q
                    ? 'bg-amber-500/15 border-amber-500/50 text-amber-300'
                    : 'bg-[#0B0F19] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {q}
              </button>
            ))}
          </div>

          {/* Hunt Output Box */}
          <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <div className="text-amber-400">
                Translated Query DSL:{' '}
                <code className="text-slate-200">
                  {huntResult.translatedQueryDsl}
                </code>
              </div>
              <div className="text-emerald-400">
                MITRE Context: {huntResult.mitreMapping}
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              {huntResult.analystNarrative}
            </p>

            <div className="pt-2 border-t border-slate-800/80">
              <div className="text-[11px] font-mono text-slate-400 mb-2">
                Matched Correlated Sequence ({huntResult.matchedLogs.length}{' '}
                events):
              </div>
              <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                {huntResult.matchedLogs.map((l) => (
                  <div
                    key={l.id}
                    onClick={() => setSelectedLog(l)}
                    className="flex flex-wrap items-center justify-between gap-2 py-1.5 px-2.5 rounded bg-[#0F1523] hover:bg-slate-800/60 cursor-pointer text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-amber-300">{l.id}</span>
                      <span className="text-slate-500">·</span>
                      <span className="text-slate-400">
                        {l.timestamp.slice(11, 19)} UTC
                      </span>
                      <span className="text-slate-500">·</span>
                      <span className="text-white">{l.user}</span>
                      <span className="text-slate-500">@</span>
                      <span className="text-slate-300">
                        {l.host.split('.')[0]}
                      </span>
                      <span className="text-slate-500">·</span>
                      <span
                        className={
                          l.outcome === 'Failure'
                            ? 'text-red-400'
                            : l.outcome === 'Success'
                              ? 'text-emerald-400'
                              : 'text-amber-400'
                        }
                      >
                        {l.eventCode} ({l.outcome})
                      </span>
                    </div>
                    <span className="text-slate-400">{l.sourceIp}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 2: Log Ingestion & Side-by-Side Wazuh Normalizer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Raw Log Collector Input */}
        <section className="lg:col-span-6 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
              <div>
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-amber-400" />
                  <span>02. Log Collector (Linux Syslog & Windows EventLog)</span>
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Import sample packets, paste raw logs, or upload authorized
                  system log files for real-time normalization.
                </p>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  {SAMPLE_RAW_LOG_PACKETS.map((pack) => (
                    <button
                      key={pack.id}
                      onClick={() => setRawInput(pack.rawText)}
                      className="px-2.5 py-1 text-xs rounded bg-[#0B0F19] border border-slate-700 text-slate-300 hover:border-amber-500/60 hover:text-amber-300 transition-colors cursor-pointer"
                    >
                      Load {pack.osHint} Sample
                    </button>
                  ))}
                </div>

                <label className="px-2.5 py-1 text-xs rounded bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors cursor-pointer flex items-center gap-1.5">
                  <Upload className="w-3.5 h-3.5" />
                  <span>Upload .log / .txt</span>
                  <input
                    type="file"
                    accept=".log,.txt,.json,.csv"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>

              <textarea
                rows={7}
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                aria-label="Raw system logs input"
                className="w-full bg-[#0B0F19] border border-slate-800 rounded-md p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500 leading-relaxed"
              />
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between gap-4">
            {ingestFeedback ? (
              <div className="flex items-center gap-2 text-xs text-emerald-400">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{ingestFeedback}</span>
              </div>
            ) : (
              <span className="text-xs text-slate-400">
                Preserves original timestamps and correlates across hosts.
              </span>
            )}

            <button
              onClick={handleIngest}
              className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors flex items-center gap-1.5 whitespace-nowrap cursor-pointer"
            >
              <span>Normalize & Ingest Logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </section>

        {/* Normalized Schema Inspector */}
        <section className="lg:col-span-6 bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800/80">
            <div>
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-amber-400" />
                <span>03. Wazuh-Pattern Normalized Event Inspector</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Click any event in the Hunt results or table to inspect its
                common normalized JSON schema.
              </p>
            </div>
            <span className="text-xs font-mono text-amber-300">
              {selectedLog.id} ({selectedLog.os})
            </span>
          </div>

          <div className="mt-4 space-y-3 text-xs">
            <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-3">
              <div className="text-[11px] font-mono text-slate-400 mb-1">
                Raw Unstructured Telemetry (`raw_log`):
              </div>
              <div className="font-mono text-slate-200 break-all">
                {selectedLog.rawLog}
              </div>
            </div>

            <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-3.5 font-mono text-xs grid grid-cols-2 gap-y-2.5 gap-x-4">
              <div>
                <span className="text-slate-500">timestamp:</span>{' '}
                <span className="text-slate-200">{selectedLog.timestamp}</span>
              </div>
              <div>
                <span className="text-slate-500">agent.host:</span>{' '}
                <span className="text-slate-200">{selectedLog.host}</span>
              </div>
              <div>
                <span className="text-slate-500">agent.os:</span>{' '}
                <span className="text-slate-200">{selectedLog.os}</span>
              </div>
              <div>
                <span className="text-slate-500">asset.tier:</span>{' '}
                <span className="text-amber-300">
                  {selectedLog.assetCriticality}
                </span>
              </div>
              <div>
                <span className="text-slate-500">user.name:</span>{' '}
                <span className="text-white font-semibold">
                  {selectedLog.user}
                </span>{' '}
                {selectedLog.isPrivilegedAccount && (
                  <span className="text-amber-400">(Privileged)</span>
                )}
              </div>
              <div>
                <span className="text-slate-500">source.ip:</span>{' '}
                <span className="text-slate-200">
                  {selectedLog.sourceIp} ({selectedLog.geoCountry})
                </span>
              </div>
              <div>
                <span className="text-slate-500">event.category:</span>{' '}
                <span className="text-slate-200">{selectedLog.category}</span>
              </div>
              <div>
                <span className="text-slate-500">event.code:</span>{' '}
                <span className="text-emerald-400">{selectedLog.eventCode}</span>
              </div>
              <div>
                <span className="text-slate-500">event.outcome:</span>{' '}
                <span className="text-slate-200">{selectedLog.outcome}</span>
              </div>
              <div>
                <span className="text-slate-500">ueba.anomaly_score:</span>{' '}
                <span className="text-red-400 font-semibold">
                  {selectedLog.anomalyScore}/100
                </span>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Section 3: Cross-Entity Event Correlation Matrix */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-amber-400" />
              <span>
                04. Multi-Entity Correlation Engine (Users, Devices & Time Windows)
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Correlates activity across distinct hosts, user identities, and
              source IP addresses to expose lateral movement.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
            {(
              [
                { id: 'user', label: 'Correlate by User' },
                { id: 'sourceIp', label: 'Correlate by Source IP' },
                { id: 'host', label: 'Correlate by Device' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                onClick={() => setCorrelationPivot(tab.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                  correlationPivot === tab.id
                    ? 'bg-amber-500 text-slate-950 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto mt-3">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 font-mono">
                <th className="py-2.5 pr-4 font-medium">Correlation Key</th>
                <th className="py-2.5 px-3 font-medium text-right">
                  Event Count
                </th>
                <th className="py-2.5 px-3 font-medium">Connected Hosts</th>
                <th className="py-2.5 px-3 font-medium">Associated Users</th>
                <th className="py-2.5 px-3 font-medium">Observed Source IPs</th>
                <th className="py-2.5 pl-3 font-medium">Time Window Span</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
              {correlatedGroups.map((grp) => {
                const timestamps = grp.events
                  .map((e) => e.timestamp.slice(11, 19))
                  .sort();
                return (
                  <tr
                    key={grp.key}
                    className="hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="py-2.5 pr-4 text-amber-300 font-semibold">
                      {grp.key}
                    </td>
                    <td className="py-2.5 px-3 text-right tabular-nums text-white">
                      {grp.events.length}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {Array.from(grp.hosts).join(', ')}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {Array.from(grp.users).join(', ')}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 tabular-nums">
                      {Array.from(grp.ips).join(', ')}
                    </td>
                    <td className="py-2.5 pl-3 text-slate-400 tabular-nums">
                      {timestamps[0]} – {timestamps[timestamps.length - 1]} UTC
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
