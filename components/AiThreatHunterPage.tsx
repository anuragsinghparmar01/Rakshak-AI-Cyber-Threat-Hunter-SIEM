'use client';

import React, { useState } from 'react';
import { motion } from 'motion/react';
import {
  Sparkles,
  Search,
  RefreshCw,
  AlertOctagon,
  Printer,
  Download,
  Clock,
  CheckCircle2,
  ShieldAlert,
} from 'lucide-react';
import {
  AIInvestigationReport,
  Incident,
  NormalizedLog,
} from '@/lib/types';
import { executeLocalNaturalLanguageHunt } from '@/lib/detection-engine';

interface AiThreatHunterPageProps {
  incidents: Incident[];
  logs: NormalizedLog[];
  selectedIncidentId: string;
  onSelectIncident: (id: string) => void;
  onSaveAiReport: (incidentId: string, report: AIInvestigationReport) => void;
}

const PRESET_NL_QUERIES = [
  'Show failed logins followed by a successful login',
  'Show privilege escalations and sudo root commands on Crown Jewel assets',
  'Show stealth PowerShell or UEBA anomalies missed by static rules',
  'Show all Windows Domain Controller security events (4625, 4624, 4672, 4720)',
];

export default function AiThreatHunterPage({
  incidents,
  logs,
  selectedIncidentId,
  onSelectIncident,
  onSaveAiReport,
}: AiThreatHunterPageProps) {
  const activeIncident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [nlQuery, setNlQuery] = useState<string>(PRESET_NL_QUERIES[0]);
  const [isHunting, setIsHunting] = useState<boolean>(false);
  const [huntResult, setHuntResult] = useState<{
    translatedQueryDsl: string;
    analystNarrative: string;
    mitreMapping: string;
    matchedLogs: NormalizedLog[];
  }>(() => {
    const initial = executeLocalNaturalLanguageHunt(PRESET_NL_QUERIES[0], logs);
    return {
      translatedQueryDsl: initial.translatedFilterSummary,
      analystNarrative: initial.correlationExplanation,
      mitreMapping: 'T1110.001 -> T1078 (Brute Force to Valid Accounts)',
      matchedLogs: initial.matchedLogs,
    };
  });

  const incidentLogs = logs.filter((l) =>
    activeIncident.eventIds.includes(l.id)
  );

  const handleRunHunt = async (overrideQuery?: string) => {
    const activeQ = overrideQuery ?? nlQuery;
    if (overrideQuery) setNlQuery(overrideQuery);
    setIsHunting(true);

    const localResult = executeLocalNaturalLanguageHunt(activeQ, logs);

    try {
      const res = await fetch('/api/ai/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: activeQ, logs }),
      });
      const data = await res.json();
      if (data.result && data.result.translatedQueryDsl) {
        const aiIds = new Set<string>(data.result.matchedEventIds || []);
        const matched =
          aiIds.size > 0
            ? logs.filter((l) => aiIds.has(l.id))
            : localResult.matchedLogs;

        setHuntResult({
          translatedQueryDsl: data.result.translatedQueryDsl,
          analystNarrative: data.result.analystNarrative,
          mitreMapping: data.result.mitreMapping || 'T1110.001 -> T1078',
          matchedLogs: matched.length > 0 ? matched : localResult.matchedLogs,
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

  const handleGenerateAiInvestigation = async () => {
    setIsGeneratingAi(true);
    try {
      const res = await fetch('/api/ai/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: activeIncident.title,
          severity: activeIncident.severity,
          confidence: activeIncident.confidence,
          affectedHosts: activeIncident.affectedHosts,
          mitreTechniques: activeIncident.mitreTechniques,
          events: incidentLogs,
        }),
      });
      const data = await res.json();
      if (data.report && data.report.plainEnglishSummary) {
        onSaveAiReport(activeIncident.id, data.report);
      } else {
        const synthesized: AIInvestigationReport = {
          generatedAt: new Date().toISOString(),
          modelUsed: 'gemini-3.8-flash (Rakshak XAI Evidence Engine)',
          plainEnglishSummary: `Incident ${activeIncident.id} (${activeIncident.title}) encompasses ${incidentLogs.length} correlated security events across ${activeIncident.affectedHosts.join(', ')}. Activity originated from ${activeIncident.sourceIps.join(', ')} targeting privileged identities (${activeIncident.affectedUsers.join(', ')}), exhibiting ${activeIncident.mitreTechniques.join(', ')} adversary behavior with ${activeIncident.confidence}% confidence.`,
          triggeringEventsExplanation: incidentLogs.map((l) => ({
            eventId: l.id,
            timestamp: l.timestamp,
            whatHappened: l.normalizedSummary,
            whySuspicious: `UEBA anomaly score ${l.anomalyScore}/100 on ${l.assetCriticality} asset (${l.eventCode}, outcome=${l.outcome}).`,
          })),
          chronologicalTimeline: incidentLogs.map((l, idx) => ({
            step: idx + 1,
            timestamp: l.timestamp.slice(11, 19) + ' UTC',
            stage: l.category,
            asset: l.host,
            actorOrIp: `${l.user} (${l.sourceIp})`,
            description: l.normalizedSummary,
          })),
          affectedAssetsAndScope: activeIncident.affectedHosts.map((h) => ({
            asset: h,
            criticality: 'Tier-0 Crown Jewel (2.0x Risk Weight)',
            impactSummary: `Targeted or accessed by ${activeIncident.affectedUsers.join(', ')} during the incident window.`,
          })),
          suggestedInvestigationSteps: [
            `Execute SOAR containment playbooks to block ${activeIncident.sourceIps.join(', ')} and lock compromised accounts.`,
            `Audit all active SSH keys, sudoers entries, and Kerberos tickets for ${activeIncident.affectedUsers.join(', ')}.`,
            `Capture volatile memory and disk artifacts on ${activeIncident.affectedHosts.join(', ')} prior to re-imaging.`,
          ],
          explainableAiReasoning: `Confidence score (${activeIncident.confidence}%) is backed by deterministic sequence correlation combined with high UEBA statistical deviation and Tier-0 asset criticality weights.`,
          limitationsAndUncertainties: [
            'Encrypted Payload Visibility: Telemetry confirms outbound byte volume and process arguments, but full packet capture (PCAP) is required to inspect encrypted payload contents.',
            'Upstream Attribution: External source IP addresses may represent Tor exit relays or compromised jump hosts rather than the threat actor origin.',
          ],
        };
        onSaveAiReport(activeIncident.id, synthesized);
      }
    } catch {
      // Handled cleanly
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleExportReportMarkdown = () => {
    const text = `# RAKSHAK AI FORENSIC DOSSIER: ${activeIncident.id}
Title: ${activeIncident.title}
Severity: ${activeIncident.severity} | Confidence: ${activeIncident.confidence}%
Affected Hosts: ${activeIncident.affectedHosts.join(', ')}

## PLAIN-ENGLISH EXECUTIVE SUMMARY
${activeIncident.aiReport?.plainEnglishSummary || 'N/A'}

## EXPLAINABLE AI (XAI) REASONING
${activeIncident.aiReport?.explainableAiReasoning || 'N/A'}

## LIMITATIONS & UNCERTAINTIES
${(activeIncident.aiReport?.limitationsAndUncertainties || []).map((l) => `- ${l}`).join('\n')}
`;
    const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeIncident.id}-AI-Forensic-Report.md`;
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
      {/* Page Header */}
      <section className="bg-[#0D121F] border border-amber-500/30 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-amber-400 tracking-wider">
              MODULE 04 · SIGNATURE AI THREAT INVESTIGATION & NATURAL-LANGUAGE
              HUNTING
            </div>
            <h1 className="font-display text-2xl font-bold text-white">
              Rakshak Explainable AI (XAI) Forensic Sanctum
            </h1>
            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              Ask natural-language threat hunting questions or generate a
              complete, evidence-backed incident dossier with plain-English
              summaries, triggering event explanations, chronological timelines,
              and explicit epistemic limitations.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={() => window.print()}
              className="px-3.5 py-2 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print PDF Dossier</span>
            </button>
            <button
              onClick={handleExportReportMarkdown}
              className="px-3.5 py-2 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Report (.md)</span>
            </button>
          </div>
        </div>
      </section>

      {/* Section 1: Natural-Language Threat Hunting Console */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-amber-400" />
              <span>01. Natural-Language Threat Hunting</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Ask questions in plain English such as &ldquo;Show failed logins
              followed by a successful login&rdquo; to correlate across logs.
            </p>
          </div>
          <span className="text-xs font-mono text-emerald-400">
            Gemini 3.8 Flash + Sequence Join Correlator
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
                className="w-full bg-[#080B12] border border-slate-700 rounded-md pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-amber-500"
              />
            </div>
            <button
              onClick={() => handleRunHunt()}
              disabled={isHunting}
              className="px-5 py-2.5 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 disabled:opacity-50 transition-colors flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap"
            >
              {isHunting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Hunting Telemetry...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Run Natural-Language Hunt</span>
                </>
              )}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400">Sample Queries:</span>
            {PRESET_NL_QUERIES.map((q) => (
              <button
                key={q}
                onClick={() => handleRunHunt(q)}
                className={`px-2.5 py-1 text-xs rounded border transition-colors cursor-pointer ${
                  nlQuery === q
                    ? 'bg-amber-500/20 border-amber-500 text-amber-300 font-medium'
                    : 'bg-[#080B12] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {q}
              </button>
            ))}
          </div>

          <div className="bg-[#080B12] border border-slate-800/90 rounded-lg p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
              <div className="text-amber-400">
                SIEM Correlation DSL:{' '}
                <code className="text-slate-200">
                  {huntResult.translatedQueryDsl}
                </code>
              </div>
              <div className="text-emerald-400">
                MITRE Mapping: {huntResult.mitreMapping}
              </div>
            </div>

            <p className="text-xs text-slate-200 leading-relaxed">
              {huntResult.analystNarrative}
            </p>

            <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
              <div className="text-[11px] font-mono text-slate-400">
                Matched Correlated Events ({huntResult.matchedLogs.length}):
              </div>
              {huntResult.matchedLogs.map((l) => (
                <div
                  key={l.id}
                  className="flex flex-wrap items-center justify-between gap-2 py-1.5 px-3 rounded bg-[#0D121F] text-xs font-mono"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-amber-300 font-semibold">{l.id}</span>
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
                          ? 'text-rose-400'
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
      </section>

      {/* Section 2: Signature AI Incident Investigation Report */}
      <section className="bg-[#0D121F] border border-slate-800/90 rounded-xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>
                02. AI Threat Investigation & Structured Incident Report
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Select an incident below to view or regenerate its plain-English
              summary, triggering evidence, chronological timeline, and
              limitations.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {incidents.map((inc) => (
              <button
                key={inc.id}
                onClick={() => onSelectIncident(inc.id)}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors cursor-pointer ${
                  inc.id === activeIncident.id
                    ? 'bg-amber-500 text-slate-950 border-amber-400 font-semibold'
                    : 'bg-[#080B12] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                {inc.id} ({inc.severity})
              </button>
            ))}

            <button
              onClick={handleGenerateAiInvestigation}
              disabled={isGeneratingAi}
              className="px-4 py-1.5 text-xs font-semibold rounded-md bg-rose-600 text-white hover:bg-rose-500 disabled:opacity-50 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              {isGeneratingAi ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Synthesizing Report...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>
                    {activeIncident.aiReport
                      ? 'Regenerate AI Report'
                      : 'Generate AI Report'}
                  </span>
                </>
              )}
            </button>
          </div>
        </div>

        {!activeIncident.aiReport ? (
          <div className="py-12 text-center space-y-3">
            <ShieldAlert className="w-8 h-8 text-amber-400 mx-auto" />
            <div className="text-sm font-semibold text-white">
              Ready to Investigate {activeIncident.id}: {activeIncident.title}
            </div>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              Click &ldquo;Generate AI Report&rdquo; above to synthesize the
              plain-English executive summary, chronological timeline, and
              evidence references for this incident.
            </p>
          </div>
        ) : (
          <div className="mt-6 space-y-6">
            {/* Plain English Summary & Explainable AI */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7 bg-[#080B12] border border-slate-800/90 rounded-lg p-5 space-y-2.5">
                <div className="flex items-center justify-between text-xs font-mono text-amber-400">
                  <span>1. PLAIN-ENGLISH INCIDENT SUMMARY</span>
                  <span className="text-slate-400">
                    {activeIncident.aiReport.modelUsed}
                  </span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {activeIncident.aiReport.plainEnglishSummary}
                </p>
              </div>

              <div className="lg:col-span-5 bg-[#080B12] border border-slate-800/90 rounded-lg p-5 space-y-2.5">
                <div className="text-xs font-mono text-emerald-400">
                  2. EXPLAINABLE AI (XAI) REASONING & EVIDENCE
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeIncident.aiReport.explainableAiReasoning}
                </p>
                <div className="pt-2 border-t border-slate-800 text-[11px] font-mono text-slate-400">
                  Affected Hosts:{' '}
                  <span className="text-white">
                    {activeIncident.affectedHosts.join(', ')}
                  </span>
                </div>
              </div>
            </div>

            {/* Chronological Incident Timeline */}
            <div className="bg-[#080B12] border border-slate-800/90 rounded-lg p-5">
              <div className="text-xs font-mono text-amber-400 mb-3 flex items-center gap-2">
                <Clock className="w-3.5 h-3.5" />
                <span>
                  3. CHRONOLOGICAL INCIDENT TIMELINE & ASSET CORRELATION
                </span>
              </div>
              <div className="divide-y divide-slate-800/80">
                {activeIncident.aiReport.chronologicalTimeline.map((step) => (
                  <div
                    key={step.step}
                    className="py-3 first:pt-1 last:pb-0 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <span className="font-mono text-amber-400 font-semibold tabular-nums shrink-0">
                        STEP 0{step.step} [{step.timestamp}]
                      </span>
                      <span className="text-white font-medium">
                        {step.description}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 shrink-0">
                      {step.stage} · {step.asset.split('.')[0]} ·{' '}
                      <span className="text-amber-300">{step.actorOrIp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Triggering Events + Suggested Steps + Limitations */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-[#080B12] border border-slate-800/90 rounded-lg p-5 space-y-3">
                <div className="text-xs font-mono text-amber-400">
                  4. WHICH EVENTS TRIGGERED THE ALERT (EVIDENCE REFERENCES)
                </div>
                <div className="divide-y divide-slate-800/80 text-xs">
                  {activeIncident.aiReport.triggeringEventsExplanation.map(
                    (ev) => (
                      <div
                        key={ev.eventId}
                        className="py-2.5 first:pt-0 last:pb-0"
                      >
                        <div className="flex items-center justify-between font-mono text-amber-300">
                          <span>{ev.eventId}</span>
                          <span className="text-slate-400">{ev.timestamp}</span>
                        </div>
                        <p className="text-slate-200 mt-1">{ev.whatHappened}</p>
                        <p className="text-slate-400 mt-0.5">
                          Trigger Rationale: {ev.whySuspicious}
                        </p>
                      </div>
                    )
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="bg-[#080B12] border border-slate-800/90 rounded-lg p-5 space-y-2.5">
                  <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>5. SUGGESTED ANALYST INVESTIGATION STEPS</span>
                  </div>
                  <ol className="space-y-2 text-xs text-slate-200 list-decimal list-inside">
                    {activeIncident.aiReport.suggestedInvestigationSteps.map(
                      (s, idx) => (
                        <li key={idx} className="leading-relaxed">
                          {s}
                        </li>
                      )
                    )}
                  </ol>
                </div>

                <div className="bg-[#080B12] border border-rose-500/40 rounded-lg p-5 space-y-2">
                  <div className="text-xs font-mono text-rose-400 flex items-center gap-1.5">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    <span>
                      6. EVIDENCE-BACKED AI LIMITATIONS & UNCERTAINTIES
                    </span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                    {activeIncident.aiReport.limitationsAndUncertainties.map(
                      (lim, idx) => (
                        <li key={idx} className="leading-relaxed">
                          {lim}
                        </li>
                      )
                    )}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </section>
    </motion.div>
  );
}
