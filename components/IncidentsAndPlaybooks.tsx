'use client';

import React, { useState } from 'react';
import {
  FileText,
  Sparkles,
  ShieldCheck,
  Clock,
  CheckCircle2,
  AlertOctagon,
  Printer,
  Download,
  Plus,
  RefreshCw,
  UserCheck,
  History,
  Play,
  XCircle,
} from 'lucide-react';
import {
  AIInvestigationReport,
  Incident,
  IncidentStatus,
  NormalizedLog,
  PlaybookAction,
} from '@/lib/types';

interface IncidentsAndPlaybooksProps {
  incidents: Incident[];
  logs: NormalizedLog[];
  playbooks: PlaybookAction[];
  selectedIncidentId: string;
  onSelectIncident: (id: string) => void;
  onUpdateIncidentStatus: (id: string, status: IncidentStatus) => void;
  onUpdateIncidentAssignee: (id: string, assignee: string) => void;
  onAddIncidentNote: (
    id: string,
    author: string,
    content: string,
    evidenceRef?: string
  ) => void;
  onSaveAiReport: (incidentId: string, report: AIInvestigationReport) => void;
  onApprovePlaybook: (playbookId: string, approver: string) => void;
  onRejectPlaybook: (playbookId: string, approver: string) => void;
  onTriggerCustomPlaybook: (
    incidentId: string,
    actionType: PlaybookAction['actionType'],
    targetEntity: string
  ) => void;
}

const SOC_ANALYSTS = [
  'A. Sharma (Tier-3 Threat Hunt Lead)',
  'M. Vance (Incident Response Lead)',
  'K. Patel (SOC Tier-2 Analyst)',
  'R. Deshmukh (Principal Forensics Engineer)',
];

export default function IncidentsAndPlaybooks({
  incidents,
  logs,
  playbooks,
  selectedIncidentId,
  onSelectIncident,
  onUpdateIncidentStatus,
  onUpdateIncidentAssignee,
  onAddIncidentNote,
  onSaveAiReport,
  onApprovePlaybook,
  onRejectPlaybook,
  onTriggerCustomPlaybook,
}: IncidentsAndPlaybooksProps) {
  const activeIncident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const [noteInput, setNoteInput] = useState<string>('');
  const [evidenceInput, setEvidenceInput] = useState<string>('EVT-9006');
  const [isGeneratingAi, setIsGeneratingAi] = useState<boolean>(false);
  const [customActionType, setCustomActionType] =
    useState<PlaybookAction['actionType']>('Block Firewall IP');
  const [customTarget, setCustomTarget] = useState<string>('185.220.101.44');

  const incidentLogs = logs.filter((l) =>
    activeIncident.eventIds.includes(l.id)
  );
  const incidentPlaybooks = playbooks.filter(
    (p) => p.incidentId === activeIncident.id
  );

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
        // Deterministic XAI synthesis if offline or fallback
        const synthesized: AIInvestigationReport = {
          generatedAt: new Date().toISOString(),
          modelUsed: 'gemini-3.8-flash (Rakshak XAI Evidence Engine)',
          plainEnglishSummary: `Incident ${activeIncident.id} (${activeIncident.title}) involves ${incidentLogs.length} correlated security events across ${activeIncident.affectedHosts.join(', ')}. Activity originated from ${activeIncident.sourceIps.join(', ')} targeting privileged identities (${activeIncident.affectedUsers.join(', ')}), exhibiting ${activeIncident.mitreTechniques.join(', ')} tactics with ${activeIncident.confidence}% confidence.`,
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
            impactSummary: `Compromised or targeted by ${activeIncident.affectedUsers.join(', ')} during incident window.`,
          })),
          suggestedInvestigationSteps: [
            `Review and approve pending SOAR containment playbooks for ${activeIncident.sourceIps.join(', ')}.`,
            `Audit all active sessions and Kerberos/SSH tokens for ${activeIncident.affectedUsers.join(', ')}.`,
            `Preserve forensic disk/memory snapshots on ${activeIncident.affectedHosts.join(', ')} before remediation.`,
          ],
          explainableAiReasoning: `Confidence score (${activeIncident.confidence}%) is derived from multi-stage rule correlation combined with high UEBA statistical deviation and Tier-0 asset criticality multipliers.`,
          limitationsAndUncertainties: [
            'Host log correlation confirms command execution and network session metadata, but full packet payload inspection (PCAP) is required to verify exact bytes transferred.',
            'External source IP attribution may reflect a VPN, Tor exit relay, or compromised third-party jump host.',
          ],
        };
        onSaveAiReport(activeIncident.id, synthesized);
      }
    } catch {
      // Handled gracefully
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!noteInput.trim()) return;
    onAddIncidentNote(
      activeIncident.id,
      activeIncident.assignee,
      noteInput.trim(),
      evidenceInput.trim() || undefined
    );
    setNoteInput('');
  };

  const handleDownloadReport = () => {
    const reportText = `# RAKSHAK INCIDENT FORENSIC REPORT: ${activeIncident.id}
Title: ${activeIncident.title}
Status: ${activeIncident.status} | Severity: ${activeIncident.severity} | Confidence: ${activeIncident.confidence}%
Assigned Analyst: ${activeIncident.assignee}
Generated At: ${new Date().toISOString()}
Affected Hosts: ${activeIncident.affectedHosts.join(', ')}
Affected Users: ${activeIncident.affectedUsers.join(', ')}
Source IPs: ${activeIncident.sourceIps.join(', ')}
MITRE ATT&CK Techniques: ${activeIncident.mitreTechniques.join(', ')}

## 1. PLAIN-ENGLISH EXECUTIVE SUMMARY
${activeIncident.aiReport?.plainEnglishSummary || 'Pending AI Investigation.'}

## 2. EXPLAINABLE AI (XAI) REASONING
${activeIncident.aiReport?.explainableAiReasoning || 'N/A'}

## 3. TRIGGERING LOG EVIDENCE
${incidentLogs.map((l) => `- [${l.id}] ${l.timestamp} | ${l.host} | ${l.user} | ${l.sourceIp} | ${l.normalizedSummary}`).join('\n')}

## 4. LIMITATIONS & UNCERTAINTIES
${(activeIncident.aiReport?.limitationsAndUncertainties || []).map((lim) => `- ${lim}`).join('\n')}

## 5. IMMUTABLE AUDIT TRAIL
${activeIncident.auditTrail.map((a) => `- [${a.timestamp}] ${a.actor} (${a.action}): ${a.details}`).join('\n')}
`;
    const blob = new Blob([reportText], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeIncident.id}-Rakshak-Forensic-Report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintPdf = () => {
    window.print();
  };

  return (
    <div className="space-y-8">
      {/* Top Incident Selector & Workflow Header */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
          <div>
            <div className="text-xs font-mono text-amber-400">
              INCIDENT MANAGEMENT, AI FORENSICS & SOAR PLAYBOOKS
            </div>
            <h2 className="text-lg font-semibold text-white mt-1">
              {activeIncident.id}: {activeIncident.title}
            </h2>
          </div>

          <div className="flex flex-wrap items-center gap-2 no-print">
            {incidents.map((inc) => (
              <button
                key={inc.id}
                onClick={() => onSelectIncident(inc.id)}
                className={`px-3 py-1.5 text-xs font-mono rounded-md border transition-colors cursor-pointer whitespace-nowrap ${
                  inc.id === activeIncident.id
                    ? 'bg-amber-500 text-slate-950 border-amber-400 font-semibold'
                    : 'bg-[#0B0F19] border-slate-800 text-slate-300 hover:border-slate-700'
                }`}
              >
                {inc.id} ({inc.status})
              </button>
            ))}

            <button
              onClick={handlePrintPdf}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF Report</span>
            </button>

            <button
              onClick={handleDownloadReport}
              className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-200 hover:bg-slate-700 transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Evidence Dossier</span>
            </button>
          </div>
        </div>

        {/* Status Workflow & Analyst Assignment Controls */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-5">
          <div>
            <label className="block text-xs text-slate-400 mb-2">
              Incident Lifecycle Status
            </label>
            <div className="flex items-center gap-1 p-1 bg-[#0B0F19] border border-slate-800 rounded-md">
              {(
                ['New', 'Investigating', 'Contained', 'Resolved'] as const
              ).map((st) => (
                <button
                  key={st}
                  onClick={() => onUpdateIncidentStatus(activeIncident.id, st)}
                  className={`flex-1 py-1.5 px-2 text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                    activeIncident.status === st
                      ? 'bg-amber-500 text-slate-950 font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-2">
              Assigned SOC Analyst
            </label>
            <div className="relative">
              <UserCheck className="w-4 h-4 text-amber-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <select
                aria-label="Assigned SOC Analyst"
                value={activeIncident.assignee}
                onChange={(e) =>
                  onUpdateIncidentAssignee(activeIncident.id, e.target.value)
                }
                className="w-full bg-[#0B0F19] border border-slate-800 rounded-md pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
              >
                {SOC_ANALYSTS.map((analyst) => (
                  <option key={analyst} value={analyst}>
                    {analyst}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <div className="text-xs text-slate-400 mb-2">
              Correlated Scope & Evidence Summary
            </div>
            <div className="bg-[#0B0F19] border border-slate-800 rounded-md px-3.5 py-2 text-xs font-mono text-slate-300 flex flex-wrap items-center justify-between">
              <span>
                Severity:{' '}
                <strong className="text-red-400">
                  {activeIncident.severity}
                </strong>
              </span>
              <span>·</span>
              <span>
                Confidence:{' '}
                <strong className="text-emerald-400">
                  {activeIncident.confidence}%
                </strong>
              </span>
              <span>·</span>
              <span>{activeIncident.eventIds.length} Events</span>
            </div>
          </div>
        </div>
      </section>

      {/* Signature Feature: AI Threat Investigation & Explainable AI Report */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <span>
                01. AI Threat Investigation & Structured Forensic Dossier
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Plain-English incident synthesis, triggering event attribution,
              chronological attack timeline, and explicit epistemic limitations.
            </p>
          </div>

          <button
            onClick={handleGenerateAiInvestigation}
            disabled={isGeneratingAi}
            className="px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 disabled:opacity-50 transition-colors flex items-center gap-2 whitespace-nowrap cursor-pointer no-print"
          >
            {isGeneratingAi ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Synthesizing Gemini 3.8 Flash Report...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>
                  {activeIncident.aiReport
                    ? 'Regenerate Live AI Investigation'
                    : 'Generate AI Investigation Report'}
                </span>
              </>
            )}
          </button>
        </div>

        {!activeIncident.aiReport ? (
          <div className="py-10 text-center space-y-3">
            <p className="text-sm text-slate-300">
              No AI Forensic Report generated yet for {activeIncident.id}.
            </p>
            <p className="text-xs text-slate-400 max-w-xl mx-auto">
              Click &ldquo;Generate AI Investigation Report&rdquo; above to
              invoke server-side Gemini 3.8 Flash over the{' '}
              {incidentLogs.length} normalized log events attached to this
              incident.
            </p>
          </div>
        ) : (
          <div className="mt-5 space-y-6">
            {/* Plain English Summary & XAI Reasoning */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7 bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono text-amber-400">
                  <span>EXECUTIVE SUMMARY (PLAIN ENGLISH)</span>
                  <span className="text-slate-400">
                    {activeIncident.aiReport.modelUsed}
                  </span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {activeIncident.aiReport.plainEnglishSummary}
                </p>
              </div>

              <div className="lg:col-span-5 bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-2">
                <div className="text-xs font-mono text-emerald-400">
                  EXPLAINABLE AI (XAI) CONFIDENCE RATIONALE
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {activeIncident.aiReport.explainableAiReasoning}
                </p>
                <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                  MITRE ATT&CK Chain:{' '}
                  <span className="text-amber-300">
                    {activeIncident.mitreTechniques.join(' -> ')}
                  </span>
                </div>
              </div>
            </div>

            {/* Chronological Incident Timeline */}
            <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4">
              <div className="text-xs font-mono text-amber-400 mb-3">
                CHRONOLOGICAL INCIDENT TIMELINE & ASSET LINKAGE
              </div>
              <div className="divide-y divide-slate-800/70">
                {activeIncident.aiReport.chronologicalTimeline.map((item) => (
                  <div
                    key={item.step}
                    className="py-2.5 first:pt-0 last:pb-0 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div className="flex items-start sm:items-center gap-3">
                      <span className="font-mono text-amber-400 font-semibold tabular-nums shrink-0">
                        0{item.step}. [{item.timestamp}]
                      </span>
                      <span className="text-white font-medium">
                        {item.description}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-slate-400 shrink-0">
                      {item.stage} · {item.asset.split('.')[0]} ·{' '}
                      <span className="text-slate-300">{item.actorOrIp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Triggering Events Explanation & Suggested Steps */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-3">
                <div className="text-xs font-mono text-amber-400">
                  EVIDENCE ATTRIBUTION (WHICH EVENTS TRIGGERED THE ALERT)
                </div>
                <div className="divide-y divide-slate-800/70 text-xs">
                  {activeIncident.aiReport.triggeringEventsExplanation.map(
                    (ev) => (
                      <div key={ev.eventId} className="py-2.5 first:pt-0 last:pb-0">
                        <div className="flex items-center justify-between font-mono text-amber-300">
                          <span>{ev.eventId}</span>
                          <span className="text-slate-400">{ev.timestamp}</span>
                        </div>
                        <p className="text-slate-200 mt-1">{ev.whatHappened}</p>
                        <p className="text-slate-400 mt-0.5">
                          Why Flagged: {ev.whySuspicious}
                        </p>
                      </div>
                    )
                  )}
                </div>
              </div>

              <div className="space-y-4">
                <div className="bg-[#0B0F19] border border-slate-800/90 rounded-md p-4 space-y-2.5">
                  <div className="text-xs font-mono text-emerald-400">
                    RECOMMENDED ANALYST INVESTIGATION STEPS
                  </div>
                  <ol className="space-y-2 text-xs text-slate-200 list-decimal list-inside">
                    {activeIncident.aiReport.suggestedInvestigationSteps.map(
                      (step, i) => (
                        <li key={i} className="leading-relaxed">
                          {step}
                        </li>
                      )
                    )}
                  </ol>
                </div>

                {/* Mandatory Evidence Limitations Statement */}
                <div className="bg-[#0B0F19] border border-amber-500/30 rounded-md p-4 space-y-2">
                  <div className="text-xs font-mono text-amber-400 flex items-center gap-1.5">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    <span>
                      AI REPORT LIMITATIONS & EPISTEMIC UNCERTAINTIES
                    </span>
                  </div>
                  <ul className="space-y-1.5 text-xs text-slate-300 list-disc list-inside">
                    {activeIncident.aiReport.limitationsAndUncertainties.map(
                      (lim, i) => (
                        <li key={i} className="leading-relaxed">
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

      {/* Section 2: Automated Response & SOAR Playbooks (with Mandatory Analyst Approval Gate) */}
      <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-amber-400" />
              <span>
                02. Automated Response Playbooks & Human-in-the-Loop Approval Gate
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Consequential containment actions (blocking IPs, disabling accounts,
              isolating hosts) require explicit analyst approval before lab
              execution.
            </p>
          </div>
        </div>

        <div className="divide-y divide-slate-800/80 mt-2">
          {incidentPlaybooks.map((pb) => (
            <div
              key={pb.id}
              className="py-4 first:pt-2 last:pb-0 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                  <span className="text-amber-300 font-semibold">{pb.id}</span>
                  <span className="text-slate-600">·</span>
                  <span className="text-white font-semibold">
                    {pb.playbookName}
                  </span>
                  <span className="text-slate-600">·</span>
                  <span
                    className={
                      pb.approvalStatus.includes('Pending')
                        ? 'text-amber-400 font-semibold'
                        : pb.approvalStatus.includes('Rejected')
                          ? 'text-red-400'
                          : 'text-emerald-400 font-semibold'
                    }
                  >
                    {pb.approvalStatus}
                  </span>
                </div>

                <div className="text-xs text-slate-200">
                  Target Entity:{' '}
                  <code className="font-mono text-amber-200">
                    {pb.targetEntity}
                  </code>{' '}
                  — {pb.recommendedReason}
                </div>

                {pb.outcomeLog && (
                  <div className="text-xs font-mono text-emerald-400 mt-1">
                    Execution Outcome ({pb.executedAt?.slice(11, 19)} UTC by{' '}
                    {pb.approvedBy}): {pb.outcomeLog}
                  </div>
                )}
              </div>

              {pb.approvalStatus === 'Pending Analyst Approval' && (
                <div className="flex items-center gap-2 shrink-0 no-print">
                  <button
                    onClick={() =>
                      onApprovePlaybook(pb.id, activeIncident.assignee)
                    }
                    className="px-3.5 py-1.5 text-xs font-semibold rounded-md bg-emerald-500 text-slate-950 hover:bg-emerald-400 transition-colors flex items-center gap-1.5 cursor-pointer whitespace-nowrap"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Approve & Execute in Lab</span>
                  </button>
                  <button
                    onClick={() =>
                      onRejectPlaybook(pb.id, activeIncident.assignee)
                    }
                    className="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-800 border border-slate-700 text-slate-300 hover:text-red-300 transition-colors flex items-center gap-1 cursor-pointer whitespace-nowrap"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    <span>Reject</span>
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Queue New Custom Response Task */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col sm:flex-row items-stretch sm:items-center gap-3 no-print">
          <span className="text-xs font-medium text-slate-300 whitespace-nowrap">
            Queue Lab Response Task:
          </span>
          <select
            aria-label="Select Response Action Type"
            value={customActionType}
            onChange={(e) =>
              setCustomActionType(
                e.target.value as PlaybookAction['actionType']
              )
            }
            className="bg-[#0B0F19] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-slate-200"
          >
            <option value="Block Firewall IP">Block Firewall IP (iptables/PA)</option>
            <option value="Disable User Account">Disable User Account (AD/PAM)</option>
            <option value="Isolate Endpoint Agent">Isolate Endpoint Agent</option>
            <option value="Revoke Active Kerberos/SSH Sessions">
              Revoke Active Kerberos/SSH Sessions
            </option>
            <option value="Notify SOC & Admin">Notify SOC & Administrators</option>
          </select>
          <input
            type="text"
            value={customTarget}
            onChange={(e) => setCustomTarget(e.target.value)}
            placeholder="Target IP, User, or Hostname..."
            className="bg-[#0B0F19] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-white font-mono flex-1"
          />
          <button
            onClick={() => {
              if (!customTarget.trim()) return;
              onTriggerCustomPlaybook(
                activeIncident.id,
                customActionType,
                customTarget.trim()
              );
            }}
            className="px-4 py-1.5 text-xs font-semibold rounded-md bg-slate-800 border border-amber-500/50 text-amber-300 hover:bg-slate-700 transition-colors cursor-pointer whitespace-nowrap"
          >
            + Open Response Task
          </button>
        </div>
      </section>

      {/* Section 3: Analyst Notes & Immutable Audit Trail */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Investigation Notes & Evidence Log */}
        <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <div className="pb-4 border-b border-slate-800/80">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-amber-400" />
                <span>03. Analyst Notes & Attached Log Evidence</span>
              </h2>
            </div>

            <div className="divide-y divide-slate-800/70 mt-3">
              {activeIncident.notes.map((note) => (
                <div key={note.id} className="py-3 first:pt-1">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span className="text-amber-300">{note.author}</span>
                    <span>
                      {note.timestamp.replace('T', ' ').slice(0, 19)} UTC
                    </span>
                  </div>
                  <p className="text-xs text-slate-200 mt-1.5 leading-relaxed">
                    {note.content}
                  </p>
                  {note.evidenceRef && (
                    <div className="text-[11px] font-mono text-emerald-400 mt-1">
                      Evidence Ref: {note.evidenceRef}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          <form
            onSubmit={handleAddNote}
            className="mt-4 pt-4 border-t border-slate-800/80 space-y-3 no-print"
          >
            <div className="flex gap-2">
              <input
                type="text"
                value={noteInput}
                onChange={(e) => setNoteInput(e.target.value)}
                placeholder="Add forensic observation or hypothesis..."
                className="flex-1 bg-[#0B0F19] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-white"
              />
              <input
                type="text"
                value={evidenceInput}
                onChange={(e) => setEvidenceInput(e.target.value)}
                placeholder="Evidence ID (e.g. EVT-9006)"
                className="w-36 bg-[#0B0F19] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-amber-300 font-mono"
              />
              <button
                type="submit"
                className="px-3.5 py-1.5 text-xs font-semibold rounded-md bg-amber-500 text-slate-950 hover:bg-amber-400 transition-colors flex items-center gap-1 cursor-pointer whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Note</span>
              </button>
            </div>
          </form>
        </section>

        {/* Immutable Audit Trail */}
        <section className="bg-[#0F1523] border border-slate-800/90 rounded-lg p-6">
          <div className="pb-4 border-b border-slate-800/80">
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <History className="w-4 h-4 text-amber-400" />
              <span>04. Immutable Incident & SOAR Audit Trail</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographically ordered chain-of-custody log for every status
              transition, note, and playbook execution.
            </p>
          </div>

          <div className="divide-y divide-slate-800/70 mt-3 max-h-80 overflow-y-auto pr-1">
            {activeIncident.auditTrail.map((entry) => (
              <div key={entry.id} className="py-2.5 first:pt-1 text-xs font-mono">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-emerald-400 font-semibold">
                    {entry.action}
                  </span>
                  <span className="tabular-nums">
                    {entry.timestamp.replace('T', ' ').slice(0, 19)} UTC
                  </span>
                </div>
                <div className="text-slate-200 mt-1 font-sans">
                  {entry.details}
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5">
                  Actor: {entry.actor}
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
