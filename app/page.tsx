'use client';

import React, { useState, useEffect } from 'react';
import {
  Activity,
  Terminal,
  ShieldAlert,
  Sparkles,
  Crosshair,
  FileText,
  BarChart3,
  Settings,
  LayoutGrid,
  Flame,
  PlusCircle,
} from 'lucide-react';
import DivineGuardianIntro from '@/components/DivineGuardianIntro';
import CommandCenterPage from '@/components/CommandCenterPage';
import OverviewMonitor from '@/components/OverviewMonitor';
import LogExplorer from '@/components/LogExplorer';
import DetectionAndUebaPage from '@/components/DetectionAndUebaPage';
import AiThreatHunterPage from '@/components/AiThreatHunterPage';
import IncidentsAndPlaybooks from '@/components/IncidentsAndPlaybooks';
import MitreAndIntel from '@/components/MitreAndIntel';
import EvaluationAndDocs from '@/components/EvaluationAndDocs';
import SettingsPage from '@/components/SettingsPage';
import {
  AIInvestigationReport,
  AgentNode,
  DetectionRule,
  Incident,
  IncidentStatus,
  IoCRecord,
  NormalizedLog,
  PlaybookAction,
  SecurityAlert,
  UEBAProfile,
} from '@/lib/types';
import {
  DETECTION_RULES,
  INITIAL_AGENTS,
  INITIAL_ALERTS,
  INITIAL_INCIDENTS,
  INITIAL_IOC_DATABASE,
  INITIAL_LOGS,
  INITIAL_PLAYBOOKS,
  INITIAL_UEBA_PROFILES,
} from '@/lib/security-data';
import {
  deduplicateAndCorrelateLogsToAlerts,
  normalizeRawLogBatch,
  normalizeSingleLogLine,
} from '@/lib/detection-engine';

const SYNTHETIC_LIVE_EVENTS = [
  'Oct  1 07:22:11 auth-sso-01 sshd[31901]: Failed password for admin_akhtar from 185.220.101.44 port 59102 ssh2',
  'WinEventLog: Security: AUDIT_FAILURE(4625): An account failed to log on. Subject: svc-backup, Logon Type: 10, Source Network Address: 91.214.124.88, Failure Reason: Bad password.',
  'Oct  1 07:23:04 prd-db-01 sudo[32110]: admin_akhtar : TTY=pts/3 ; PWD=/etc ; USER=root ; COMMAND=/usr/bin/cat /etc/sudoers',
  'WinEventLog: Security: AUDIT_SUCCESS(4672): Special privileges assigned to new logon. Account Name: svc-backup, Privileges: SeDebugPrivilege',
  'Oct  1 07:24:19 k8s-ingress-02 sshd[33012]: Accepted publickey for kube-admin from 10.10.30.10 port 44120 ssh2',
];

const WORKSPACE_PAGES = [
  {
    id: 'overview',
    code: '00',
    label: 'Command Center',
    sublabel: 'Executive Overview & Guide',
    icon: LayoutGrid,
  },
  {
    id: 'monitor',
    code: '01',
    label: 'Real-Time Monitor',
    sublabel: 'Live Stream, Filters & Agents',
    icon: Activity,
  },
  {
    id: 'logs',
    code: '02',
    label: 'Log Collection & Analysis',
    sublabel: 'Wazuh Normalizer & Correlator',
    icon: Terminal,
  },
  {
    id: 'detection',
    code: '03',
    label: 'Detection, Chains & UEBA',
    sublabel: 'Rules, Deduplication & Z-Score',
    icon: ShieldAlert,
  },
  {
    id: 'ai-hunter',
    code: '04',
    label: 'AI Threat Hunter',
    sublabel: 'Explainable AI & NL Hunting',
    icon: Sparkles,
  },
  {
    id: 'mitre',
    code: '05',
    label: 'MITRE ATT&CK & Intel',
    sublabel: 'Kill-Chain & Resilient IoCs',
    icon: Crosshair,
  },
  {
    id: 'incidents',
    code: '06',
    label: 'Incidents & SOAR',
    sublabel: 'Case Workflow, PDF & Playbooks',
    icon: FileText,
  },
  {
    id: 'evaluation',
    code: '07',
    label: 'Evaluation & Benchmarks',
    sublabel: 'Precision/Recall, Tests & API',
    icon: BarChart3,
  },
  {
    id: 'settings',
    code: '08',
    label: 'Settings & AI Engine',
    sublabel: 'API Key Setup & Thresholds',
    icon: Settings,
  },
];

export default function RakshakHomePage() {
  const [showIntro, setShowIntro] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [logs, setLogs] = useState<NormalizedLog[]>(INITIAL_LOGS);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
  const [agents, setAgents] = useState<AgentNode[]>(INITIAL_AGENTS);
  const [rules, setRules] = useState<DetectionRule[]>(DETECTION_RULES);
  const [incidents, setIncidents] = useState<Incident[]>(INITIAL_INCIDENTS);
  const [selectedIncidentId, setSelectedIncidentId] =
    useState<string>('INC-2026-089');
  const [iocs, setIocs] = useState<IoCRecord[]>(INITIAL_IOC_DATABASE);
  const [playbooks, setPlaybooks] =
    useState<PlaybookAction[]>(INITIAL_PLAYBOOKS);
  const [uebaProfiles] = useState<UEBAProfile[]>(INITIAL_UEBA_PROFILES);

  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [syntheticIdx, setSyntheticIdx] = useState<number>(0);

  const handleInjectLiveEvent = () => {
    const rawSample =
      SYNTHETIC_LIVE_EVENTS[syntheticIdx % SYNTHETIC_LIVE_EVENTS.length];
    setSyntheticIdx((prev) => prev + 1);
    const newLog = normalizeSingleLogLine(rawSample);
    setLogs((prev) => [newLog, ...prev]);
    setAlerts((prev) => deduplicateAndCorrelateLogsToAlerts([newLog], prev));
  };

  useEffect(() => {
    if (!isStreaming) return;
    const timer = setInterval(() => {
      const rawSample =
        SYNTHETIC_LIVE_EVENTS[
          Math.floor(Math.random() * SYNTHETIC_LIVE_EVENTS.length)
        ];
      const newLog = normalizeSingleLogLine(rawSample);
      setLogs((prev) => [newLog, ...prev.slice(0, 49)]);
      setAlerts((prev) => deduplicateAndCorrelateLogsToAlerts([newLog], prev));
    }, 6000);
    return () => clearInterval(timer);
  }, [isStreaming]);

  const handleIngestRawLogs = (rawText: string) => {
    const batch = normalizeRawLogBatch(rawText);
    setLogs((prev) => [...batch, ...prev]);
    setAlerts((prev) => deduplicateAndCorrelateLogsToAlerts(batch, prev));
  };

  const handleInvestigateAlert = (alert: SecurityAlert) => {
    if (alert.incidentId) {
      setSelectedIncidentId(alert.incidentId);
      setActiveTab('ai-hunter');
      return;
    }
    handleCreateIncidentFromAlert(alert);
  };

  const handleCreateIncidentFromAlert = (alert: SecurityAlert) => {
    const newIncidentId = `INC-2026-${Math.floor(100 + Math.random() * 899)}`;
    const now = new Date().toISOString();
    const newInc: Incident = {
      id: newIncidentId,
      title: alert.title,
      status: 'Investigating',
      severity: alert.severity,
      confidence: alert.confidence,
      assignee: 'A. Sharma (Tier-3 Threat Hunt Lead)',
      createdAt: now,
      updatedAt: now,
      alertIds: [alert.id],
      eventIds: alert.triggeringEventIds,
      affectedHosts: [alert.host],
      affectedUsers: [alert.user],
      sourceIps: [alert.sourceIp],
      mitreTechniques: [alert.mitreTechniqueId],
      notes: [
        {
          id: `N-${Date.now()}`,
          author: 'Rakshak SOC Analyst',
          timestamp: now,
          content: `Escalated deduplicated alert ${alert.id} (${alert.occurrenceCount} occurrences) to formal incident investigation.`,
          evidenceRef: alert.triggeringEventIds.join(', '),
        },
      ],
      auditTrail: [
        {
          id: `AUD-${Date.now()}`,
          timestamp: now,
          actor: 'A. Sharma (Tier-3 Threat Hunt Lead)',
          action: 'INCIDENT_ESCALATED',
          details: `Created incident ${newIncidentId} from alert ${alert.id}.`,
        },
      ],
    };

    setIncidents((prev) => [newInc, ...prev]);
    setAlerts((prev) =>
      prev.map((a) =>
        a.id === alert.id
          ? { ...a, status: 'Grouped in Incident', incidentId: newIncidentId }
          : a
      )
    );
    setSelectedIncidentId(newIncidentId);
    setActiveTab('incidents');
  };

  const handleCreateIncidentFromMultipleAlerts = (
    selectedAlerts: SecurityAlert[]
  ) => {
    if (selectedAlerts.length === 0) return;
    if (selectedAlerts.length === 1) {
      handleCreateIncidentFromAlert(selectedAlerts[0]);
      return;
    }

    const newIncidentId = `INC-2026-${Math.floor(100 + Math.random() * 899)}`;
    const now = new Date().toISOString();
    const allAlertIds = selectedAlerts.map((a) => a.id);
    const allEventIds = Array.from(
      new Set(selectedAlerts.flatMap((a) => a.triggeringEventIds))
    );
    const allHosts = Array.from(new Set(selectedAlerts.map((a) => a.host)));
    const allUsers = Array.from(new Set(selectedAlerts.map((a) => a.user)));
    const allIps = Array.from(new Set(selectedAlerts.map((a) => a.sourceIp)));
    const allMitre = Array.from(
      new Set(selectedAlerts.map((a) => a.mitreTechniqueId))
    );
    const maxConfidence = Math.max(...selectedAlerts.map((a) => a.confidence));
    const hasCritical = selectedAlerts.some((a) => a.severity === 'Critical');

    const newInc: Incident = {
      id: newIncidentId,
      title: `Correlated Multi-Alert Incident (${selectedAlerts.length} Alerts across ${allHosts.map((h) => h.split('.')[0]).join(', ')})`,
      status: 'Investigating',
      severity: hasCritical ? 'Critical' : 'High',
      confidence: maxConfidence,
      assignee: 'A. Sharma (Tier-3 Threat Hunt Lead)',
      createdAt: now,
      updatedAt: now,
      alertIds: allAlertIds,
      eventIds: allEventIds,
      affectedHosts: allHosts,
      affectedUsers: allUsers,
      sourceIps: allIps,
      mitreTechniques: allMitre,
      notes: [
        {
          id: `N-${Date.now()}`,
          author: 'Rakshak SOC Analyst',
          timestamp: now,
          content: `Grouped ${selectedAlerts.length} alerts (${allAlertIds.join(', ')}) into a unified multi-stage incident investigation.`,
          evidenceRef: allEventIds.join(', '),
        },
      ],
      auditTrail: [
        {
          id: `AUD-${Date.now()}`,
          timestamp: now,
          actor: 'A. Sharma (Tier-3 Threat Hunt Lead)',
          action: 'MULTI_ALERT_INCIDENT_CREATED',
          details: `Correlated alerts ${allAlertIds.join(', ')} into ${newIncidentId}.`,
        },
      ],
    };

    setIncidents((prev) => [newInc, ...prev]);
    setAlerts((prev) =>
      prev.map((a) =>
        allAlertIds.includes(a.id)
          ? { ...a, status: 'Grouped in Incident', incidentId: newIncidentId }
          : a
      )
    );
    setSelectedIncidentId(newIncidentId);
    setActiveTab('incidents');
  };

  const handleResetLabState = () => {
    setLogs(INITIAL_LOGS);
    setAlerts(INITIAL_ALERTS);
    setAgents(INITIAL_AGENTS);
    setRules(DETECTION_RULES);
    setIncidents(INITIAL_INCIDENTS);
    setSelectedIncidentId('INC-2026-089');
    setIocs(INITIAL_IOC_DATABASE);
    setPlaybooks(INITIAL_PLAYBOOKS);
    setIsStreaming(false);
  };

  const handleToggleIsolateAgent = (agentId: string) => {
    setAgents((prev) =>
      prev.map((ag) => {
        if (ag.id !== agentId) return ag;
        const nextStatus = ag.status === 'Isolated' ? 'Active' : 'Isolated';
        return {
          ...ag,
          status: nextStatus,
          eps: nextStatus === 'Isolated' ? 0 : 140,
        };
      })
    );
  };

  const handleUpdateIncidentStatus = (id: string, status: IncidentStatus) => {
    const now = new Date().toISOString();
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === id
          ? {
              ...inc,
              status,
              updatedAt: now,
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: inc.assignee,
                  action: 'STATUS_CHANGED',
                  details: `Transitioned incident status from ${inc.status} to ${status}.`,
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleUpdateIncidentAssignee = (id: string, assignee: string) => {
    const now = new Date().toISOString();
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === id
          ? {
              ...inc,
              assignee,
              updatedAt: now,
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: 'SOC Lead',
                  action: 'ANALYST_ASSIGNED',
                  details: `Reassigned incident ownership to ${assignee}.`,
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleAddIncidentNote = (
    id: string,
    author: string,
    content: string,
    evidenceRef?: string
  ) => {
    const now = new Date().toISOString();
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === id
          ? {
              ...inc,
              updatedAt: now,
              notes: [
                ...inc.notes,
                {
                  id: `N-${Date.now()}`,
                  author,
                  timestamp: now,
                  content,
                  evidenceRef,
                },
              ],
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: author,
                  action: 'NOTE_ADDED',
                  details: `Added forensic note referencing ${evidenceRef || 'general investigation'}.`,
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleSaveAiReport = (
    incidentId: string,
    report: AIInvestigationReport
  ) => {
    const now = new Date().toISOString();
    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === incidentId
          ? {
              ...inc,
              aiReport: report,
              updatedAt: now,
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: 'Rakshak Gemini 3.8 XAI Engine',
                  action: 'AI_REPORT_GENERATED',
                  details:
                    'Synthesized structured forensic report, timeline, and epistemic limitations.',
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleApprovePlaybook = (playbookId: string, approver: string) => {
    const now = new Date().toISOString();
    const targetPb = playbooks.find((p) => p.id === playbookId);
    if (!targetPb) return;

    setPlaybooks((prev) =>
      prev.map((p) =>
        p.id === playbookId
          ? {
              ...p,
              approvalStatus: 'Approved & Executed',
              approvedBy: approver,
              executedAt: now,
              outcomeLog: `Lab SOAR Execution Succeeded: Applied ${p.actionType} on ${p.targetEntity} (Exit Code 0).`,
            }
          : p
      )
    );

    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === targetPb.incidentId
          ? {
              ...inc,
              status: inc.status === 'New' ? 'Contained' : inc.status,
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: approver,
                  action: 'PLAYBOOK_APPROVED_AND_EXECUTED',
                  details: `Approved ${targetPb.id} (${targetPb.actionType}) targeting ${targetPb.targetEntity}. Outcome: Lab rule enforced.`,
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleRejectPlaybook = (playbookId: string, approver: string) => {
    const now = new Date().toISOString();
    const targetPb = playbooks.find((p) => p.id === playbookId);
    if (!targetPb) return;

    setPlaybooks((prev) =>
      prev.map((p) =>
        p.id === playbookId
          ? {
              ...p,
              approvalStatus: 'Rejected',
              approvedBy: approver,
              executedAt: now,
              outcomeLog: `Action cancelled by analyst ${approver}.`,
            }
          : p
      )
    );

    setIncidents((prev) =>
      prev.map((inc) =>
        inc.id === targetPb.incidentId
          ? {
              ...inc,
              auditTrail: [
                {
                  id: `AUD-${Date.now()}`,
                  timestamp: now,
                  actor: approver,
                  action: 'PLAYBOOK_REJECTED',
                  details: `Rejected ${targetPb.id} (${targetPb.actionType}) on ${targetPb.targetEntity}.`,
                },
                ...inc.auditTrail,
              ],
            }
          : inc
      )
    );
  };

  const handleTriggerCustomPlaybook = (
    incidentId: string,
    actionType: PlaybookAction['actionType'],
    targetEntity: string
  ) => {
    const now = new Date().toISOString();
    const newPb: PlaybookAction = {
      id: `PB-0${playbooks.length + 1}`,
      incidentId,
      playbookName: `SOAR-CUSTOM: ${actionType}`,
      actionType,
      targetEntity,
      recommendedReason:
        'Queued manually by SOC analyst during active threat investigation.',
      requiresApproval: actionType !== 'Notify SOC & Admin',
      approvalStatus:
        actionType === 'Notify SOC & Admin'
          ? 'Auto-Executed (Low Risk)'
          : 'Pending Analyst Approval',
      requestedAt: now,
      approvedBy:
        actionType === 'Notify SOC & Admin' ? 'Rakshak Auto-Policy' : undefined,
      executedAt: actionType === 'Notify SOC & Admin' ? now : undefined,
      outcomeLog:
        actionType === 'Notify SOC & Admin'
          ? `Dispatched high-priority notification to ${targetEntity}.`
          : undefined,
    };

    setPlaybooks((prev) => [newPb, ...prev]);
  };

  const handleAddOrEnrichIoc = (indicator: string, isOfflineMode: boolean) => {
    const existing = iocs.find(
      (i) => i.indicator.toLowerCase() === indicator.toLowerCase()
    );
    if (existing) {
      setIocs((prev) =>
        prev.map((i) =>
          i.id === existing.id
            ? {
                ...i,
                sightingsCount: i.sightingsCount + 1,
                retrievedAt: new Date().toISOString(),
                cacheStatus: isOfflineMode
                  ? 'OFFLINE_CACHE_FALLBACK'
                  : 'CACHE_HIT',
              }
            : i
        )
      );
      return;
    }

    const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(indicator);
    const isHash = indicator.length >= 32 && !indicator.includes('.');
    const newRecord: IoCRecord = {
      id: `IOC-0${iocs.length + 1}`,
      indicator,
      type: isIp ? 'IPv4' : isHash ? 'SHA-256' : 'Domain',
      reputation: isOfflineMode ? 'Suspicious' : 'Malicious',
      confidenceScore: isOfflineMode ? 68 : 89,
      verificationStatus: isOfflineMode
        ? 'Unverified Observation'
        : 'Verified Intelligence',
      source: isOfflineMode
        ? 'Rakshak Local Telemetry Cache (External API Offline)'
        : 'AbuseIPDB + VirusTotal Live Enrichment',
      retrievedAt: new Date().toISOString(),
      cacheStatus: isOfflineMode ? 'OFFLINE_CACHE_FALLBACK' : 'LIVE_FETCH',
      asnOrRegistrar: isIp
        ? 'AS4134 External Transit'
        : 'External DNS / File Artifact',
      country: 'External',
      threatActorOrCampaign: isOfflineMode
        ? 'Unverified Local Sighting'
        : 'Correlated Scanner / C2 Node',
      associatedMalware: 'Heuristic Match',
      sightingsCount: 1,
      summary: isOfflineMode
        ? 'External threat feeds unreachable; enriched via local Rakshak heuristic cache as an Unverified Observation.'
        : 'Enriched via live threat intelligence feeds and stored in local resilient cache.',
    };

    setIocs((prev) => [newRecord, ...prev]);
  };

  const handleToggleRule = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r))
    );
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#07090F] text-slate-100">
      {/* Fierce Lord Kaal Bhairav & Mahakali Trishul Opening Animation */}
      <DivineGuardianIntro
        isOpen={showIntro}
        onComplete={() => setShowIntro(false)}
      />

      {/* Strict 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between px-6 py-3.5 border-b border-slate-800/90 bg-[#07090F]/95 sticky top-0 z-30 backdrop-blur no-print">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('overview');
          }}
          className="font-display text-xl font-bold tracking-[0.16em] text-amber-400 whitespace-nowrap"
        >
          RAKSHAK
        </a>

        {/* Zone 2: 5 clean text navigation links */}
        <nav className="hidden lg:flex items-center gap-7 text-xs font-medium">
          {[
            { id: 'overview', label: 'Command Center' },
            { id: 'monitor', label: 'Live Monitor' },
            { id: 'ai-hunter', label: 'AI Threat Hunter' },
            { id: 'incidents', label: 'Incidents & SOAR' },
            { id: 'settings', label: 'Settings' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`py-1 transition-colors whitespace-nowrap cursor-pointer border-b-2 ${
                activeTab === item.id
                  ? 'text-amber-400 border-amber-400 font-semibold'
                  : 'text-slate-400 border-transparent hover:text-slate-100'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Zone 3: 2 primary actions */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setShowIntro(true)}
            className="px-3 py-1.5 text-xs font-medium text-rose-200 bg-rose-950/70 border border-rose-500/50 rounded-md hover:bg-rose-900/80 transition-colors whitespace-nowrap cursor-pointer flex items-center gap-1.5"
          >
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            <span>Trishul Intro</span>
          </button>
          <button
            onClick={handleInjectLiveEvent}
            className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-amber-500 rounded-md hover:bg-amber-400 transition-colors whitespace-nowrap cursor-pointer flex items-center gap-1.5"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Simulate Threat</span>
          </button>
        </div>
      </header>

      {/* Mobile Horizontal Page Selector */}
      <div className="flex xl:hidden items-center gap-1.5 overflow-x-auto px-4 py-2.5 border-b border-slate-800 bg-[#0B0E17] no-print">
        {WORKSPACE_PAGES.map((page) => (
          <button
            key={page.id}
            onClick={() => setActiveTab(page.id)}
            className={`px-3 py-1.5 text-xs rounded-md whitespace-nowrap cursor-pointer transition-colors ${
              activeTab === page.id
                ? 'bg-amber-500 text-slate-950 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {page.code}. {page.label}
          </button>
        ))}
      </div>

      {/* Main Workspace Container: Left Sidebar + Page Viewport */}
      <div className="flex-1 flex w-full max-w-[1600px] mx-auto">
        {/* Structured Left Sidebar for All 9 Pages (Desktop) */}
        <aside className="hidden xl:flex flex-col w-64 shrink-0 border-r border-slate-800/80 bg-[#090C15] p-4 justify-between no-print">
          <div className="space-y-1">
            <div className="px-3 py-2 text-[11px] font-mono text-slate-400 tracking-wider">
              RAKSHAK WORKSPACE PAGES
            </div>
            {WORKSPACE_PAGES.map((page) => {
              const IconComp = page.icon;
              const isActive = activeTab === page.id;
              return (
                <button
                  key={page.id}
                  onClick={() => setActiveTab(page.id)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex items-start gap-3 cursor-pointer ${
                    isActive
                      ? 'bg-amber-500/15 border border-amber-500/40 text-amber-300'
                      : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200 border border-transparent'
                  }`}
                >
                  <IconComp
                    className={`w-4 h-4 mt-0.5 shrink-0 ${
                      isActive ? 'text-amber-400' : 'text-slate-500'
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="text-xs font-semibold truncate">
                      {page.code}. {page.label}
                    </div>
                    <div className="text-[11px] text-slate-500 truncate mt-0.5">
                      {page.sublabel}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          <div className="p-3.5 rounded-lg bg-[#0D121F] border border-slate-800/90 space-y-2 text-xs">
            <div className="font-mono text-[11px] text-amber-400 font-semibold">
              GUARDIAN STATUS
            </div>
            <div className="text-slate-300 text-[11px] leading-relaxed">
              Kaal Bhairav Temporal Correlation & Mahakali SOAR Containment
              active across {agents.length} hosts.
            </div>
            <button
              onClick={() => setActiveTab('settings')}
              className="w-full py-1.5 text-center text-[11px] font-mono rounded bg-slate-800 hover:bg-slate-700 text-amber-300 transition-colors cursor-pointer"
            >
              Open AI & Engine Settings
            </button>
          </div>
        </aside>

        {/* Active Page Viewport */}
        <main className="flex-1 min-w-0 px-4 sm:px-6 lg:px-8 py-7">
          {activeTab === 'overview' && (
            <CommandCenterPage
              logs={logs}
              alerts={alerts}
              agents={agents}
              incidents={incidents}
              iocs={iocs}
              playbooks={playbooks}
              onNavigateTab={setActiveTab}
              onReplayIntro={() => setShowIntro(true)}
              onInjectLiveEvent={handleInjectLiveEvent}
            />
          )}

          {activeTab === 'monitor' && (
            <OverviewMonitor
              logs={logs}
              alerts={alerts}
              agents={agents}
              isStreaming={isStreaming}
              onToggleStream={() => setIsStreaming((prev) => !prev)}
              onInjectLiveEvent={handleInjectLiveEvent}
              onInvestigateAlert={handleInvestigateAlert}
              onCreateIncidentFromAlert={handleCreateIncidentFromAlert}
              onCreateIncidentFromMultipleAlerts={
                handleCreateIncidentFromMultipleAlerts
              }
              onToggleIsolateAgent={handleToggleIsolateAgent}
              onNavigateTab={setActiveTab}
            />
          )}

          {activeTab === 'logs' && (
            <LogExplorer logs={logs} onIngestRawLogs={handleIngestRawLogs} />
          )}

          {activeTab === 'detection' && (
            <DetectionAndUebaPage
              logs={logs}
              alerts={alerts}
              rules={rules}
              uebaProfiles={uebaProfiles}
              onToggleRule={handleToggleRule}
              onInvestigateAlert={handleInvestigateAlert}
              onCreateIncidentFromAlert={handleCreateIncidentFromAlert}
              onCreateIncidentFromMultipleAlerts={
                handleCreateIncidentFromMultipleAlerts
              }
            />
          )}

          {activeTab === 'ai-hunter' && (
            <AiThreatHunterPage
              incidents={incidents}
              logs={logs}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              onSaveAiReport={handleSaveAiReport}
            />
          )}

          {activeTab === 'mitre' && (
            <MitreAndIntel
              rules={rules}
              alerts={alerts}
              iocs={iocs}
              uebaProfiles={uebaProfiles}
              onAddOrEnrichIoc={handleAddOrEnrichIoc}
              onToggleRule={handleToggleRule}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentsAndPlaybooks
              incidents={incidents}
              logs={logs}
              playbooks={playbooks}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              onUpdateIncidentStatus={handleUpdateIncidentStatus}
              onUpdateIncidentAssignee={handleUpdateIncidentAssignee}
              onAddIncidentNote={handleAddIncidentNote}
              onSaveAiReport={handleSaveAiReport}
              onApprovePlaybook={handleApprovePlaybook}
              onRejectPlaybook={handleRejectPlaybook}
              onTriggerCustomPlaybook={handleTriggerCustomPlaybook}
            />
          )}

          {activeTab === 'evaluation' && (
            <EvaluationAndDocs
              logs={logs}
              onResetLabState={handleResetLabState}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsPage
              onReplayIntro={() => setShowIntro(true)}
              onResetLabState={handleResetLabState}
            />
          )}
        </main>
      </div>

      {/* Quiet, Clean Footer */}
      <footer className="border-t border-slate-800/80 py-4 px-6 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 max-w-[1600px] w-full mx-auto no-print">
        <div>
          Rakshak Cyber Threat Hunter · Always Watching, Always Protecting
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setActiveTab('evaluation')}
            className="hover:text-slate-300 transition-colors cursor-pointer"
          >
            Evaluation & API Docs
          </button>
          <span aria-hidden="true">·</span>
          <button
            onClick={() => setActiveTab('settings')}
            className="hover:text-slate-300 transition-colors cursor-pointer"
          >
            Platform & AI Settings
          </button>
        </div>
      </footer>
    </div>
  );
}
