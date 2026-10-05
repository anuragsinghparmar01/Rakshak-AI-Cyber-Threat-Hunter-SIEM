export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type LogSourceOS = 'Linux' | 'Windows';

export type EventOutcome = 'Success' | 'Failure' | 'Blocked' | 'Elevated' | 'Observed';

export type EventCategory =
  | 'Authentication'
  | 'PrivilegeChange'
  | 'ProcessExecution'
  | 'NetworkExfiltration'
  | 'AccountManagement'
  | 'ServiceInstallation';

export interface NormalizedLog {
  id: string;
  timestamp: string; // ISO 8601
  host: string;
  os: LogSourceOS;
  user: string;
  sourceIp: string;
  geoCountry: string;
  isUnusualGeo: boolean;
  isUnusualHour: boolean;
  category: EventCategory;
  eventCode: string; // e.g., sshd_failed, sudo_exec, EventID 4625, EventID 4672
  outcome: EventOutcome;
  processName: string;
  rawLog: string;
  normalizedSummary: string;
  assetCriticality: 'Tier-0 Crown Jewel' | 'Tier-1 Production' | 'Tier-2 Standard';
  isPrivilegedAccount: boolean;
  // Benchmark ground truth & evaluation flags
  groundTruthMalicious: boolean;
  ruleFlagged: boolean;
  anomalyScore: number; // 0 to 100 statistical UEBA anomaly score
  anomalyFlagged: boolean;
  matchedRuleId?: string;
}

export interface AgentNode {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  osFamily: LogSourceOS;
  version: string;
  status: 'Active' | 'Degraded' | 'Isolated' | 'Disconnected';
  criticality: 'Tier-0 Crown Jewel' | 'Tier-1 Production' | 'Tier-2 Standard';
  riskMultiplier: number; // e.g. 2.0x for Tier-0
  lastHeartbeatSec: number;
  eps: number; // Events per second
  cpuLoad: number;
  memUsage: number;
  privilegedUsers: string[];
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  defaultSeverity: SeverityLevel;
  baseConfidence: number; // 0 - 100
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  mitreUrl: string;
  attackStage: 'Reconnaissance & Initial Access' | 'Credential Access' | 'Privilege Escalation' | 'Lateral Movement' | 'Collection & Exfiltration';
  wazuhRuleEquivalent: string;
  evidenceCriteria: string;
  enabled: boolean;
}

export interface SecurityAlert {
  id: string;
  ruleId: string;
  ruleName: string;
  title: string;
  severity: SeverityLevel;
  confidence: number; // Separate confidence score (0-100%)
  riskScore: number; // Weighted by asset criticality and privilege
  host: string;
  assetCriticality: 'Tier-0 Crown Jewel' | 'Tier-1 Production' | 'Tier-2 Standard';
  user: string;
  isPrivilegedAccount: boolean;
  sourceIp: string;
  firstSeen: string;
  lastSeen: string;
  occurrenceCount: number; // Alert deduplication counter
  deduplicationKey: string;
  triggeringEventIds: string[];
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  mitreUrl: string;
  attackStage: string;
  xaiReasoning: {
    ruleTriggerExplanation: string;
    uebaDeviationSummary: string;
    assetRiskContext: string;
    confidenceBreakdown: { factor: string; weight: string }[];
  };
  status: 'Open' | 'Grouped in Incident' | 'Dismissed';
  incidentId?: string;
}

export type IncidentStatus = 'New' | 'Investigating' | 'Contained' | 'Resolved';

export interface IncidentNote {
  id: string;
  author: string;
  timestamp: string;
  content: string;
  evidenceRef?: string;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  details: string;
}

export interface AIInvestigationReport {
  generatedAt: string;
  modelUsed: string;
  plainEnglishSummary: string;
  triggeringEventsExplanation: {
    eventId: string;
    timestamp: string;
    whatHappened: string;
    whySuspicious: string;
  }[];
  chronologicalTimeline: {
    step: number;
    timestamp: string;
    stage: string;
    asset: string;
    actorOrIp: string;
    description: string;
  }[];
  affectedAssetsAndScope: {
    asset: string;
    criticality: string;
    impactSummary: string;
  }[];
  suggestedInvestigationSteps: string[];
  explainableAiReasoning: string;
  limitationsAndUncertainties: string[];
}

export interface Incident {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: SeverityLevel;
  confidence: number;
  assignee: string;
  createdAt: string;
  updatedAt: string;
  alertIds: string[];
  eventIds: string[];
  affectedHosts: string[];
  affectedUsers: string[];
  sourceIps: string[];
  mitreTechniques: string[];
  notes: IncidentNote[];
  auditTrail: AuditEntry[];
  aiReport?: AIInvestigationReport;
}

export interface IoCRecord {
  id: string;
  indicator: string;
  type: 'IPv4' | 'Domain' | 'SHA-256';
  reputation: 'Malicious' | 'Suspicious' | 'Clean' | 'Unknown';
  confidenceScore: number; // 0-100
  verificationStatus: 'Verified Intelligence' | 'Unverified Observation';
  source: string;
  retrievedAt: string;
  cacheStatus: 'CACHE_HIT' | 'LIVE_FETCH' | 'OFFLINE_CACHE_FALLBACK';
  asnOrRegistrar: string;
  country: string;
  threatActorOrCampaign: string;
  associatedMalware: string;
  sightingsCount: number;
  summary: string;
}

export interface PlaybookAction {
  id: string;
  incidentId: string;
  playbookName: string;
  actionType: 'Block Firewall IP' | 'Disable User Account' | 'Isolate Endpoint Agent' | 'Notify SOC & Admin' | 'Revoke Active Kerberos/SSH Sessions';
  targetEntity: string;
  recommendedReason: string;
  requiresApproval: boolean;
  approvalStatus: 'Pending Analyst Approval' | 'Approved & Executed' | 'Rejected' | 'Auto-Executed (Low Risk)';
  requestedAt: string;
  approvedBy?: string;
  executedAt?: string;
  outcomeLog?: string;
}

export interface UEBAProfile {
  user: string;
  role: string;
  isPrivileged: boolean;
  typicalHours: string;
  knownHosts: string[];
  usualCountries: string[];
  baselineDailyAuthFailures: number;
  currentSessionAuthFailures: number;
  baselinePrivilegeCommands: number;
  currentPrivilegeCommands: number;
  uebaRiskScore: number; // 0-100
  zScoreDeviation: number; // e.g. 4.2 sigma
  detectedAnomalies: string[];
}

export interface AttackChainStage {
  stageOrder: number;
  phaseName: string;
  mitreId: string;
  timestamp: string;
  host: string;
  user: string;
  sourceIp: string;
  eventId: string;
  summary: string;
  severity: SeverityLevel;
}

export interface TestCaseResult {
  id: string;
  suite: 'Log Normalizer' | 'Detection Engine' | 'Alert Deduplication' | 'UEBA Anomaly' | 'Threat Intel & Cache' | 'Integration Pipeline';
  name: string;
  description: string;
  passed: boolean;
  durationMs: number;
  assertions: number;
  expectedOutput: string;
  actualOutput: string;
}
