Rakshak — Explainable AI Cyber Threat Hunter, SIEM & SOAR Platform
Tagline: Always Watching, Always Protecting
Problem Statement
Security analysts face thousands of raw log lines daily across heterogeneous Linux and Windows environments. Traditional static rules miss low-and-slow behavioral anomalies, while purely statistical anomaly detectors generate high false positives without explaining why an alert triggered. Furthermore, automated response tools risk disrupting production infrastructure if executed without human oversight.
Solution Overview
Rakshak bridges deterministic SIEM rule correlation, statistical User & Entity Behavior Analytics (UEBA), Explainable AI (XAI) forensics, and Human-in-the-Loop SOAR into a single, intuitive 9-module command sanctum:
Real-Time Security Monitoring (Module 01)
Monitors live security events, event velocity (EPS), authentication failures, and connected Linux/Windows agent health.
Multi-dimensional filtering by Host, Time Window, User, Source IP, and Severity, plus 1-click guided attack scenario simulations.
Log Collection & Wazuh-Pattern Normalization (Module 02)
Ingests sample packets, pasted raw logs, or uploaded .log/.txt files across Linux (/var/log/auth.log, sshd, sudo, PAM, UFW) and Windows Security Auditing (EventID 4624, 4625, 4672, 4720).
Normalizes heterogeneous logs into a unified schema while preserving original timestamps and correlating across users, hosts, and time windows.
Threat Detection Engine, Attack Chains & UEBA (Module 03)
Detects brute-force attacks, post-failure compromises, off-hours/foreign-ASN logins, and suspicious privilege escalations.
Separates Severity (business impact weighted by Tier-0/Tier-1 asset criticality) from Confidence (%) (detection certainty).
Performs Alert Deduplication and Attack-Chain Reconstruction across multi-host intrusion stages.
Signature Explainable AI (XAI) & Natural-Language Threat Hunting (Module 04)
Summarizes complex incidents in plain English, explains every triggering event, constructs a chronological timeline, and recommends actionable investigation steps.
Explicitly documents Epistemic Limitations & Uncertainties (e.g., encrypted payload visibility, VPN/Tor exit attribution) to prevent analyst over-reliance.
Supports Natural-Language Threat Hunting, converting plain-English questions into executable correlation queries.
MITRE ATT&CK Mapping & Threat Intelligence Enrichment (Module 05)
Maps all detection rules to official MITRE ATT&CK Enterprise v16 tactics and techniques (T1110.001, T1078, T1548.003, T1059.001, T1098).
Enriches IPs, domains, and SHA-256 hashes with reputation scores, source provenance, local caching, graceful offline fallback, and strict separation between Verified Intelligence and Unverified Observations.
Incident Management & SOAR Playbooks (Module 06)
Supports multi-alert incident creation, analyst assignment, status tracking (New, Investigating, Contained, Resolved), forensic notes, immutable audit trails, and printable PDF Incident Dossiers.
Recommends automated SOAR playbooks (Firewall IP Block, AD Account Disable, Host Isolation) with a mandatory Analyst Approval Gate for consequential actions.
Evaluation, Benchmarks & Automated Testing (Module 07)
Evaluates Precision, Recall, F1-Score, and False-Positive Rate (FPR) over a labelled dataset of benign and malicious events.
Benchmarks Rule-Based Detection vs. UEBA Anomaly Model vs. Rakshak Hybrid Ensemble, accompanied by an in-browser Unit & Integration Test Runner and interactive REST API Playground.
Platform & AI Engine Settings (Module 08)
Provides real-time tuning for deduplication windows, brute-force thresholds, UEBA Z-score cutoffs, Tier-0 Crown Jewel multipliers, and server-side AI engine diagnostics.
