use crate::models::{ForensicEvent, TemporalBurst};

pub struct PromptBuilder {
    max_token_budget_chars: usize,
}

impl PromptBuilder {
    pub fn new(max_token_budget_chars: usize) -> Self {
        Self {
            max_token_budget_chars,
        }
    }

    /// Builds a prompt for `gemini-3.5-flash-lite` for ultra-fast event classification & burst triage
    pub fn build_rapid_triage_prompt(
        &self,
        events: &[ForensicEvent],
        bursts: &[TemporalBurst],
    ) -> String {
        let suspicious_events: Vec<&ForensicEvent> = events
            .iter()
            .filter(|e| e.is_suspicious || e.anomaly_score >= 0.5)
            .take(60)
            .collect();

        let mut burst_summary = String::new();
        for b in bursts.iter().take(5) {
            burst_summary.push_str(&format!(
                "- Burst #{}: Start={}, End={}, EventCount={}, Score={:.2}, Dominant={:?}, {}\n",
                b.id,
                b.start_time.to_rfc3339(),
                b.end_time.to_rfc3339(),
                b.event_count,
                b.anomaly_score,
                b.dominant_source,
                b.summary
            ));
        }

        let mut event_table = String::new();
        for ev in suspicious_events {
            event_table.push_str(&format!(
                "[{}] [{}] [{}] Score={:.2} | {}\n",
                ev.timestamp.to_rfc3339(),
                ev.source.as_str(),
                ev.macb.to_macb_string(),
                ev.anomaly_score,
                ev.summary
            ));
        }

        format!(
r#"SYSTEM: You are the CHRONO-SHARD Rapid Forensic Triage Engine powered by Google Gemini 3.5 Flash Lite.
OBJECTIVE: Perform lightning-fast triage on these high-anomaly endpoint telemetry bursts and suspicious events.

TEMPORAL BURSTS DETECTED:
{}

HIGH-ANOMALY FORENSIC EVENTS (Sample):
{}

REQUIRED OUTPUT FORMAT (Plain text with clear headers):
=== TRIAGE SUMMARY ===
[1-2 paragraphs identifying if an active attack is occurring and the primary threat vector]

=== ANOMALOUS BURST ANALYSIS ===
[Brief explanation of why the detected temporal bursts indicate malicious automated activity]

=== THREAT LEVEL ===
[CRITICAL / HIGH / MEDIUM / LOW] (Score: 0-100)

=== IMMEDIATE ISOLATION RECOMMENDATIONS ===
[3 bullet points of immediate forensic containment actions]
"#,
            if burst_summary.is_empty() { "No severe bursts detected." } else { &burst_summary },
            if event_table.is_empty() { "No highly anomalous individual events." } else { &event_table }
        )
    }

    /// Builds a prompt for `gemini-4-carbon` for deep kill-chain synthesis and timeline reconstruction
    pub fn build_killchain_synthesis_prompt(
        &self,
        events: &[ForensicEvent],
        bursts: &[TemporalBurst],
    ) -> String {
        // Prioritize: 1. Bursts, 2. Suspicious/MITRE tagged events, 3. Chronological context
        let mut prioritized_events: Vec<&ForensicEvent> = events.iter().collect();
        // Sort by anomaly score descending to select top contributors within budget
        prioritized_events.sort_by(|a, b| {
            b.anomaly_score
                .partial_cmp(&a.anomaly_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Retain top 120 most significant events, then re-sort chronologically
        let mut selected_events: Vec<&ForensicEvent> =
            prioritized_events.into_iter().take(120).collect();
        selected_events.sort_by_key(|e| e.timestamp);

        let mut timeline_block = String::new();
        let mut budget_left = self.max_token_budget_chars;

        for ev in selected_events {
            let line = format!(
                "TIME: {} | SRC: {:<10} | MACB: {} | TACTIC: {:?} | ANOMALY: {:.2}\n  TARGET: {}\n  SUMMARY: {}\n  RAW: {}\n---\n",
                ev.timestamp.to_rfc3339(),
                ev.source.as_str(),
                ev.macb.to_macb_string(),
                ev.tactic.map(|t| t.name()).unwrap_or("None"),
                ev.anomaly_score,
                ev.path_or_target.as_deref().unwrap_or("N/A"),
                ev.summary,
                &ev.raw_artifact.replace('\n', " | ")[..ev.raw_artifact.len().min(160)]
            );

            if line.len() > budget_left {
                break;
            }
            budget_left -= line.len();
            timeline_block.push_str(&line);
        }

        let mut bursts_block = String::new();
        for b in bursts {
            bursts_block.push_str(&format!(
                "- Burst ID {}: Span {} to {} | Count: {} | Anomaly: {:.2} | Details: {}\n",
                b.id,
                b.start_time.to_rfc3339(),
                b.end_time.to_rfc3339(),
                b.event_count,
                b.anomaly_score,
                b.summary
            ));
        }

        format!(
r#"SYSTEM ROLE: You are the Principal DFIR Architect and Cyber Threat Intelligence Specialist operating CHRONO-SHARD with Gemini 4 Carbon.
OBJECTIVE: Reconstruct a complete MITRE ATT&CK Kill-Chain timeline, determine root cause, identify timestomping and evasion tactics, extract IOCs, and deliver an incident response narrative from the correlated forensic timeline below.

TEMPORAL BURSTS IDENTIFIED:
{}

CORRELATED CHRONOLOGICAL FORENSIC TIMELINE (MACB + Logs + Shell + Persistence + Browser):
{}

DELIVER A COMPREHENSIVE DFIR INCIDENT REPORT IN THE FOLLOWING FORMAT:

# INCIDENT OVERVIEW & EXECUTIVE SUMMARY
- Threat Assessment & Confidence
- Suspected Threat Actor / Methodology
- Primary Vector of Entry

# MITRE ATT&CK KILL-CHAIN MAPPING
Map every phase evidenced in the artifacts:
1. **Initial Access**: (Identify entry point, browser downloads, phishing or SSH ingress)
2. **Execution**: (Command line executions, malicious scripts dropped in temp)
3. **Persistence**: (Cron schedules, systemd service units, SSH keys injected)
4. **Privilege Escalation**: (Sudo abuse, SUID binaries, token manipulation)
5. **Defense Evasion**: (Timestomping detected via MACB, log clearing `history -c`, hidden dotfiles)
6. **Command and Control / Exfiltration**: (Network endpoints, reverse shells, beacons)

# ROOT CAUSE ANALYSIS & TIMELINE OF COMPROMISE
- Detail the exact step-by-step chronological sequence of attacker activity.
- Explain the forensic significance of the MACB timestamps and anomalous temporal bursts.

# INDICATORS OF COMPROMISE (IOCs)
- **Filesystem Paths & Drops**:
- **Commands & Scripts**:
- **Network IPs & URLs**:
- **Persistence Hooks**:

# REMEDIATION & CONTAINMENT PLAYBOOK
1. Immediate containment actions
2. Eradication & removal steps
3. System hardening & detection engineering rules (e.g. Sigma / Yara / auditd)

# PREDICTED NEXT ATTACKER MOVE (PRE-CRIME SHADOW TRAP TARGET)
Provide a structured JSON block with the predicted next move of the threat actor:
```json
{{
  "tactic": "Credential Access",
  "technique_id": "T1552.004",
  "probability": 0.92,
  "likely_target_path": "/tmp/demo_env/.aws_prod_keys.bak",
  "rationale": "Adversary established root persistence; highly probable next action is cloud and credential discovery in staging directories."
}}
```
"#,
            if bursts_block.is_empty() { "None" } else { &bursts_block },
            if timeline_block.is_empty() { "No events available" } else { &timeline_block }
        )
    }
}
