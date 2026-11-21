use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventSource {
    Filesystem,
    AuthLog,
    ShellHistory,
    Persistence,
    Browser,
    Syslog,
}

impl EventSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventSource::Filesystem => "FS_MACB",
            EventSource::AuthLog => "AUTH_LOG",
            EventSource::ShellHistory => "SHELL_HIST",
            EventSource::Persistence => "PERSIST",
            EventSource::Browser => "BROWSER",
            EventSource::Syslog => "SYSLOG",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MacbFlags {
    pub modified: bool, // M: Content modified (mtime)
    pub accessed: bool, // A: File accessed (atime)
    pub changed: bool,  // C: Inode / metadata changed (ctime)
    pub born: bool,     // B: Birth / Creation time (btime / crtime)
}

impl MacbFlags {
    pub fn new(modified: bool, accessed: bool, changed: bool, born: bool) -> Self {
        Self {
            modified,
            accessed,
            changed,
            born,
        }
    }

    pub fn to_macb_string(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.modified { 'M' } else { '.' },
            if self.accessed { 'A' } else { '.' },
            if self.changed { 'C' } else { '.' },
            if self.born { 'B' } else { '.' }
        )
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        !self.modified && !self.accessed && !self.changed && !self.born
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitreTactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
    Unknown,
}

impl MitreTactic {
    pub fn id(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
            MitreTactic::Unknown => "TA0000",
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
            MitreTactic::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: MitreTactic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ForensicConfidence {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ForensicConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicConfidence::Info => "INFO",
            ForensicConfidence::Low => "LOW",
            ForensicConfidence::Medium => "MED",
            ForensicConfidence::High => "HIGH",
            ForensicConfidence::Critical => "CRIT",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub macb: MacbFlags,
    pub actor: Option<String>,
    pub summary: String,
    pub path_or_target: Option<String>,
    pub raw_artifact: String,
    pub tactic: Option<MitreTactic>,
    pub technique: Option<MitreTechnique>,
    pub confidence: ForensicConfidence,
    pub anomaly_score: f32, // 0.0 - 1.0
    pub burst_id: Option<usize>,
    pub is_suspicious: bool,
    pub entropy: Option<f32>,
    pub is_packed: bool,
    pub extracted_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalBurst {
    pub id: usize,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub event_count: usize,
    pub anomaly_score: f32,
    pub dominant_source: EventSource,
    pub summary: String,
    pub mitre_tactics: Vec<MitreTactic>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PredictedNextMove {
    pub tactic: String,
    pub technique_id: String,
    pub probability: f32,
    pub likely_target_path: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AiAnalysisReport {
    pub triage_summary: String,       // Rapid classification (gemini-3.5-flash-lite)
    pub kill_chain_narrative: String, // Deep multi-stage synthesis (gemini-4-carbon)
    pub attack_vector: String,
    pub iocs: Vec<String>,
    pub remediation_steps: Vec<String>,
    pub confidence_assessment: String,
    pub generated_at: Option<DateTime<Utc>>,
    pub model_used: String,
    pub predicted_next_move: Option<PredictedNextMove>,
}
