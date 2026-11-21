use crate::models::{
    EventSource, ForensicConfidence, ForensicEvent, MacbFlags, MitreTactic, MitreTechnique,
};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

// Compiled regex patterns for auth log events
static RE_FAILED_SSH: OnceLock<Regex> = OnceLock::new();
static RE_ACCEPTED_SSH: OnceLock<Regex> = OnceLock::new();
static RE_SUDO_CMD: OnceLock<Regex> = OnceLock::new();
static RE_USERADD: OnceLock<Regex> = OnceLock::new();
static RE_PAM_FAIL: OnceLock<Regex> = OnceLock::new();
static RE_SYSLOG_TS: OnceLock<Regex> = OnceLock::new();

fn get_failed_ssh_re() -> &'static Regex {
    RE_FAILED_SSH.get_or_init(|| {
        Regex::new(r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)").unwrap()
    })
}

fn get_accepted_ssh_re() -> &'static Regex {
    RE_ACCEPTED_SSH.get_or_init(|| {
        Regex::new(r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)").unwrap()
    })
}

fn get_sudo_cmd_re() -> &'static Regex {
    RE_SUDO_CMD.get_or_init(|| {
        Regex::new(r"sudo:\s+(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+)").unwrap()
    })
}

fn get_useradd_re() -> &'static Regex {
    RE_USERADD.get_or_init(|| {
        Regex::new(r"useradd\[\d+\]:\s+new\s+user:\s+name=(?P<user>\S+)").unwrap()
    })
}

fn get_pam_fail_re() -> &'static Regex {
    RE_PAM_FAIL.get_or_init(|| {
        Regex::new(r"pam_unix\(\S+:auth\):\s+authentication\s+failure;\s*logname=\S*\s*uid=\d*\s*euid=\d*\s*tty=\S*\s*ruser=\S*\s*rhost=(?P<rhost>\S*)\s*(?:user=(?P<user>\S*))?").unwrap()
    })
}

fn get_syslog_ts_re() -> &'static Regex {
    RE_SYSLOG_TS.get_or_init(|| {
        Regex::new(r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})").unwrap()
    })
}

pub struct AuthLogCollector {
    custom_paths: Vec<PathBuf>,
}

impl AuthLogCollector {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self { custom_paths }
    }

    pub fn target_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // Custom paths
        for p in &self.custom_paths {
            if p.exists() {
                files.push(p.clone());
            }
        }

        // Standard Linux locations
        let standard_paths = [
            "/var/log/auth.log",
            "/var/log/auth.log.1",
            "/var/log/secure",
            "/var/log/secure.1",
            "/var/log/audit/audit.log",
            "./logs/auth.log",
            "./test_artifacts/auth.log",
        ];

        for p in &standard_paths {
            let path = PathBuf::from(p);
            if path.exists() && !files.contains(&path) {
                files.push(path);
            }
        }

        files
    }

    pub fn collect(&self) -> Vec<ForensicEvent> {
        let targets = self.target_files();
        let mut events = Vec::new();

        for file_path in targets {
            if let Ok(file) = File::open(&file_path) {
                let reader = BufReader::new(file);
                for line_result in reader.lines() {
                    if let Ok(line) = line_result {
                        if let Some(event) = parse_auth_log_line(&line, &file_path) {
                            events.push(event);
                        }
                    }
                }
            }
        }

        events
    }
}

pub fn parse_auth_log_line(line: &str, file_path: &Path) -> Option<ForensicEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    let timestamp = parse_timestamp(trimmed)?;

    let failed_re = get_failed_ssh_re();
    let accepted_re = get_accepted_ssh_re();
    let sudo_re = get_sudo_cmd_re();
    let useradd_re = get_useradd_re();
    let pam_fail_re = get_pam_fail_re();

    if let Some(caps) = failed_re.captures(trimmed) {
        let user = caps.name("user").map(|m| m.as_str().to_string());
        let ip = caps.name("ip").map(|m| m.as_str().to_string());
        let port = caps.name("port").map(|m| m.as_str()).unwrap_or("?");
        let summary = format!("SSH Failed Password: user '{}' from {}:{}", user.as_deref().unwrap_or("?"), ip.as_deref().unwrap_or("?"), port);

        return Some(ForensicEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            source: EventSource::AuthLog,
            macb: MacbFlags::default(),
            actor: user,
            summary,
            path_or_target: ip,
            raw_artifact: trimmed.to_string(),
            tactic: Some(MitreTactic::CredentialAccess),
            technique: Some(MitreTechnique {
                id: "T1110.001".to_string(),
                name: "Brute Force: Password Guessing".to_string(),
                tactic: MitreTactic::CredentialAccess,
            }),
            confidence: ForensicConfidence::Medium,
            anomaly_score: 0.75,
            burst_id: None,
            is_suspicious: true,
            entropy: None,
            is_packed: false,
            extracted_strings: Vec::new(),
        });
    }

    if let Some(caps) = accepted_re.captures(trimmed) {
        let user = caps.name("user").map(|m| m.as_str().to_string());
        let ip = caps.name("ip").map(|m| m.as_str().to_string());
        let port = caps.name("port").map(|m| m.as_str()).unwrap_or("?");
        let summary = format!("SSH Accepted Login: user '{}' from {}:{}", user.as_deref().unwrap_or("?"), ip.as_deref().unwrap_or("?"), port);

        return Some(ForensicEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            source: EventSource::AuthLog,
            macb: MacbFlags::default(),
            actor: user,
            summary,
            path_or_target: ip,
            raw_artifact: trimmed.to_string(),
            tactic: Some(MitreTactic::InitialAccess),
            technique: Some(MitreTechnique {
                id: "T1078".to_string(),
                name: "Valid Accounts".to_string(),
                tactic: MitreTactic::InitialAccess,
            }),
            confidence: ForensicConfidence::High,
            anomaly_score: 0.65,
            burst_id: None,
            is_suspicious: true,
            entropy: None,
            is_packed: false,
            extracted_strings: Vec::new(),
        });
    }

    if let Some(caps) = sudo_re.captures(trimmed) {
        let user = caps.name("user").map(|m| m.as_str().to_string());
        let target = caps.name("target").map(|m| m.as_str()).unwrap_or("root");
        let cmd = caps.name("cmd").map(|m| m.as_str().to_string()).unwrap_or_default();
        let summary = format!("Sudo Execution: {} -> ({}) {}", user.as_deref().unwrap_or("?"), target, cmd);

        let is_suspicious_cmd = cmd.contains("/bin/sh")
            || cmd.contains("/bin/bash")
            || cmd.contains("chmod")
            || cmd.contains("curl")
            || cmd.contains("wget")
            || cmd.contains("nc ");

        return Some(ForensicEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            source: EventSource::AuthLog,
            macb: MacbFlags::default(),
            actor: user,
            summary,
            path_or_target: Some(cmd),
            raw_artifact: trimmed.to_string(),
            tactic: Some(MitreTactic::PrivilegeEscalation),
            technique: Some(MitreTechnique {
                id: "T1548.003".to_string(),
                name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching".to_string(),
                tactic: MitreTactic::PrivilegeEscalation,
            }),
            confidence: if is_suspicious_cmd { ForensicConfidence::Critical } else { ForensicConfidence::Medium },
            anomaly_score: if is_suspicious_cmd { 0.90 } else { 0.40 },
            burst_id: None,
            is_suspicious: is_suspicious_cmd,
            entropy: None,
            is_packed: false,
            extracted_strings: Vec::new(),
        });
    }

    if let Some(caps) = useradd_re.captures(trimmed) {
        let user = caps.name("user").map(|m| m.as_str().to_string());
        let summary = format!("User Account Created: '{}'", user.as_deref().unwrap_or("?"));

        return Some(ForensicEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            source: EventSource::AuthLog,
            macb: MacbFlags::default(),
            actor: user.clone(),
            summary,
            path_or_target: user,
            raw_artifact: trimmed.to_string(),
            tactic: Some(MitreTactic::Persistence),
            technique: Some(MitreTechnique {
                id: "T1136.001".to_string(),
                name: "Create Account: Local Account".to_string(),
                tactic: MitreTactic::Persistence,
            }),
            confidence: ForensicConfidence::High,
            anomaly_score: 0.85,
            burst_id: None,
            is_suspicious: true,
            entropy: None,
            is_packed: false,
            extracted_strings: Vec::new(),
        });
    }

    if let Some(caps) = pam_fail_re.captures(trimmed) {
        let rhost = caps.name("rhost").map(|m| m.as_str().to_string());
        let user = caps.name("user").map(|m| m.as_str().to_string());
        let summary = format!("PAM Auth Failure for user '{}' from host '{}'", user.as_deref().unwrap_or("unknown"), rhost.as_deref().unwrap_or("local"));

        return Some(ForensicEvent {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            source: EventSource::AuthLog,
            macb: MacbFlags::default(),
            actor: user,
            summary,
            path_or_target: rhost,
            raw_artifact: trimmed.to_string(),
            tactic: Some(MitreTactic::CredentialAccess),
            technique: Some(MitreTechnique {
                id: "T1110".to_string(),
                name: "Brute Force".to_string(),
                tactic: MitreTactic::CredentialAccess,
            }),
            confidence: ForensicConfidence::Medium,
            anomaly_score: 0.60,
            burst_id: None,
            is_suspicious: true,
            entropy: None,
            is_packed: false,
            extracted_strings: Vec::new(),
        });
    }

    // Generic log line
    Some(ForensicEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp,
        source: EventSource::AuthLog,
        macb: MacbFlags::default(),
        actor: None,
        summary: format!("AuthLog: {}", &trimmed[..trimmed.len().min(80)]),
        path_or_target: Some(file_path.display().to_string()),
        raw_artifact: trimmed.to_string(),
        tactic: None,
        technique: None,
        confidence: ForensicConfidence::Info,
        anomaly_score: 0.1,
        burst_id: None,
        is_suspicious: false,
        entropy: None,
        is_packed: false,
        extracted_strings: Vec::new(),
    })
}

fn parse_timestamp(line: &str) -> Option<DateTime<Utc>> {
    // 1. Try ISO8601 / RFC3339 prefix
    if line.len() >= 19 {
        let candidate = &line[0..19];
        if let Ok(ndt) = NaiveDateTime::parse_from_str(candidate, "%Y-%m-%dT%H:%M:%S") {
            return Some(DateTime::from_naive_utc_and_offset(ndt, Utc));
        }
        if let Ok(ndt) = NaiveDateTime::parse_from_str(candidate, "%Y-%m-%d %H:%M:%S") {
            return Some(DateTime::from_naive_utc_and_offset(ndt, Utc));
        }
    }

    // 2. Try classic Syslog format "Oct 24 14:02:11"
    let syslog_re = get_syslog_ts_re();
    if let Some(caps) = syslog_re.captures(line) {
        let month_str = caps.name("month")?.as_str();
        let day_str = caps.name("day")?.as_str();
        let time_str = caps.name("time")?.as_str();

        let month = match month_str {
            "Jan" => 1, "Feb" => 2, "Mar" => 3, "Apr" => 4,
            "May" => 5, "Jun" => 6, "Jul" => 7, "Aug" => 8,
            "Sep" => 9, "Oct" => 10, "Nov" => 11, "Dec" => 12,
            _ => return None,
        };
        let day: u32 = day_str.parse().ok()?;
        let time = NaiveTime::parse_from_str(time_str, "%H:%M:%S").ok()?;
        let current_year = Utc::now().year();

        let date = NaiveDate::from_ymd_opt(current_year, month, day)?;
        let ndt = NaiveDateTime::new(date, time);
        return Some(DateTime::from_naive_utc_and_offset(ndt, Utc));
    }

    None
}
