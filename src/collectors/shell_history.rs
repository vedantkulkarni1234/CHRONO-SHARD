use crate::models::{
    EventSource, ForensicConfidence, ForensicEvent, MacbFlags, MitreTactic, MitreTechnique,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static RE_ZSH_EXTENDED: OnceLock<Regex> = OnceLock::new();
static RE_BASH_TIMESTAMP: OnceLock<Regex> = OnceLock::new();

fn get_zsh_extended_re() -> &'static Regex {
    RE_ZSH_EXTENDED.get_or_init(|| {
        Regex::new(r"^:\s*(?P<ts>\d+):(?P<duration>\d+);(?P<cmd>.*)$").unwrap()
    })
}

fn get_bash_timestamp_re() -> &'static Regex {
    RE_BASH_TIMESTAMP.get_or_init(|| Regex::new(r"^#(?P<ts>\d{9,10})$").unwrap())
}

pub struct ShellHistoryCollector {
    custom_paths: Vec<PathBuf>,
}

impl ShellHistoryCollector {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self { custom_paths }
    }

    pub fn target_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        for p in &self.custom_paths {
            if p.exists() {
                files.push(p.clone());
            }
        }

        // Unix shell histories
        if let Ok(home) = std::env::var("HOME") {
            let candidates = [
                format!("{}/.bash_history", home),
                format!("{}/.zsh_history", home),
                format!("{}/.sh_history", home),
                format!("{}/.ash_history", home),
            ];
            for c in &candidates {
                let p = PathBuf::from(c);
                if p.exists() && !files.contains(&p) {
                    files.push(p);
                }
            }
        }

        // Windows PowerShell history
        if let Ok(appdata) = std::env::var("APPDATA") {
            let ps_hist = PathBuf::from(format!(
                "{}\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
                appdata
            ));
            if ps_hist.exists() && !files.contains(&ps_hist) {
                files.push(ps_hist);
            }
        }

        // Fallbacks for test artifacts and demo scripts
        let test_hist = PathBuf::from("./test_artifacts/shell_history.txt");
        if test_hist.exists() && !files.contains(&test_hist) {
            files.push(test_hist);
        }

        files
    }

    pub fn collect(&self) -> Vec<ForensicEvent> {
        let targets = self.target_files();
        let mut events = Vec::new();

        for file_path in targets {
            if let Ok(file) = File::open(&file_path) {
                let metadata = file.metadata().ok();
                let file_mtime = metadata
                    .and_then(|m| m.modified().ok())
                    .map(DateTime::<Utc>::from)
                    .unwrap_or_else(Utc::now);

                let reader = BufReader::new(file);
                let zsh_re = get_zsh_extended_re();
                let bash_re = get_bash_timestamp_re();

                let mut pending_bash_timestamp: Option<DateTime<Utc>> = None;
                let mut line_counter: i64 = 0;

                for line_res in reader.lines() {
                    if let Ok(line) = line_res {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        // Check if line is bash timestamp comment: #1700000000
                        if let Some(caps) = bash_re.captures(trimmed) {
                            if let Ok(ts_sec) = caps["ts"].parse::<i64>() {
                                pending_bash_timestamp =
                                    DateTime::from_timestamp(ts_sec, 0);
                            }
                            continue;
                        }

                        let (timestamp, command) = if let Some(caps) = zsh_re.captures(trimmed) {
                            let ts_sec = caps["ts"].parse::<i64>().unwrap_or(0);
                            let cmd = caps["cmd"].to_string();
                            let dt = DateTime::from_timestamp(ts_sec, 0).unwrap_or(file_mtime);
                            (dt, cmd)
                        } else if let Some(ts) = pending_bash_timestamp.take() {
                            (ts, trimmed.to_string())
                        } else {
                            // Synthesize sequential offset backwards from file mtime
                            line_counter += 1;
                            let dt = file_mtime - chrono::Duration::seconds(line_counter * 5);
                            (dt, trimmed.to_string())
                        };

                        if let Some(ev) =
                            classify_command(&command, timestamp, &file_path, trimmed)
                        {
                            events.push(ev);
                        }
                    }
                }
            }
        }

        events
    }
}

fn classify_command(
    command: &str,
    timestamp: DateTime<Utc>,
    file_path: &Path,
    raw_line: &str,
) -> Option<ForensicEvent> {
    let lower = command.to_lowercase();
    let mut tactic = None;
    let mut technique = None;
    let mut confidence = ForensicConfidence::Info;
    let mut anomaly_score = 0.10;
    let mut is_suspicious = false;

    // Defense Evasion checks
    if lower.contains("history -c")
        || lower.contains("unset histfile")
        || lower.contains("histsize=0")
        || lower.contains("rm -rf /var/log")
        || lower.contains("touch -r")
        || lower.contains("shred ")
        || lower.contains("/dev/null >")
    {
        tactic = Some(MitreTactic::DefenseEvasion);
        technique = Some(MitreTechnique {
            id: if lower.contains("touch -r") {
                "T1070.006".to_string()
            } else {
                "T1070.003".to_string()
            },
            name: if lower.contains("touch -r") {
                "Indicator Removal: Timestomp".to_string()
            } else {
                "Indicator Removal: Clear Command History".to_string()
            },
            tactic: MitreTactic::DefenseEvasion,
        });
        confidence = ForensicConfidence::Critical;
        anomaly_score = 0.95;
        is_suspicious = true;
    }
    // Execution / Command & Control / Reverse Shells
    else if lower.contains("| bash")
        || lower.contains("| sh")
        || lower.contains("nc -e")
        || lower.contains("nc -lvnp")
        || lower.contains("/dev/tcp/")
        || lower.contains("python -c \"import socket")
        || lower.contains("socat ")
        || lower.contains("chmod +x /tmp/")
        || lower.contains("/tmp/.")
    {
        tactic = Some(MitreTactic::Execution);
        technique = Some(MitreTechnique {
            id: "T1059.004".to_string(),
            name: "Command and Scripting Interpreter: Unix Shell".to_string(),
            tactic: MitreTactic::Execution,
        });
        confidence = ForensicConfidence::Critical;
        anomaly_score = 0.92;
        is_suspicious = true;
    }
    // Privilege Escalation
    else if lower.contains("sudo su")
        || lower.contains("sudo -i")
        || lower.contains("chmod +s")
        || lower.contains("pkexec")
        || lower.contains("doas")
    {
        tactic = Some(MitreTactic::PrivilegeEscalation);
        technique = Some(MitreTechnique {
            id: "T1548.003".to_string(),
            name: "Abuse Elevation Control Mechanism: Sudo and Sudo Caching".to_string(),
            tactic: MitreTactic::PrivilegeEscalation,
        });
        confidence = ForensicConfidence::High;
        anomaly_score = 0.85;
        is_suspicious = true;
    }
    // Persistence
    else if lower.contains("crontab")
        || lower.contains("authorized_keys")
        || lower.contains("/etc/cron")
        || lower.contains("systemctl enable")
        || lower.contains("/etc/rc.local")
    {
        tactic = Some(MitreTactic::Persistence);
        technique = Some(MitreTechnique {
            id: "T1053.003".to_string(),
            name: "Scheduled Task/Job: Cron".to_string(),
            tactic: MitreTactic::Persistence,
        });
        confidence = ForensicConfidence::High;
        anomaly_score = 0.80;
        is_suspicious = true;
    }
    // Discovery / Reconnaissance
    else if lower.starts_with("whoami")
        || lower.starts_with("id")
        || lower.contains("uname -a")
        || lower.contains("netstat")
        || lower.contains("ss -")
        || lower.contains("lsof -i")
        || lower.contains("ip a")
        || lower.contains("ifconfig")
        || lower.contains("ps aux")
        || lower.contains("find / -perm")
    {
        tactic = Some(MitreTactic::Discovery);
        technique = Some(MitreTechnique {
            id: "T1082".to_string(),
            name: "System Information Discovery".to_string(),
            tactic: MitreTactic::Discovery,
        });
        confidence = ForensicConfidence::Medium;
        anomaly_score = 0.55;
        is_suspicious = true;
    }

    let summary = format!("SHELL: {}", command);

    Some(ForensicEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp,
        source: EventSource::ShellHistory,
        macb: MacbFlags::default(),
        actor: None,
        summary,
        path_or_target: Some(file_path.display().to_string()),
        raw_artifact: raw_line.to_string(),
        tactic,
        technique,
        confidence,
        anomaly_score,
        burst_id: None,
        is_suspicious,
        entropy: None,
        is_packed: false,
        extracted_strings: Vec::new(),
    })
}
