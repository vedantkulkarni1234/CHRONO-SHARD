use crate::models::{
    EventSource, ForensicConfidence, ForensicEvent, MacbFlags, MitreTactic, MitreTechnique,
};
use chrono::{DateTime, Utc};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub struct PersistenceCollector {
    custom_paths: Vec<PathBuf>,
}

impl PersistenceCollector {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self { custom_paths }
    }

    pub fn target_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        for p in &self.custom_paths {
            if p.exists() {
                paths.push(p.clone());
            }
        }

        // Crontabs
        let cron_files = [
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/var/spool/cron/crontabs",
        ];
        for c in &cron_files {
            let p = PathBuf::from(c);
            if p.exists() && !paths.contains(&p) {
                paths.push(p);
            }
        }

        // Systemd units
        let systemd_paths = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ];
        for s in &systemd_paths {
            let p = PathBuf::from(s);
            if p.exists() && !paths.contains(&p) {
                paths.push(p);
            }
        }

        // Home directory persistence
        if let Ok(home) = std::env::var("HOME") {
            let user_targets = [
                format!("{}/.ssh/authorized_keys", home),
                format!("{}/.ssh/authorized_keys2", home),
                format!("{}/.bashrc", home),
                format!("{}/.bash_profile", home),
                format!("{}/.zshrc", home),
                format!("{}/.profile", home),
                format!("{}/.config/systemd/user", home),
                format!("{}/.config/autostart", home),
            ];
            for ut in &user_targets {
                let p = PathBuf::from(ut);
                if p.exists() && !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }

        // Windows Startup & Persistence
        if let Ok(appdata) = std::env::var("APPDATA") {
            let win_startup = PathBuf::from(format!(
                "{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                appdata
            ));
            if win_startup.exists() && !paths.contains(&win_startup) {
                paths.push(win_startup);
            }
        }

        // Test artifacts directory
        let test_persist = PathBuf::from("./test_artifacts/persistence");
        if test_persist.exists() && !paths.contains(&test_persist) {
            paths.push(test_persist);
        }

        paths
    }

    pub fn collect(&self) -> Vec<ForensicEvent> {
        let targets = self.target_paths();
        let mut events = Vec::new();

        for target in targets {
            if target.is_dir() {
                if let Ok(entries) = fs::read_dir(&target) {
                    for entry in entries.filter_map(Result::ok) {
                        let path = entry.path();
                        if path.is_file() {
                            self.inspect_file(&path, &mut events);
                        }
                    }
                }
            } else if target.is_file() {
                self.inspect_file(&target, &mut events);
            }
        }

        events
    }

    fn inspect_file(&self, path: &Path, events: &mut Vec<ForensicEvent>) {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };

        let mtime: DateTime<Utc> = metadata
            .modified()
            .ok()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);

        let path_str = path.to_string_lossy();
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return,
        };

        let reader = BufReader::new(file);
        let mut line_num = 0;

        for line_res in reader.lines() {
            line_num += 1;
            if let Ok(line) = line_res {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                // Check Cron patterns
                if path_str.contains("cron") {
                    let is_suspicious = trimmed.contains("curl")
                        || trimmed.contains("wget")
                        || trimmed.contains("/tmp")
                        || trimmed.contains("/dev/shm")
                        || trimmed.contains("nc ")
                        || trimmed.contains("bash -i")
                        || trimmed.contains("python");

                    events.push(ForensicEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: mtime,
                        source: EventSource::Persistence,
                        macb: MacbFlags::new(true, false, false, false),
                        actor: None,
                        summary: format!("CRON: {} (line {})", filename, line_num),
                        path_or_target: Some(path.display().to_string()),
                        raw_artifact: format!("{}:{} -> {}", path.display(), line_num, trimmed),
                        tactic: Some(MitreTactic::Persistence),
                        technique: Some(MitreTechnique {
                            id: "T1053.003".to_string(),
                            name: "Scheduled Task/Job: Cron".to_string(),
                            tactic: MitreTactic::Persistence,
                        }),
                        confidence: if is_suspicious {
                            ForensicConfidence::Critical
                        } else {
                            ForensicConfidence::Medium
                        },
                        anomaly_score: if is_suspicious { 0.94 } else { 0.40 },
                        burst_id: None,
                        is_suspicious,
                        entropy: None,
                        is_packed: false,
                        extracted_strings: Vec::new(),
                    });
                }
                // Check Systemd Unit patterns
                else if path_str.contains("systemd") && trimmed.starts_with("ExecStart=") {
                    let exec_cmd = trimmed.trim_start_matches("ExecStart=");
                    let is_suspicious = exec_cmd.contains("/tmp")
                        || exec_cmd.contains("/dev/shm")
                        || exec_cmd.contains("curl")
                        || exec_cmd.contains("reverse");

                    events.push(ForensicEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: mtime,
                        source: EventSource::Persistence,
                        macb: MacbFlags::new(true, false, false, false),
                        actor: None,
                        summary: format!("SYSTEMD: {} [{}]", filename, exec_cmd),
                        path_or_target: Some(path.display().to_string()),
                        raw_artifact: format!("{}:{} -> {}", path.display(), line_num, trimmed),
                        tactic: Some(MitreTactic::Persistence),
                        technique: Some(MitreTechnique {
                            id: "T1543.002".to_string(),
                            name: "Create or Modify System Process: Systemd Service".to_string(),
                            tactic: MitreTactic::Persistence,
                        }),
                        confidence: if is_suspicious {
                            ForensicConfidence::Critical
                        } else {
                            ForensicConfidence::Low
                        },
                        anomaly_score: if is_suspicious { 0.91 } else { 0.30 },
                        burst_id: None,
                        is_suspicious,
                        entropy: None,
                        is_packed: false,
                        extracted_strings: Vec::new(),
                    });
                }
                // Check SSH Authorized Keys
                else if path_str.contains("authorized_keys") {
                    let is_suspicious = trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-");
                    events.push(ForensicEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: mtime,
                        source: EventSource::Persistence,
                        macb: MacbFlags::new(true, false, false, false),
                        actor: None,
                        summary: format!(
                            "SSH Key Injected: {}",
                            &trimmed[..trimmed.len().min(40)]
                        ),
                        path_or_target: Some(path.display().to_string()),
                        raw_artifact: format!("{}:{} -> {}", path.display(), line_num, trimmed),
                        tactic: Some(MitreTactic::Persistence),
                        technique: Some(MitreTechnique {
                            id: "T1098.004".to_string(),
                            name: "Account Manipulation: SSH Authorized Keys".to_string(),
                            tactic: MitreTactic::Persistence,
                        }),
                        confidence: ForensicConfidence::High,
                        anomaly_score: 0.82,
                        burst_id: None,
                        is_suspicious,
                        entropy: None,
                        is_packed: false,
                        extracted_strings: Vec::new(),
                    });
                }
                // Check Shell profile tampering (.bashrc, .profile)
                else if (filename == ".bashrc" || filename == ".zshrc" || filename == ".profile")
                    && (trimmed.contains("/dev/tcp")
                        || trimmed.contains("curl")
                        || trimmed.contains("eval ")
                        || trimmed.contains("alias sudo="))
                {
                    events.push(ForensicEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: mtime,
                        source: EventSource::Persistence,
                        macb: MacbFlags::new(true, false, false, false),
                        actor: None,
                        summary: format!("SHELL PROFILE HOOK: {}", filename),
                        path_or_target: Some(path.display().to_string()),
                        raw_artifact: format!("{}:{} -> {}", path.display(), line_num, trimmed),
                        tactic: Some(MitreTactic::Persistence),
                        technique: Some(MitreTechnique {
                            id: "T1546.004".to_string(),
                            name: "Event Triggered Execution: Unix Shell Configuration Modification"
                                .to_string(),
                            tactic: MitreTactic::Persistence,
                        }),
                        confidence: ForensicConfidence::Critical,
                        anomaly_score: 0.95,
                        burst_id: None,
                        is_suspicious: true,
                        entropy: None,
                        is_packed: false,
                        extracted_strings: Vec::new(),
                    });
                }
            }
        }
    }
}
