use crate::analysis::entropy::{classify_entropy, extract_strings, shannon_entropy, EntropyClass};
use crate::models::{
    EventSource, ForensicConfidence, ForensicEvent, MacbFlags, MitreTactic, MitreTechnique,
};
use chrono::{DateTime, Utc};
use rayon::prelude::*;
use std::fs::Metadata;
use std::path::PathBuf;
use std::time::SystemTime;
use walkdir::WalkDir;

/// Maximum file size (50 MB) for entropy scanning — skip larger files for speed
const ENTROPY_SCAN_MAX_BYTES: u64 = 50 * 1024 * 1024;

pub struct FilesystemCollector {
    custom_paths: Vec<PathBuf>,
}

impl FilesystemCollector {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self { custom_paths }
    }

    /// Determines target directories to sweep based on OS and user inputs
    pub fn target_directories(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();

        // Add custom paths first if specified
        for path in &self.custom_paths {
            if path.exists() {
                dirs.push(path.clone());
            }
        }

        // Standard high-risk DFIR staging paths (Linux / Unix)
        let standard_unix_paths = [
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/systemd/system",
        ];

        for p in &standard_unix_paths {
            let path = PathBuf::from(p);
            if path.exists() && !dirs.contains(&path) {
                dirs.push(path);
            }
        }

        // User local paths (Unix)
        if let Ok(home) = std::env::var("HOME") {
            let user_paths = [
                format!("{}/.local/share", home),
                format!("{}/.config/systemd/user", home),
                format!("{}/.ssh", home),
            ];
            for p in &user_paths {
                let path = PathBuf::from(p);
                if path.exists() && !dirs.contains(&path) {
                    dirs.push(path);
                }
            }
        }

        // Cross-platform / Windows fallbacks
        if let Ok(temp) = std::env::var("TEMP") {
            let p = PathBuf::from(temp);
            if p.exists() && !dirs.contains(&p) {
                dirs.push(p);
            }
        }
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let p = PathBuf::from(format!("{}\\Temp", local_appdata));
            if p.exists() && !dirs.contains(&p) {
                dirs.push(p);
            }
        }

        // Also include local `./scripts` and `./test_artifacts` or current dir if nothing found
        let local_script = PathBuf::from("./scripts");
        if local_script.exists() && !dirs.contains(&local_script) {
            dirs.push(local_script);
        }

        let local_artifacts = PathBuf::from("./test_artifacts");
        if local_artifacts.exists() && !dirs.contains(&local_artifacts) {
            dirs.push(local_artifacts);
        }

        dirs
    }

    /// Fast parallel traversal yielding normalized ForensicEvents in under 2 seconds
    pub fn collect(&self) -> Vec<ForensicEvent> {
        let targets = self.target_directories();
        if targets.is_empty() {
            return Vec::new();
        }

        // Parallel collection across root directories
        targets
            .par_iter()
            .flat_map(|target_dir| {
                let mut events = Vec::new();
                // Limit depth to 5 for speed guarantee
                let walker = WalkDir::new(target_dir)
                    .max_depth(5)
                    .follow_links(false)
                    .into_iter()
                    .filter_map(Result::ok);

                for entry in walker {
                    let path = entry.path();
                    if let Ok(metadata) = entry.metadata() {
                        let path_str = path.to_string_lossy().to_string();
                        let file_name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();

                        let (mtime, atime, ctime, btime) = extract_macb_timestamps(&metadata);
                        let now = Utc::now();

                        // Suspicious heuristics
                        let is_hidden = file_name.starts_with('.') && file_name.len() > 1;
                        let is_in_temp = path_str.contains("/tmp")
                            || path_str.contains("/dev/shm")
                            || path_str.contains("/var/tmp")
                            || path_str.to_lowercase().contains("\\temp")
                            || path_str.contains("test_artifacts");

                        let is_script_or_bin = is_suspicious_extension(&file_name);
                        let is_timestomped = detect_timestomping(mtime, atime, ctime, btime, now);

                        // Base timestamp is mtime, fallback to now
                        let primary_timestamp = mtime.unwrap_or(now);

                        let macb = MacbFlags::new(
                            mtime.is_some(),
                            atime.is_some(),
                            ctime.is_some(),
                            btime.is_some(),
                        );

                        // Tactic & technique classification
                        let mut tactic = None;
                        let mut technique = None;
                        let mut confidence = ForensicConfidence::Info;
                        let mut anomaly_score: f32 = 0.05;
                        let mut is_suspicious = false;

                        if is_timestomped {
                            tactic = Some(MitreTactic::DefenseEvasion);
                            technique = Some(MitreTechnique {
                                id: "T1070.006".to_string(),
                                name: "Indicator Removal: Timestomp".to_string(),
                                tactic: MitreTactic::DefenseEvasion,
                            });
                            confidence = ForensicConfidence::High;
                            anomaly_score = 0.88;
                            is_suspicious = true;
                        } else if is_in_temp && is_script_or_bin {
                            tactic = Some(MitreTactic::Execution);
                            technique = Some(MitreTechnique {
                                id: "T1059".to_string(),
                                name: "Command and Scripting Interpreter".to_string(),
                                tactic: MitreTactic::Execution,
                            });
                            confidence = ForensicConfidence::High;
                            anomaly_score = 0.82;
                            is_suspicious = true;
                        } else if is_hidden && is_in_temp {
                            tactic = Some(MitreTactic::DefenseEvasion);
                            technique = Some(MitreTechnique {
                                id: "T1564.001".to_string(),
                                name: "Hide Artifacts: Hidden Files and Directories".to_string(),
                                tactic: MitreTactic::DefenseEvasion,
                            });
                            confidence = ForensicConfidence::Medium;
                            anomaly_score = 0.70;
                            is_suspicious = true;
                        } else if path_str.contains("cron") || path_str.contains("systemd") {
                            tactic = Some(MitreTactic::Persistence);
                            technique = Some(MitreTechnique {
                                id: "T1053".to_string(),
                                name: "Scheduled Task/Job".to_string(),
                                tactic: MitreTactic::Persistence,
                            });
                            confidence = ForensicConfidence::Medium;
                            anomaly_score = 0.60;
                            is_suspicious = true;
                        }

                        let size = metadata.len();

                        // ── Entropy Analysis ──────────────────────────────────
                        // Scan files in temp/staging dirs that are under the size cap
                        let (entropy_val, extracted_strings, is_packed) = if is_in_temp
                            && metadata.is_file()
                            && size > 0
                            && size <= ENTROPY_SCAN_MAX_BYTES
                        {
                            match std::fs::read(path) {
                                Ok(bytes) => {
                                    let e = shannon_entropy(&bytes);
                                    let strings = extract_strings(&bytes, 20);
                                    let packed = matches!(
                                        classify_entropy(e),
                                        EntropyClass::PackedOrEncrypted
                                    );
                                    (Some(e), strings, packed)
                                }
                                Err(_) => (None, Vec::new(), false),
                            }
                        } else {
                            (None, Vec::new(), false)
                        };

                        // If packed, escalate tactic & score
                        let (tactic, technique, confidence, anomaly_score, is_suspicious) =
                            if is_packed {
                                (
                                    Some(MitreTactic::DefenseEvasion),
                                    Some(MitreTechnique {
                                        id: "T1027".to_string(),
                                        name: "Obfuscated Files or Information".to_string(),
                                        tactic: MitreTactic::DefenseEvasion,
                                    }),
                                    ForensicConfidence::Critical,
                                    0.97f32,
                                    true,
                                )
                            } else {
                                (tactic, technique, confidence, anomaly_score, is_suspicious)
                            };

                        // Build entropy annotation for summary
                        let entropy_tag = match entropy_val {
                            Some(e) if e > 7.2 => format!(" H:{:.2}⚠PACKED", e),
                            Some(e) if e > 6.0 => format!(" H:{:.2}~HIGH", e),
                            Some(e) => format!(" H:{:.2}", e),
                            None => String::new(),
                        };

                        let summary = format!(
                            "FS [{}] {}{}  ({} bytes)",
                            macb.to_macb_string(),
                            file_name,
                            entropy_tag,
                            size
                        );

                        let raw_artifact = format!(
                            "Path: {}\nSize: {} bytes\nMACB: {}\nMTime: {}\nATime: {}\nCTime: {}\nBTime: {}\nPermissions: {:o}",
                            path.display(),
                            size,
                            macb.to_macb_string(),
                            mtime.map(|t| t.to_rfc3339()).unwrap_or_else(|| "N/A".to_string()),
                            atime.map(|t| t.to_rfc3339()).unwrap_or_else(|| "N/A".to_string()),
                            ctime.map(|t| t.to_rfc3339()).unwrap_or_else(|| "N/A".to_string()),
                            btime.map(|t| t.to_rfc3339()).unwrap_or_else(|| "N/A".to_string()),
                            get_permissions_octal(&metadata)
                        );

                        events.push(ForensicEvent {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: primary_timestamp,
                            source: EventSource::Filesystem,
                            macb,
                            actor: None,
                            summary,
                            path_or_target: Some(path.display().to_string()),
                            raw_artifact,
                            tactic,
                            technique,
                            confidence,
                            anomaly_score,
                            burst_id: None,
                            is_suspicious,
                            entropy: entropy_val,
                            is_packed,
                            extracted_strings,
                        });
                    }
                }
                events
            })
            .collect()
    }
}

fn extract_macb_timestamps(
    meta: &Metadata,
) -> (
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
) {
    let mtime = meta.modified().ok().map(to_utc);
    let atime = meta.accessed().ok().map(to_utc);
    let btime = meta.created().ok().map(to_utc);
    // On Unix platforms ctime is available via MetadataExt, otherwise fallback to mtime/btime
    #[cfg(unix)]
    let ctime = {
        use std::os::unix::fs::MetadataExt;
        let sec = meta.ctime();
        let nsec = meta.ctime_nsec() as u32;
        DateTime::from_timestamp(sec, nsec)
    };
    #[cfg(not(unix))]
    let ctime = btime.or(mtime);

    (mtime, atime, ctime, btime)
}

fn to_utc(st: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(st)
}

fn is_suspicious_extension(name: &str) -> bool {
    let lower = name.to_lowercase();
    let exts = [
        ".sh", ".py", ".pl", ".php", ".elf", ".so", ".bin", ".exe", ".dll", ".ps1", ".bat",
        ".vbs", ".payload", ".cron",
    ];
    exts.iter().any(|ext| lower.ends_with(ext))
        || lower.contains("reverse")
        || lower.contains("backdoor")
        || lower.contains("payload")
}

fn detect_timestomping(
    mtime: Option<DateTime<Utc>>,
    atime: Option<DateTime<Utc>>,
    _ctime: Option<DateTime<Utc>>,
    btime: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    // 1. Future timestamp
    if let Some(m) = mtime {
        if m > now + chrono::Duration::minutes(5) {
            return true;
        }
    }
    if let Some(a) = atime {
        if a > now + chrono::Duration::minutes(5) {
            return true;
        }
    }

    // 2. Created time after modification time (impossible in normal sequential operations)
    if let (Some(b), Some(m)) = (btime, mtime) {
        if b > m + chrono::Duration::seconds(10) {
            return true;
        }
    }

    false
}

#[cfg(unix)]
fn get_permissions_octal(meta: &Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o777
}

#[cfg(not(unix))]
fn get_permissions_octal(meta: &Metadata) -> u32 {
    if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}
