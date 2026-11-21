use crate::models::{
    EventSource, ForensicConfidence, ForensicEvent, MacbFlags, MitreTactic, MitreTechnique,
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::path::{Path, PathBuf};

pub struct BrowserCollector {
    custom_paths: Vec<PathBuf>,
}

impl BrowserCollector {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self { custom_paths }
    }

    pub fn target_databases(&self) -> Vec<(PathBuf, BrowserType)> {
        let mut dbs = Vec::new();

        for p in &self.custom_paths {
            if p.exists() {
                let b_type = if p.to_string_lossy().contains("places.sqlite") {
                    BrowserType::Firefox
                } else {
                    BrowserType::Chromium
                };
                dbs.push((p.clone(), b_type));
            }
        }

        // Linux Chromium & Chrome
        if let Ok(home) = std::env::var("HOME") {
            let candidates = [
                (format!("{}/.config/google-chrome/Default/History", home), BrowserType::Chromium),
                (format!("{}/.config/chromium/Default/History", home), BrowserType::Chromium),
                (format!("{}/.config/BraveSoftware/Brave-Browser/Default/History", home), BrowserType::Chromium),
            ];
            for (c, b_type) in candidates {
                let p = PathBuf::from(c);
                if p.exists() {
                    dbs.push((p, b_type));
                }
            }

            // Firefox on Linux
            let ff_dir = PathBuf::from(format!("{}/.mozilla/firefox", home));
            if ff_dir.exists() {
                if let Ok(entries) = fs::read_dir(ff_dir) {
                    for entry in entries.filter_map(Result::ok) {
                        let places = entry.path().join("places.sqlite");
                        if places.exists() {
                            dbs.push((places, BrowserType::Firefox));
                        }
                    }
                }
            }
        }

        // Windows Chrome, Edge, Brave
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
            let win_candidates = [
                (format!("{}\\Google\\Chrome\\User Data\\Default\\History", local_appdata), BrowserType::Chromium),
                (format!("{}\\Microsoft\\Edge\\User Data\\Default\\History", local_appdata), BrowserType::Chromium),
                (format!("{}\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History", local_appdata), BrowserType::Chromium),
            ];
            for (c, b_type) in win_candidates {
                let p = PathBuf::from(c);
                if p.exists() {
                    dbs.push((p, b_type));
                }
            }
        }

        // Windows Firefox
        if let Ok(appdata) = std::env::var("APPDATA") {
            let win_ff = PathBuf::from(format!("{}\\Mozilla\\Firefox\\Profiles", appdata));
            if win_ff.exists() {
                if let Ok(entries) = fs::read_dir(win_ff) {
                    for entry in entries.filter_map(Result::ok) {
                        let places = entry.path().join("places.sqlite");
                        if places.exists() {
                            dbs.push((places, BrowserType::Firefox));
                        }
                    }
                }
            }
        }

        // Test artifacts fallback
        let test_db = PathBuf::from("./test_artifacts/browser_history.sqlite");
        if test_db.exists() {
            dbs.push((test_db, BrowserType::Chromium));
        }

        dbs
    }

    pub fn collect(&self) -> Vec<ForensicEvent> {
        let targets = self.target_databases();
        let mut events = Vec::new();

        for (db_path, browser_type) in targets {
            // Safe copy to temp directory to avoid lock contention with active browser
            let temp_dir = std::env::temp_dir();
            let temp_db_path = temp_dir.join(format!(
                "chrono_shard_{}_{}",
                uuid::Uuid::new_v4(),
                db_path.file_name().unwrap().to_string_lossy()
            ));

            if fs::copy(&db_path, &temp_db_path).is_ok() {
                match browser_type {
                    BrowserType::Chromium => {
                        self.parse_chromium(&temp_db_path, &db_path, &mut events);
                    }
                    BrowserType::Firefox => {
                        self.parse_firefox(&temp_db_path, &db_path, &mut events);
                    }
                }
                let _ = fs::remove_file(&temp_db_path);
            } else {
                // If copy fails, attempt read-only immutable URI open directly
                let uri = format!("file:{}?mode=ro&immutable=1", db_path.to_string_lossy());
                if let Ok(conn) = Connection::open_with_flags(
                    &uri,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
                ) {
                    match browser_type {
                        BrowserType::Chromium => {
                            self.query_chromium_conn(&conn, &db_path, &mut events);
                        }
                        BrowserType::Firefox => {
                            self.query_firefox_conn(&conn, &db_path, &mut events);
                        }
                    }
                }
            }
        }

        events
    }

    fn parse_chromium(&self, temp_path: &Path, original_path: &Path, events: &mut Vec<ForensicEvent>) {
        let uri = format!("file:{}?mode=ro&immutable=1", temp_path.to_string_lossy());
        if let Ok(conn) = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ) {
            self.query_chromium_conn(&conn, original_path, events);
        }
    }

    fn query_chromium_conn(&self, conn: &Connection, original_path: &Path, events: &mut Vec<ForensicEvent>) {
        // Chromium urls table: id, url, title, visit_count, typed_count, last_visit_time
        let mut stmt = match conn.prepare(
            "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: String = row.get(1).unwrap_or_default();
            let last_visit_time: i64 = row.get(2).unwrap_or(0);
            Ok((url, title, last_visit_time))
        });

        if let Ok(rows) = rows {
            for row in rows.filter_map(Result::ok) {
                let (url, title, time_val) = row;
                // Chromium timestamps: microseconds since 1601-01-01 UTC
                // Epoch diff: 11644473600 seconds
                if time_val > 0 {
                    let us_diff = 11_644_473_600_000_000i64;
                    if time_val > us_diff {
                        let unix_us = time_val - us_diff;
                        let unix_sec = unix_us / 1_000_000;
                        let unix_nsec = ((unix_us % 1_000_000) * 1000) as u32;

                        if let Some(ts) = DateTime::from_timestamp(unix_sec, unix_nsec) {
                            classify_browser_event(url, title, ts, original_path, events);
                        }
                    }
                }
            }
        }
    }

    fn parse_firefox(&self, temp_path: &Path, original_path: &Path, events: &mut Vec<ForensicEvent>) {
        let uri = format!("file:{}?mode=ro&immutable=1", temp_path.to_string_lossy());
        if let Ok(conn) = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        ) {
            self.query_firefox_conn(&conn, original_path, events);
        }
    }

    fn query_firefox_conn(&self, conn: &Connection, original_path: &Path, events: &mut Vec<ForensicEvent>) {
        // Firefox places.sqlite: moz_places: id, url, title, last_visit_date (microseconds since 1970-01-01)
        let mut stmt = match conn.prepare(
            "SELECT url, title, last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 500",
        ) {
            Ok(s) => s,
            Err(_) => return,
        };

        let rows = stmt.query_map([], |row| {
            let url: String = row.get(0)?;
            let title: String = row.get(1).unwrap_or_default();
            let last_visit_date: i64 = row.get(2).unwrap_or(0);
            Ok((url, title, last_visit_date))
        });

        if let Ok(rows) = rows {
            for row in rows.filter_map(Result::ok) {
                let (url, title, time_val) = row;
                if time_val > 0 {
                    let unix_sec = time_val / 1_000_000;
                    let unix_nsec = ((time_val % 1_000_000) * 1000) as u32;

                    if let Some(ts) = DateTime::from_timestamp(unix_sec, unix_nsec) {
                        classify_browser_event(url, title, ts, original_path, events);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserType {
    Chromium,
    Firefox,
}

fn classify_browser_event(
    url: String,
    title: String,
    ts: DateTime<Utc>,
    original_path: &Path,
    events: &mut Vec<ForensicEvent>,
) {
    let lower_url = url.to_lowercase();
    let is_c2_or_phish = lower_url.contains("raw.githubusercontent.com")
        || lower_url.contains("pastebin.com")
        || lower_url.contains("rentry.co")
        || lower_url.contains("ngrok")
        || lower_url.contains("webhook.site")
        || lower_url.contains("torproject")
        || lower_url.contains(".onion")
        || lower_url.contains("reverse_shell")
        || lower_url.contains("payload");

    let is_tool_dl = lower_url.ends_with(".sh")
        || lower_url.ends_with(".ps1")
        || lower_url.ends_with(".elf")
        || lower_url.ends_with(".exe")
        || lower_url.ends_with(".bat");

    let mut tactic = None;
    let mut technique = None;
    let mut confidence = ForensicConfidence::Info;
    let mut anomaly_score = 0.05;
    let mut is_suspicious = false;

    if is_c2_or_phish || is_tool_dl {
        tactic = Some(MitreTactic::InitialAccess);
        technique = Some(MitreTechnique {
            id: "T1105".to_string(),
            name: "Ingress Tool Transfer".to_string(),
            tactic: MitreTactic::InitialAccess,
        });
        confidence = ForensicConfidence::High;
        anomaly_score = 0.86;
        is_suspicious = true;
    }

    let summary = format!("BROWSER: {} ({})", &title[..title.len().min(40)], &url[..url.len().min(60)]);
    let raw = format!("URL: {}\nTitle: {}\nOrigin DB: {}", url, title, original_path.display());

    events.push(ForensicEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: ts,
        source: EventSource::Browser,
        macb: MacbFlags::new(false, true, false, false),
        actor: None,
        summary,
        path_or_target: Some(url),
        raw_artifact: raw,
        tactic,
        technique,
        confidence,
        anomaly_score,
        burst_id: None,
        is_suspicious,
        entropy: None,
        is_packed: false,
        extracted_strings: Vec::new(),
    });
}
