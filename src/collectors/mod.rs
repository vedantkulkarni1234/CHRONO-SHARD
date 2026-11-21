pub mod auth_logs;
pub mod browser;
pub mod filesystem;
pub mod persistence;
pub mod shell_history;

use crate::models::ForensicEvent;
use std::path::PathBuf;
use std::time::Instant;

pub struct CollectorManager {
    pub filesystem: filesystem::FilesystemCollector,
    pub auth_logs: auth_logs::AuthLogCollector,
    pub shell_history: shell_history::ShellHistoryCollector,
    pub persistence: persistence::PersistenceCollector,
    pub browser: browser::BrowserCollector,
}

impl CollectorManager {
    pub fn new(custom_paths: Vec<PathBuf>) -> Self {
        Self {
            filesystem: filesystem::FilesystemCollector::new(custom_paths.clone()),
            auth_logs: auth_logs::AuthLogCollector::new(custom_paths.clone()),
            shell_history: shell_history::ShellHistoryCollector::new(custom_paths.clone()),
            persistence: persistence::PersistenceCollector::new(custom_paths.clone()),
            browser: browser::BrowserCollector::new(custom_paths),
        }
    }

    /// Parallel sweep of all digital forensic telemetry sources in sub-2 seconds
    pub fn sweep_all(&self) -> (Vec<ForensicEvent>, f64) {
        let start = Instant::now();

        // Run collectors concurrently using rayon or scoped joins
        let (mut fs_events, (mut auth_events, (mut shell_events, (mut persist_events, mut browser_events)))) =
            rayon::join(
                || self.filesystem.collect(),
                || {
                    rayon::join(
                        || self.auth_logs.collect(),
                        || {
                            rayon::join(
                                || self.shell_history.collect(),
                                || rayon::join(
                                    || self.persistence.collect(),
                                    || self.browser.collect(),
                                ),
                            )
                        },
                    )
                },
            );

        let mut all_events = Vec::with_capacity(
            fs_events.len()
                + auth_events.len()
                + shell_events.len()
                + persist_events.len()
                + browser_events.len(),
        );

        all_events.append(&mut fs_events);
        all_events.append(&mut auth_events);
        all_events.append(&mut shell_events);
        all_events.append(&mut persist_events);
        all_events.append(&mut browser_events);

        let duration_secs = start.elapsed().as_secs_f64();
        (all_events, duration_secs)
    }
}
