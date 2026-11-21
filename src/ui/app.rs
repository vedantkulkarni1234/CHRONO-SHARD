use crate::analysis::correlator::Correlator;
use crate::defense::{DEFAULT_CANARY_PATH, ShadowTrapEngine, ShadowTrapState, TrapTriggered};
use crate::models::{AiAnalysisReport, ForensicEvent, TemporalBurst};
use chrono::Utc;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPane {
    Timeline,
    Inspector,
    Narrative,
}

pub struct AppState {
    pub all_events: Vec<ForensicEvent>,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub bursts: Vec<TemporalBurst>,
    pub selected_burst_idx: usize,
    pub sparkline_buckets: Vec<u64>,
    pub focused_pane: FocusedPane,

    // AI state
    pub ai_report: Option<AiAnalysisReport>,
    pub ai_streaming_buffer: String,
    pub is_ai_running: bool,
    pub ai_model_label: String,

    // Search and filtering
    pub filter_query: String,
    pub filter_active: bool,
    pub filter_modal_open: bool,
    pub help_modal_open: bool,

    // Pane scrolling
    pub inspector_scroll: u16,
    pub narrative_scroll: u16,

    // Shadow Trap defense state
    pub shadow_trap: ShadowTrapEngine,
    pub trap_freeze_modal_open: bool,

    // Performance metrics
    pub collection_duration_secs: f64,
    pub notification: Option<(String, Instant)>,
    pub should_quit: bool,
}

impl AppState {
    pub fn new(
        events: Vec<ForensicEvent>,
        bursts: Vec<TemporalBurst>,
        collection_duration_secs: f64,
        ai_model_label: String,
    ) -> Self {
        let indices: Vec<usize> = (0..events.len()).collect();
        let sparkline = Correlator::generate_sparkline_buckets(&events, 50);

        Self {
            all_events: events,
            filtered_indices: indices,
            selected_index: 0,
            bursts,
            selected_burst_idx: 0,
            sparkline_buckets: sparkline,
            focused_pane: FocusedPane::Timeline,
            ai_report: None,
            ai_streaming_buffer: String::new(),
            is_ai_running: false,
            ai_model_label,
            filter_query: String::new(),
            filter_active: false,
            filter_modal_open: false,
            help_modal_open: false,
            inspector_scroll: 0,
            narrative_scroll: 0,
            shadow_trap: ShadowTrapEngine::new(),
            trap_freeze_modal_open: false,
            collection_duration_secs,
            notification: None,
            should_quit: false,
        }
    }

    pub fn selected_event(&self) -> Option<&ForensicEvent> {
        if self.filtered_indices.is_empty() {
            return None;
        }
        let original_idx = self.filtered_indices[self.selected_index];
        self.all_events.get(original_idx)
    }

    pub fn next_event(&mut self) {
        if !self.filtered_indices.is_empty() && self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
            self.inspector_scroll = 0;
        }
    }

    pub fn prev_event(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.inspector_scroll = 0;
        }
    }

    pub fn first_event(&mut self) {
        self.selected_index = 0;
        self.inspector_scroll = 0;
    }

    pub fn last_event(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
            self.inspector_scroll = 0;
        }
    }

    pub fn jump_next_burst(&mut self) {
        if self.bursts.is_empty() || self.filtered_indices.is_empty() {
            return;
        }
        self.selected_burst_idx = (self.selected_burst_idx + 1) % self.bursts.len();
        let target_burst_id = self.bursts[self.selected_burst_idx].id;

        // Find first event in filtered list with this burst_id
        for (pos, &orig_idx) in self.filtered_indices.iter().enumerate() {
            if self.all_events[orig_idx].burst_id == Some(target_burst_id) {
                self.selected_index = pos;
                self.inspector_scroll = 0;
                self.set_notification(format!("Jumped to Burst #{}", target_burst_id));
                break;
            }
        }
    }

    pub fn toggle_pane(&mut self) {
        self.focused_pane = match self.focused_pane {
            FocusedPane::Timeline => FocusedPane::Inspector,
            FocusedPane::Inspector => FocusedPane::Narrative,
            FocusedPane::Narrative => FocusedPane::Timeline,
        };
    }

    pub fn apply_filter(&mut self) {
        let q = self.filter_query.to_lowercase();
        if q.is_empty() {
            self.filtered_indices = (0..self.all_events.len()).collect();
            self.filter_active = false;
        } else {
            self.filtered_indices = self
                .all_events
                .iter()
                .enumerate()
                .filter(|(_, ev)| {
                    ev.summary.to_lowercase().contains(&q)
                        || ev.source.as_str().to_lowercase().contains(&q)
                        || ev.raw_artifact.to_lowercase().contains(&q)
                        || ev.path_or_target.as_deref().unwrap_or("").to_lowercase().contains(&q)
                        || ev.tactic.map(|t| t.name().to_lowercase()).unwrap_or_default().contains(&q)
                        || ev.macb.to_macb_string().to_lowercase().contains(&q)
                })
                .map(|(idx, _)| idx)
                .collect();
            self.filter_active = true;
        }
        self.selected_index = 0;
        self.filter_modal_open = false;
        self.set_notification(format!("Filter applied: {} matches", self.filtered_indices.len()));
    }

    pub fn clear_filter(&mut self) {
        self.filter_query.clear();
        self.filtered_indices = (0..self.all_events.len()).collect();
        self.filter_active = false;
        self.selected_index = 0;
        self.set_notification("Filter cleared".to_string());
    }

    pub fn scroll_up(&mut self) {
        match self.focused_pane {
            FocusedPane::Inspector => {
                if self.inspector_scroll > 0 {
                    self.inspector_scroll -= 1;
                }
            }
            FocusedPane::Narrative => {
                if self.narrative_scroll > 0 {
                    self.narrative_scroll = self.narrative_scroll.saturating_sub(3);
                }
            }
            FocusedPane::Timeline => self.prev_event(),
        }
    }

    pub fn scroll_down(&mut self) {
        match self.focused_pane {
            FocusedPane::Inspector => {
                self.inspector_scroll += 1;
            }
            FocusedPane::Narrative => {
                self.narrative_scroll += 3;
            }
            FocusedPane::Timeline => self.next_event(),
        }
    }

    pub fn set_notification(&mut self, msg: String) {
        self.notification = Some((msg, Instant::now()));
    }

    pub fn arm_shadow_trap(&mut self, tx: UnboundedSender<TrapTriggered>) {
        let path_str = self
            .ai_report
            .as_ref()
            .and_then(|r| r.predicted_next_move.as_ref())
            .map(|p| p.likely_target_path.clone())
            .unwrap_or_else(|| DEFAULT_CANARY_PATH.to_string());

        let target_path = PathBuf::from(path_str);
        if let Ok(()) = self.shadow_trap.arm(target_path.clone(), tx) {
            self.set_notification(format!("SHADOW TRAP ARMED on {}", target_path.display()));
        } else {
            self.set_notification("Failed to deploy Shadow Trap canary".to_string());
        }
    }

    pub fn handle_trap_triggered(&mut self, event: TrapTriggered) {
        let pid = event.pid;
        let cmdline = event.cmdline.clone();
        self.shadow_trap.state = ShadowTrapState::Triggered {
            target_path: event.target_path,
            pid,
            cmdline: event.cmdline,
            environ: event.environ,
            triggered_at: event.timestamp,
            is_frozen: true,
        };
        self.set_notification(format!(
            "ALERT: INTRUDER FROZEN — PID {} ({}) SUSPENDED VIA SIGSTOP",
            pid, cmdline
        ));
    }

    pub fn resume_trap_process(&mut self) {
        if let Ok(()) = self.shadow_trap.resume() {
            self.set_notification("Adversary process resumed via SIGCONT".to_string());
        }
    }

    pub fn kill_trap_process(&mut self) {
        if let Ok(()) = self.shadow_trap.kill() {
            self.set_notification("Adversary process terminated via SIGKILL".to_string());
        }
    }

    pub fn current_notification(&self) -> Option<&str> {
        if let Some((ref msg, instant)) = self.notification {
            if instant.elapsed().as_secs() < 4 {
                return Some(msg);
            }
        }
        None
    }

    pub fn export_report(&mut self) -> std::io::Result<String> {
        let filename = format!("chrono_shard_report_{}.md", Utc::now().format("%Y%m%d_%H%M%S"));
        let mut file = File::create(&filename)?;

        writeln!(file, "# CHRONO-SHARD DIGITAL FORENSICS INCIDENT REPORT")?;
        writeln!(file, "Generated: {}\n", Utc::now().to_rfc3339())?;
        writeln!(file, "## Collection Telemetry")?;
        writeln!(file, "- **Total Swept Events**: {}", self.all_events.len())?;
        writeln!(file, "- **Temporal Bursts Detected**: {}", self.bursts.len())?;
        writeln!(file, "- **Telemetry Collection Latency**: {:.3}s\n", self.collection_duration_secs)?;

        if let Some(ref report) = self.ai_report {
            writeln!(file, "## AI Investigation Report ({})", report.model_used)?;
            writeln!(file, "{}\n", report.kill_chain_narrative)?;
            writeln!(file, "### Indicators of Compromise (IOCs)")?;
            for ioc in &report.iocs {
                writeln!(file, "- `{}`", ioc)?;
            }
            writeln!(file, "\n### Actionable Remediation Steps")?;
            for step in &report.remediation_steps {
                writeln!(file, "- {}", step)?;
            }
        } else if !self.ai_streaming_buffer.is_empty() {
            writeln!(file, "## AI Narrative (Live Streamed)")?;
            writeln!(file, "{}\n", self.ai_streaming_buffer)?;
        }

        writeln!(file, "\n## Timeline of Correlated Forensic Events")?;
        writeln!(file, "| Timestamp (UTC) | Source | MACB | Tactic | Anomaly | Target / Summary |")?;
        writeln!(file, "|---|---|---|---|---|---|")?;

        for &idx in &self.filtered_indices {
            let ev = &self.all_events[idx];
            writeln!(
                file,
                "| {} | {} | `{}` | {:?} | {:.2} | {} |",
                ev.timestamp.to_rfc3339(),
                ev.source.as_str(),
                ev.macb.to_macb_string(),
                ev.tactic.map(|t| t.name()).unwrap_or("None"),
                ev.anomaly_score,
                ev.summary.replace('|', "\\|")
            )?;
        }

        self.set_notification(format!("Report exported to {}", filename));
        Ok(filename)
    }
}
