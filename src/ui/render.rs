use crate::analysis::entropy::{classify_entropy, entropy_spark_bar_parts, EntropyClass};
use crate::defense::ShadowTrapState;
use crate::models::{EventSource, MacbFlags};
use crate::ui::app::{AppState, FocusedPane};
use crate::ui::theme::DfirTheme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Clear, List, ListItem, Paragraph, Sparkline,
        Wrap,
    },
    Frame,
};

pub fn render_ui(f: &mut Frame, state: &mut AppState) {
    let size = f.area();

    // Base background
    f.render_widget(Block::default().style(DfirTheme::base_style()), size);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header banner
            Constraint::Length(4), // Activity Sparkline
            Constraint::Min(12),   // Main split panes
            Constraint::Length(1), // Footer hotkeys
        ])
        .split(size);

    render_header(f, state, chunks[0]);
    render_sparkline(f, state, chunks[1]);
    render_main_panes(f, state, chunks[2]);
    render_footer(f, state, chunks[3]);

    // Modals
    if state.trap_freeze_modal_open {
        render_trap_freeze_modal(f, state);
    } else if state.filter_modal_open {
        render_filter_modal(f, state);
    } else if state.help_modal_open {
        render_help_modal(f);
    }
}

fn render_header(f: &mut Frame, state: &AppState, area: Rect) {
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

    let title_line = Line::from(vec![
        Span::styled(
            " CHRONO-SHARD ",
            Style::default()
                .bg(DfirTheme::CYAN_TIMESTAMP)
                .fg(DfirTheme::OBSIDIAN_BG)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            "DFIR TIME-MACHINE",
            Style::default()
                .fg(DfirTheme::TEXT_PRIMARY)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" [{:.2}s sweep]", state.collection_duration_secs),
            Style::default().fg(DfirTheme::EMERALD_CLEAN),
        ),
    ]);

    let title_widget = Paragraph::new(title_line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DfirTheme::BORDER_NORMAL))
                .style(Style::default().bg(DfirTheme::PANEL_BG)),
        )
        .alignment(Alignment::Left);

    f.render_widget(title_widget, header_chunks[0]);

    // Status badges on the right
    let notif_text = state.current_notification().unwrap_or("");
    let ai_status = if state.is_ai_running {
        Span::styled(
            " [AI STREAMING...] ",
            Style::default()
                .bg(DfirTheme::AMBER_BURST)
                .fg(DfirTheme::OBSIDIAN_BG)
                .add_modifier(Modifier::BOLD),
        )
    } else if state.ai_report.is_some() {
        Span::styled(
            " [AI SYNTHESIS READY] ",
            Style::default()
                .bg(DfirTheme::EMERALD_CLEAN)
                .fg(DfirTheme::OBSIDIAN_BG)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " [AI STANDBY] ",
            Style::default().fg(DfirTheme::TEXT_DIM),
        )
    };

    let filter_badge = if state.filter_active {
        Span::styled(
            format!(" [FILTER: \"{}\"] ", state.filter_query),
            Style::default()
                .bg(DfirTheme::MAGENTA_EVASION)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" [ALL EVENTS] ", Style::default().fg(DfirTheme::TEXT_DIM))
    };

    let trap_badge = match &state.shadow_trap.state {
        ShadowTrapState::Disarmed => {
            Span::styled(" [TRAP: STANDBY] ", Style::default().fg(DfirTheme::TEXT_DIM))
        }
        ShadowTrapState::Armed { target_path, .. } => {
            let fname = target_path.file_name().unwrap_or_default().to_string_lossy();
            Span::styled(
                format!(" [SHADOW TRAP ARMED: {}] ", fname),
                Style::default()
                    .bg(DfirTheme::CYAN_TIMESTAMP)
                    .fg(DfirTheme::OBSIDIAN_BG)
                    .add_modifier(Modifier::BOLD),
            )
        }
        ShadowTrapState::Triggered { pid, is_frozen, .. } => {
            if *is_frozen {
                Span::styled(
                    format!(" [INTERCEPTED & FROZEN — PID {} SUSPENDED VIA SIGSTOP] [Press R] ", pid),
                    Style::default()
                        .bg(DfirTheme::CRIMSON_ALERT)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled(
                    format!(" [TRAP RESOLVED — PID {}] ", pid),
                    Style::default()
                        .bg(DfirTheme::EMERALD_CLEAN)
                        .fg(DfirTheme::OBSIDIAN_BG)
                        .add_modifier(Modifier::BOLD),
                )
            }
        }
    };

    let status_line = Line::from(vec![
        Span::styled(
            format!("Events: {} ", state.filtered_indices.len()),
            Style::default().fg(DfirTheme::CYAN_TIMESTAMP),
        ),
        Span::styled(
            format!("| Bursts: {} ", state.bursts.len()),
            Style::default().fg(DfirTheme::AMBER_BURST),
        ),
        filter_badge,
        Span::raw(" "),
        trap_badge,
        Span::raw(" "),
        ai_status,
        Span::raw(" "),
        Span::styled(notif_text, Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD)),
    ]);

    let status_widget = Paragraph::new(status_line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(DfirTheme::BORDER_NORMAL))
                .style(Style::default().bg(DfirTheme::PANEL_BG)),
        )
        .alignment(Alignment::Right);

    f.render_widget(status_widget, header_chunks[1]);
}

fn render_sparkline(f: &mut Frame, state: &AppState, area: Rect) {
    let sparkline_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DfirTheme::BORDER_NORMAL))
        .title(Span::styled(
            " Temporal Horizon Activity Density (Sparkline) ",
            Style::default()
                .fg(DfirTheme::CYAN_TIMESTAMP)
                .add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(DfirTheme::PANEL_BG));

    let sparkline = Sparkline::default()
        .block(sparkline_block)
        .data(&state.sparkline_buckets)
        .style(Style::default().fg(DfirTheme::AMBER_BURST));

    f.render_widget(sparkline, area);
}

fn render_main_panes(f: &mut Frame, state: &AppState, area: Rect) {
    let horizontal_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(58), // Timeline
            Constraint::Percentage(42), // Inspector + AI
        ])
        .split(area);

    render_timeline(f, state, horizontal_split[0]);

    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // Inspector
            Constraint::Percentage(55), // AI Narrative
        ])
        .split(horizontal_split[1]);

    render_inspector(f, state, right_split[0]);
    render_ai_narrative(f, state, right_split[1]);
}

fn render_timeline(f: &mut Frame, state: &AppState, area: Rect) {
    let is_focused = state.focused_pane == FocusedPane::Timeline;
    let block = DfirTheme::panel_block("Kill-Chain Timeline", is_focused);

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.filtered_indices.is_empty() {
        let empty_msg = Paragraph::new("No forensic events matching criteria.")
            .style(Style::default().fg(DfirTheme::TEXT_DIM))
            .alignment(Alignment::Center);
        f.render_widget(empty_msg, inner);
        return;
    }

    let visible_rows = inner.height as usize;
    let total_events = state.filtered_indices.len();

    // Compute window scroll to keep cursor centered
    let half_window = visible_rows / 2;
    let start_idx = if state.selected_index > half_window {
        (state.selected_index - half_window).min(total_events.saturating_sub(visible_rows))
    } else {
        0
    };
    let end_idx = (start_idx + visible_rows).min(total_events);

    let mut list_items = Vec::new();

    for idx in start_idx..end_idx {
        let is_selected = idx == state.selected_index;
        let orig_idx = state.filtered_indices[idx];
        let ev = &state.all_events[orig_idx];

        let cursor_span = if is_selected {
            Span::styled(
                " > ",
                Style::default()
                    .fg(DfirTheme::CYAN_TIMESTAMP)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("   ")
        };

        let time_str = ev.timestamp.format("%H:%M:%S%.3f").to_string();
        let time_span = Span::styled(
            format!("{:<12} ", time_str),
            Style::default().fg(DfirTheme::CYAN_TIMESTAMP),
        );

        let macb_spans = format_macb_spans(&ev.macb);

        let src_label = match ev.source {
            EventSource::Filesystem => "FS   ",
            EventSource::AuthLog => "AUTH ",
            EventSource::ShellHistory => "SHELL",
            EventSource::Persistence => "CRON ",
            EventSource::Browser => "WEB  ",
            EventSource::Syslog => "SYS  ",
        };
        let src_span = Span::styled(
            format!(" {:<5} ", src_label),
            Style::default()
                .fg(Color::Rgb(140, 160, 190))
                .add_modifier(Modifier::BOLD),
        );

        let tactic_span = if let Some(tactic) = ev.tactic {
            Span::styled(
                format!(" [{:<10}] ", tactic.name()),
                Style::default().fg(DfirTheme::tactic_color(Some(tactic))),
            )
        } else {
            Span::styled(" [          ] ", Style::default().fg(DfirTheme::TEXT_DIM))
        };

        let anomaly_span = if ev.anomaly_score >= 0.8 {
            Span::styled(
                " [CRIT] ",
                Style::default()
                    .bg(DfirTheme::CRIMSON_ALERT)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
        } else if ev.anomaly_score >= 0.5 {
            Span::styled(
                " [WARN] ",
                Style::default()
                    .bg(DfirTheme::AMBER_BURST)
                    .fg(DfirTheme::OBSIDIAN_BG)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("        ")
        };

        let burst_span = if let Some(b_id) = ev.burst_id {
            Span::styled(
                format!("⚡#{} ", b_id),
                Style::default().fg(DfirTheme::AMBER_BURST),
            )
        } else {
            Span::raw("    ")
        };

        let summary_style = if is_selected {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else if ev.is_suspicious {
            Style::default().fg(DfirTheme::TEXT_PRIMARY)
        } else {
            Style::default().fg(DfirTheme::TEXT_DIM)
        };

        let summary_span = Span::styled(ev.summary.clone(), summary_style);

        let mut spans = vec![
            cursor_span,
            time_span,
            Span::raw("["),
        ];
        spans.extend(macb_spans);
        spans.extend(vec![
            Span::raw("]"),
            src_span,
            tactic_span,
            anomaly_span,
            burst_span,
            summary_span,
        ]);

        let row_style = if is_selected {
            Style::default().bg(Color::Rgb(28, 38, 56))
        } else {
            Style::default()
        };

        list_items.push(ListItem::new(Line::from(spans)).style(row_style));
    }

    // Pre-Crime Shadow Trap: Predicted Next Step Node
    let trap_item = match &state.shadow_trap.state {
        ShadowTrapState::Disarmed => {
            let next_move = state
                .ai_report
                .as_ref()
                .and_then(|r| r.predicted_next_move.as_ref());

            let (tactic, tech, prob, target) = if let Some(m) = next_move {
                (
                    m.tactic.as_str(),
                    m.technique_id.as_str(),
                    (m.probability * 100.0) as u32,
                    m.likely_target_path.as_str(),
                )
            } else {
                (
                    "Credential Access",
                    "T1552.004",
                    92,
                    "/tmp/demo_env/.aws_prod_keys.bak",
                )
            };

            ListItem::new(Line::from(vec![
                Span::styled("   ⚡ 🔮 ", Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD)),
                Span::styled("PREDICTED NEXT STEP", Style::default().bg(DfirTheme::AMBER_BURST).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" [{}: {}] ", tactic, tech), Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD)),
                Span::styled(format!("Target: {} ({}% prob) ", target, prob), Style::default().fg(Color::White)),
                Span::styled("[Press T to Arm Shadow Trap]", Style::default().bg(DfirTheme::CYAN_TIMESTAMP).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
            ])).style(Style::default().bg(Color::Rgb(28, 24, 16)))
        }
        ShadowTrapState::Armed { target_path, .. } => {
            ListItem::new(Line::from(vec![
                Span::styled("   ⚡ 🔒 ", Style::default().fg(DfirTheme::CYAN_TIMESTAMP).add_modifier(Modifier::BOLD)),
                Span::styled("SHADOW TRAP ARMED", Style::default().bg(DfirTheme::CYAN_TIMESTAMP).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" Decoy Canary: {} ", target_path.display()), Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
                Span::styled("— Kernel inotify monitoring active... Awaiting adversary ingress", Style::default().fg(Color::Rgb(180, 240, 255))),
            ])).style(Style::default().bg(Color::Rgb(12, 28, 38)))
        }
        ShadowTrapState::Triggered { pid, cmdline, is_frozen, .. } => {
            ListItem::new(Line::from(vec![
                Span::styled("   ⚡ ☠ ", Style::default().fg(DfirTheme::CRIMSON_ALERT).add_modifier(Modifier::BOLD)),
                Span::styled("INTERCEPTED & FROZEN", Style::default().bg(DfirTheme::CRIMSON_ALERT).fg(Color::White).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" PID {} [{}] ", pid, cmdline), Style::default().fg(DfirTheme::CRIMSON_ALERT).add_modifier(Modifier::BOLD)),
                Span::styled(
                    if *is_frozen { "SUSPENDED VIA SIGSTOP [Press R: Resume/Kill]" } else { "RESOLVED (SIGCONT/SIGKILL)" },
                    Style::default().bg(Color::Rgb(70, 20, 28)).fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ])).style(Style::default().bg(Color::Rgb(38, 12, 18)))
        }
    };
    list_items.push(trap_item);

    let list = List::new(list_items);
    f.render_widget(list, inner);
}

fn format_macb_spans(macb: &MacbFlags) -> Vec<Span<'static>> {
    vec![
        if macb.modified {
            Span::styled("M", Style::default().fg(DfirTheme::CRIMSON_ALERT).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(".", Style::default().fg(DfirTheme::TEXT_DIM))
        },
        if macb.accessed {
            Span::styled("A", Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(".", Style::default().fg(DfirTheme::TEXT_DIM))
        },
        if macb.changed {
            Span::styled("C", Style::default().fg(DfirTheme::CYAN_TIMESTAMP).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(".", Style::default().fg(DfirTheme::TEXT_DIM))
        },
        if macb.born {
            Span::styled("B", Style::default().fg(DfirTheme::EMERALD_CLEAN).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(".", Style::default().fg(DfirTheme::TEXT_DIM))
        },
    ]
}

fn render_inspector(f: &mut Frame, state: &AppState, area: Rect) {
    let is_focused = state.focused_pane == FocusedPane::Inspector;
    let block = DfirTheme::panel_block("Forensic Artifact Inspector", is_focused);

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(ev) = state.selected_event() {
        let mut lines = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Timestamp (UTC): ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(
                ev.timestamp.to_rfc3339(),
                Style::default().fg(DfirTheme::CYAN_TIMESTAMP).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled("Source: ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(ev.source.as_str(), Style::default().fg(Color::Yellow)),
        ]));

        lines.push(Line::from(vec![
            Span::styled("MACB Flags: ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(
                format!("{} ", ev.macb.to_macb_string()),
                Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "(M=Modified, A=Accessed, C=Metadata/Inode, B=Born/Created)",
                Style::default().fg(DfirTheme::TEXT_DIM),
            ),
        ]));

        if let Some(tactic) = ev.tactic {
            let tech_id = ev.technique.as_ref().map(|t| t.id.as_str()).unwrap_or("N/A");
            let tech_name = ev.technique.as_ref().map(|t| t.name.as_str()).unwrap_or("N/A");

            lines.push(Line::from(vec![
                Span::styled("MITRE Tactic: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    format!("{} ({})", tactic.name(), tactic.id()),
                    Style::default().fg(DfirTheme::tactic_color(Some(tactic))).add_modifier(Modifier::BOLD),
                ),
            ]));

            lines.push(Line::from(vec![
                Span::styled("MITRE Technique: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    format!("{} - {}", tech_id, tech_name),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Target / Path: ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(
                ev.path_or_target.as_deref().unwrap_or("None"),
                Style::default().fg(Color::Cyan),
            ),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Threat Severity: ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(
                format!("{:.0}% (Score: {:.2})", ev.anomaly_score * 100.0, ev.anomaly_score),
                DfirTheme::confidence_style(ev.confidence),
            ),
            Span::raw(" | "),
            Span::styled("Confidence: ", Style::default().fg(DfirTheme::TEXT_DIM)),
            Span::styled(ev.confidence.as_str(), DfirTheme::confidence_style(ev.confidence)),
        ]));

        lines.push(Line::from(Span::styled(
            "--- Raw Forensic Telemetry ---",
            Style::default().fg(DfirTheme::TEXT_DIM),
        )));

        for raw_line in ev.raw_artifact.lines() {
            lines.push(Line::from(Span::styled(
                raw_line,
                Style::default().fg(Color::Rgb(180, 195, 215)),
            )));
        }

        // ── Entropy & Obfuscation Analysis ────────────────────────────────────
        if let Some(entropy) = ev.entropy {
            let eclass = classify_entropy(entropy);
            let bar_color = match eclass {
                EntropyClass::PackedOrEncrypted => DfirTheme::ENTROPY_PACKED,
                EntropyClass::HighEntropy       => DfirTheme::ENTROPY_HIGH,
                EntropyClass::Normal            => DfirTheme::ENTROPY_NORMAL,
            };
            let (label, label_color) = match eclass {
                EntropyClass::PackedOrEncrypted => (
                    " ⚠ PACKED / ENCRYPTED PAYLOAD (UPX / XOR likely) ",
                    DfirTheme::ENTROPY_PACKED,
                ),
                EntropyClass::HighEntropy => (
                    " ~ HIGH ENTROPY — compressed / suspicious ",
                    DfirTheme::ENTROPY_HIGH,
                ),
                EntropyClass::Normal => (" ✓ NORMAL ENTROPY ", DfirTheme::ENTROPY_NORMAL),
            };

            // Separator
            lines.push(Line::from(Span::styled(
                "── Entropy & Obfuscation Analysis ──────────────────────────────",
                Style::default().fg(DfirTheme::TEXT_DIM),
            )));

            // Spark-bar + numeric reading on one line (two-tone: active bar + dim track)
            let (bar_active, bar_dim) = entropy_spark_bar_parts(entropy);
            lines.push(Line::from(vec![
                Span::styled("Shannon Entropy  ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(bar_active, Style::default().fg(bar_color).add_modifier(Modifier::BOLD)),
                Span::styled(bar_dim, Style::default().fg(DfirTheme::ENTROPY_BAR_DIM)),
                Span::styled(
                    format!("  {:.2} / 8.00  ", entropy),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    label,
                    Style::default()
                        .fg(Color::Black)
                        .bg(label_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]));

            // Extracted strings section (only when available)
            if !ev.extracted_strings.is_empty() {
                lines.push(Line::from(Span::styled(
                    "── Extracted Printable Strings ─────────────────────────────────",
                    Style::default().fg(DfirTheme::TEXT_DIM),
                )));
                for s in ev.extracted_strings.iter().take(10) {
                    lines.push(Line::from(vec![
                        Span::styled(" › ", Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
                        Span::styled(
                            s.as_str(),
                            Style::default().fg(Color::Rgb(200, 220, 255)),
                        ),
                    ]));
                }
            }
        }

        // ── Pre-Crime Shadow Trap Intercept Telemetry ──────────────────────────
        match &state.shadow_trap.state {
            ShadowTrapState::Triggered {
                target_path,
                pid,
                cmdline,
                environ,
                triggered_at,
                is_frozen,
            } => {
                lines.push(Line::from(Span::styled(
                    "── Pre-Crime Shadow Trap :: Intercepted Adversary ───────────────",
                    Style::default().fg(DfirTheme::CRIMSON_ALERT).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(vec![
                    Span::styled("Trap Status: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(
                        if *is_frozen { "⚠ FROZEN IN KERNEL VIA SIGSTOP" } else { "RESUMED / TERMINATED" },
                        Style::default()
                            .fg(if *is_frozen { DfirTheme::CRIMSON_ALERT } else { DfirTheme::EMERALD_CLEAN })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" | "),
                    Span::styled("Decoy Canary: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(target_path.display().to_string(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Adversary PID: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(pid.to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                    Span::raw(" | "),
                    Span::styled("Command: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(cmdline.clone(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Triggered: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(triggered_at.to_rfc3339(), Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
                    Span::styled("  [Press R for SIGCONT / SIGKILL]", Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD)),
                ]));
                if !environ.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "Captured Environment:",
                        Style::default().fg(DfirTheme::TEXT_DIM),
                    )));
                    for env_var in environ.iter().take(5) {
                        lines.push(Line::from(vec![
                            Span::styled("   $ ", Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
                            Span::styled(env_var.as_str(), Style::default().fg(Color::Rgb(180, 200, 230))),
                        ]));
                    }
                }
            }
            ShadowTrapState::Armed { target_path, armed_at } => {
                lines.push(Line::from(Span::styled(
                    "── Pre-Crime Shadow Trap Active ────────────────────────────────",
                    Style::default().fg(DfirTheme::CYAN_TIMESTAMP).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(vec![
                    Span::styled("Canary Deployed: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(target_path.display().to_string(), Style::default().fg(Color::Cyan)),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("Armed At: ", Style::default().fg(DfirTheme::TEXT_DIM)),
                    Span::styled(armed_at.to_rfc3339(), Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
                    Span::styled("  (Kernel inotify active — will freeze on access)", Style::default().fg(DfirTheme::TEXT_DIM)),
                ]));
            }
            ShadowTrapState::Disarmed => {}
        }

        let paragraph = Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((state.inspector_scroll, 0));

        f.render_widget(paragraph, inner);
    } else {
        let no_sel = Paragraph::new("No event selected.").style(Style::default().fg(DfirTheme::TEXT_DIM));
        f.render_widget(no_sel, inner);
    }
}

fn render_ai_narrative(f: &mut Frame, state: &AppState, area: Rect) {
    let is_focused = state.focused_pane == FocusedPane::Narrative;
    let title = format!(
        "AI Incident Reconstruction [{}]",
        state.ai_model_label
    );
    let block = DfirTheme::panel_block(&title, is_focused);

    let inner = block.inner(area);
    f.render_widget(block, area);

    let content_text = if !state.ai_streaming_buffer.is_empty() {
        &state.ai_streaming_buffer
    } else if let Some(ref report) = state.ai_report {
        &report.kill_chain_narrative
    } else {
        "Press [a] to trigger the Gemini Dual-Model Forensic Analysis Pipeline.\n\n- gemini-3.5-flash-lite: Rapid temporal burst classification & anomaly triage\n- gemini-4-carbon: Deep MITRE ATT&CK kill-chain synthesis & timeline reconstruction"
    };

    let paragraph = Paragraph::new(content_text)
        .style(Style::default().fg(Color::Rgb(220, 230, 245)))
        .wrap(Wrap { trim: false })
        .scroll((state.narrative_scroll, 0));

    f.render_widget(paragraph, inner);
}

fn render_footer(f: &mut Frame, _state: &AppState, area: Rect) {
    let hotkeys = Line::from(vec![
        Span::styled(" [Tab] ", Style::default().bg(Color::Rgb(40, 50, 70)).fg(Color::White)),
        Span::raw(" Pane  "),
        Span::styled(" [↑/↓] ", Style::default().bg(Color::Rgb(40, 50, 70)).fg(Color::White)),
        Span::raw(" Nav  "),
        Span::styled(" [b] ", Style::default().bg(DfirTheme::AMBER_BURST).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
        Span::raw(" Burst  "),
        Span::styled(" [f] ", Style::default().bg(Color::Rgb(40, 50, 70)).fg(Color::White)),
        Span::raw(" Filter  "),
        Span::styled(" [T] ", Style::default().bg(DfirTheme::AMBER_BURST).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
        Span::raw(" Shadow Trap  "),
        Span::styled(" [R] ", Style::default().bg(DfirTheme::CRIMSON_ALERT).fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" Freeze Control  "),
        Span::styled(" [a] ", Style::default().bg(DfirTheme::CYAN_TIMESTAMP).fg(DfirTheme::OBSIDIAN_BG).add_modifier(Modifier::BOLD)),
        Span::raw(" Gemini Dual-AI  "),
        Span::styled(" [e] ", Style::default().bg(Color::Rgb(40, 50, 70)).fg(Color::White)),
        Span::raw(" Export  "),
        Span::styled(" [?] ", Style::default().bg(Color::Rgb(40, 50, 70)).fg(Color::White)),
        Span::raw(" Help  "),
        Span::styled(" [q] ", Style::default().bg(DfirTheme::CRIMSON_ALERT).fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::raw(" Quit"),
    ]);

    let footer_widget = Paragraph::new(hotkeys)
        .style(Style::default().bg(DfirTheme::OBSIDIAN_BG))
        .alignment(Alignment::Center);

    f.render_widget(footer_widget, area);
}

fn render_filter_modal(f: &mut Frame, state: &AppState) {
    let area = centered_rect(60, 20, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DfirTheme::CYAN_TIMESTAMP))
        .title(" Filter Forensic Timeline ")
        .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(DfirTheme::PANEL_BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let text = vec![
        Line::from("Filter by keyword, source, path, or MITRE tactic:"),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(DfirTheme::CYAN_TIMESTAMP)),
            Span::styled(&state.filter_query, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            Span::styled("_", Style::default().fg(DfirTheme::AMBER_BURST)),
        ]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" [Enter] ", Style::default().fg(DfirTheme::EMERALD_CLEAN)),
            Span::raw(" Apply Filter    "),
            Span::styled(" [Esc] ", Style::default().fg(DfirTheme::CRIMSON_ALERT)),
            Span::raw(" Cancel"),
        ]),
    ];

    let p = Paragraph::new(text).alignment(Alignment::Left);
    f.render_widget(p, inner);
}

fn render_trap_freeze_modal(f: &mut Frame, state: &AppState) {
    let area = centered_rect(65, 45, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DfirTheme::CRIMSON_ALERT))
        .title(" Pre-Crime Shadow Trap :: Adversary Process Freeze Control ")
        .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(DfirTheme::PANEL_BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if let ShadowTrapState::Triggered {
        pid,
        cmdline,
        is_frozen,
        target_path,
        ..
    } = &state.shadow_trap.state
    {
        let lines = vec![
            Line::from(Span::styled(
                "🚨 KERNEL PRE-CRIME INTERCEPT ACTIVE",
                Style::default()
                    .fg(DfirTheme::CRIMSON_ALERT)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::raw(""),
            Line::from(vec![
                Span::styled("Suspended PID:    ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    pid.to_string(),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Command Line:     ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    cmdline.clone(),
                    Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Decoy Canary:     ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    target_path.display().to_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ]),
            Line::from(vec![
                Span::styled("Kernel State:     ", Style::default().fg(DfirTheme::TEXT_DIM)),
                Span::styled(
                    if *is_frozen {
                        "FROZEN (Kernel SIGSTOP Active)"
                    } else {
                        "RESUMED / TERMINATED"
                    },
                    Style::default()
                        .fg(if *is_frozen {
                            DfirTheme::CRIMSON_ALERT
                        } else {
                            DfirTheme::EMERALD_CLEAN
                        })
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::raw(""),
            Line::from(Span::styled(
                "FORENSIC REMEDIATION ACTIONS:",
                Style::default()
                    .fg(DfirTheme::CYAN_TIMESTAMP)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(vec![
                Span::styled(
                    "  [C] ",
                    Style::default()
                        .bg(DfirTheme::EMERALD_CLEAN)
                        .fg(DfirTheme::OBSIDIAN_BG)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " Safely Resume process via SIGCONT",
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "  [K] ",
                    Style::default()
                        .bg(DfirTheme::CRIMSON_ALERT)
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    " Terminate adversary process via SIGKILL",
                    Style::default().fg(Color::White),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "  [Esc] ",
                    Style::default().bg(Color::Rgb(60, 70, 90)).fg(Color::White),
                ),
                Span::styled(" Dismiss control modal", Style::default().fg(DfirTheme::TEXT_DIM)),
            ]),
        ];
        let p = Paragraph::new(lines).alignment(Alignment::Left);
        f.render_widget(p, inner);
    }
}

fn render_help_modal(f: &mut Frame) {
    let area = centered_rect(70, 70, f.area());
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DfirTheme::CYAN_TIMESTAMP))
        .title(" CHRONO-SHARD :: Cyber-Forensics Quick Reference ")
        .title_style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
        .style(Style::default().bg(DfirTheme::PANEL_BG));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let lines = vec![
        Line::from(Span::styled("KEYBOARD SHORTCUTS:", Style::default().fg(DfirTheme::CYAN_TIMESTAMP).add_modifier(Modifier::BOLD))),
        Line::from("  [Tab]            Cycle focus between Timeline, Inspector, and AI Narrative"),
        Line::from("  [↑ / ↓]          Navigate events or scroll active pane"),
        Line::from("  [g / G]          Jump to top / bottom of timeline"),
        Line::from("  [b]              Jump to next anomalous temporal burst"),
        Line::from("  [f]              Open regex/text filter modal"),
        Line::from("  [c]              Clear active filter"),
        Line::from("  [T]              Deploy Pre-Crime Shadow Trap canary decoy & arm kernel monitor"),
        Line::from("  [R]              Freeze Control: safely resume (SIGCONT) or terminate (SIGKILL) intruder"),
        Line::from("  [a]              Trigger live Gemini Dual-Model AI Investigation"),
        Line::from("  [e]              Export full incident report to Markdown"),
        Line::from("  [q / Esc]        Quit CHRONO-SHARD"),
        Line::raw(""),
        Line::from(Span::styled("MACB FORENSIC TIMESTAMPS:", Style::default().fg(DfirTheme::AMBER_BURST).add_modifier(Modifier::BOLD))),
        Line::from("  M (Modified)     File content last written / changed"),
        Line::from("  A (Accessed)     File last read or executed"),
        Line::from("  C (Changed)      Inode / metadata status change (permissions, owner)"),
        Line::from("  B (Born)         Birth / creation timestamp (detects timestomping)"),
        Line::raw(""),
        Line::from(Span::styled("DUAL-MODEL GEMINI PIPELINE:", Style::default().fg(DfirTheme::EMERALD_CLEAN).add_modifier(Modifier::BOLD))),
        Line::from("  gemini-3.5-flash-lite: Sub-second triage, burst velocity classification"),
        Line::from("  gemini-4-carbon:       Deep MITRE ATT&CK kill-chain narrative & root cause analysis"),
        Line::raw(""),
        Line::from(Span::styled("Press [Esc] or [?] to close this help window.", Style::default().fg(DfirTheme::TEXT_DIM))),
    ];

    let p = Paragraph::new(lines).alignment(Alignment::Left);
    f.render_widget(p, inner);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
