# ⚡ CHRONO-SHARD :: Cyber Forensic Time-Machine

[![Rust Edition](https://img.shields.io/badge/Rust-2021%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![TUI](https://img.shields.io/badge/TUI-Ratatui%200.29-cyan.svg?style=flat-square)](https://github.com/ratatui/ratatui)
[![AI Engine](https://img.shields.io/badge/AI-Gemini%20Dual--Model-purple.svg?style=flat-square&logo=google)](https://ai.google.dev)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-v15.1%20Enterprise-crimson.svg?style=flat-square)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20Apache--2.0-blue.svg?style=flat-square)](#license)

**CHRONO-SHARD** is a blazing-fast, terminal-based (TUI) live digital forensics and incident response (DFIR) time-machine written in Rust. It sweeps live filesystem metadata (MACB timestamps), system authentication logs, shell histories, persistence mechanisms, and browser history databases in **under 2 seconds**, detects anomalous temporal bursts, and leverages Google Gemini's dual-model architecture (**`gemini-3.5-flash-lite` + `gemini-4-carbon`**) to reconstruct a cohesive, interactive **MITRE ATT&CK kill-chain timeline** directly inside a cyber-forensic terminal UI.

---

## 🏛️ High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                            CHRONO-SHARD ENGINE                               │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     │ PARALLEL TELEMETRY HARVESTERS (Sub-2s Rayon + Tokio Concurrency)  │
     ├─────────────────┬──────────────────┬────────────────┬─────────────┤
     │ Filesystem MACB │ Auth & PAM Logs  │ Shell History  │ Persistence │
     │ (/tmp, /dev/shm)│ (auth.log/audit) │ (bash/zsh/ps)  │ (cron/units)│
     └────────┬────────┴────────┬─────────┴────────┬───────┴──────┬──────┘
              │                 │                  │              │
              └─────────────────┼──────────────────┼──────────────┘
                                ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │  ANALYSIS & CORRELATION PIPELINE                                  │
     │  - Strict UTC Timestamp Normalization Across Disparate Formats    │
     │  - Fingerprint-based Deduplication                                │
     │  - Sliding-Window Temporal Burst Detection (> 3-sigma velocity)   │
     └──────────────────────────┬────────────────────────────────────────┘
                                │
                                ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │  DUAL-MODEL GEMINI AI PIPELINE (Token-Budgeted Context Packer)    │
     │  ├── Step 1: gemini-3.5-flash-lite (Rapid Triage & Classification)│
     │  └── Step 2: gemini-4-carbon       (Deep Kill-Chain Synthesis)    │
     └──────────────────────────┬────────────────────────────────────────┘
                                │ Live SSE Streaming
                                ▼
     ┌───────────────────────────────────────────────────────────────────┐
     │  RATATUI 60 FPS DFIR TERMINAL USER INTERFACE                      │
     │  - Header & Telemetry Sparkline (Activity Horizon)                │
     │  - Kill-Chain Timeline (Color-coded MACB flags & MITRE tactics)   │
     │  - Forensic Inspector (Permissions, Inodes, Raw Telemetry)        │
     │  - AI Narrative & Incident Reconstruction (Live Markdown stream)  │
     └───────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Capabilities

### 1. Sub-2-Second Parallel Telemetry Sweep
- **Rayon Parallel Traversal:** Concurrently sweeps high-risk forensic volatile directories (`/tmp`, `/dev/shm`, `/var/tmp`, `~/.local/share`, `%TEMP%`) extracting full **MACB** (Modified, Accessed, Changed, Born) metadata.
- **Timestomp Detection:** Automatically flags inverted timestamps (e.g. birth time after modification time or anomalous historical offsets) indicative of `touch -r` manipulation.
- **Lockless Browser SQLite Extraction:** Reads locked browser databases (Chrome, Edge, Firefox, Brave) in immutable read-only mode (`?mode=ro&immutable=1`) without process contention.

### 2. Sliding-Window Anomaly & Burst Detection
- Automatically clusters high-velocity forensic events within configurable sliding windows (default: 15 seconds).
- Identifies automated exploit stagers, rapid log wipers, and automated malware droppers.

### 3. Dual-Model Gemini AI Incident Reconstruction
- **`gemini-3.5-flash-lite` (Rapid Triage):** Sub-second categorization of unclassified telemetry, anomaly scoring, and immediate threat posture assessment.
- **`gemini-4-carbon` (Deep Kill-Chain Synthesis):** Synthesizes multi-stage attack narratives, maps tactics from Initial Access to Impact, isolates Root Cause, extracts IOCs, and drafts actionable remediation playbooks.
- **Zero-Latency Fallback:** Includes a built-in synthetic DFIR simulation engine for demonstration or offline incident response without active internet connection.

### 4. 60 FPS Obsidian/Cyan/Amber DFIR Terminal UI
- High-contrast DFIR color palette designed for cyber incident response war-rooms.
- Keyboard-driven split panes with instant filtering, cursor inspection, burst jumping, and one-key markdown report export.

---

## 🚀 Getting Started

### Prerequisites
- **Rust Toolchain:** Rust 1.75+ (Cargo edition 2021)
- **Optional API Key:** `GEMINI_API_KEY` for live AI synthesis (fallback mode available out-of-the-box).

### Compilation & Build

```bash
# Clone the repository
git clone https://github.com/your-org/chrono-shard.git
cd chrono-shard

# Build optimized release binary
cargo build --release
```

The resulting binary will be located at `target/release/chrono-shard`.

---

## 🕹️ Usage & CLI Options

```text
Usage: chrono-shard [OPTIONS]

Options:
  -s, --scan-path <PATH>        Custom directories or files to sweep
  -w, --window <SECONDS>        Sliding window duration for burst detection [default: 15]
  -b, --burst-threshold <COUNT> Event count threshold to trigger an anomalous burst [default: 8]
      --api-key <KEY>           Google Gemini API Key (or set GEMINI_API_KEY env var)
      --flash-model <MODEL>     Rapid triage model [default: gemini-3.5-flash-lite]
      --carbon-model <MODEL>    Deep kill-chain synthesis model [default: gemini-4-carbon]
      --simulate                Generate safe simulation attack artifacts for instant demo
      --export <FILE>           Export incident report directly to path without starting TUI
      --headless-ai             Run AI analysis in headless mode and stream report to stdout
  -h, --help                    Print help
  -V, --version                 Print version
```

### Quick Run Commands

```bash
# 1. Interactive Forensic TUI with Simulated Attack Telemetry
cargo run --release -- --simulate

# 2. Live Forensic Sweep of Host System with Gemini Dual-Model
export GEMINI_API_KEY="your-api-key"
cargo run --release

# 3. Headless Forensic Sweep and Automated Markdown Incident Report
cargo run --release -- --simulate --export incident_report.md
```

---

## ⌨️ TUI Keyboard Controls

| Key | Action |
|:---|:---|
| `Tab` | Cycle focus between **Timeline**, **Inspector**, and **AI Narrative** |
| `↑` / `↓` or `k` / `j` | Navigate events in Timeline or scroll focused pane |
| `g` / `G` | Jump to **beginning** / **end** of timeline |
| `b` | **Jump to next anomalous temporal burst** (⚡) |
| `f` | Open **regex/keyword filter modal** |
| `c` | **Clear** active filter |
| `a` | **Trigger Gemini Dual-AI Investigation** (streaming SSE narrative) |
| `e` | **Export full forensic incident report** to Markdown |
| `?` | Toggle **Help & MITRE ATT&CK reference modal** |
| `q` / `Esc` | Quit CHRONO-SHARD |

---

## 🧪 Safe Attack Simulation Workflow

CHRONO-SHARD comes equipped with safe, reversible demo scripts:

### Linux / Unix Simulation:
```bash
# Run simulated intrusion (Initial Access -> Staging -> Timestomping -> Cron Persistence)
chmod +x scripts/simulate_attack.sh
./scripts/simulate_attack.sh

# Launch CHRONO-SHARD to investigate
cargo run --release

# Revert and clean up simulation artifacts
./scripts/simulate_attack.sh --clean
```

### Windows Simulation:
```powershell
# Run PowerShell attack simulator
.\scripts\simulate_attack.ps1

# Launch CHRONO-SHARD
cargo run --release -- --simulate

# Revert and clean up simulation artifacts
.\scripts\simulate_attack.ps1 -Clean
```

---

## 🎯 MITRE ATT&CK Matrix Coverage

| Tactic | Technique ID | Technique Name | Evidence Source |
|:---|:---|:---|:---|
| **Initial Access** | `T1105` | Ingress Tool Transfer | Browser downloads, curl staging in `/tmp` |
| **Initial Access** | `T1078` | Valid Accounts | Auth log accepted SSH keys from foreign IP |
| **Execution** | `T1059.004` | Unix Shell | Shell history, executed staging scripts |
| **Persistence** | `T1053.003` | Scheduled Task: Cron | `/etc/cron.d/`, user crontabs |
| **Persistence** | `T1543.002` | Systemd Service | Injected `.service` units in `/etc/systemd/` |
| **Persistence** | `T1098.004` | SSH Authorized Keys | Injected public keys in `~/.ssh/authorized_keys` |
| **Privilege Escalation** | `T1548.003` | Sudo Caching Abuse | Sudo commands logged in `auth.log` |
| **Defense Evasion** | `T1070.006` | Timestomping | Filesystem MACB timestamp discrepancy |
| **Defense Evasion** | `T1070.003` | Clear Command History | Shell history `history -c`, `unset HISTFILE` |
| **Command & Control** | `T1071.001` | Web Protocols | Browser history, reverse shell TCP sockets |

---

## 📄 License
Dual-licensed under either Apache 2.0 or MIT at your option.
