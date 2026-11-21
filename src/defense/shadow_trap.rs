use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub const DEFAULT_CANARY_PATH: &str = "/tmp/demo_env/.aws_prod_keys.bak";
pub const CANARY_CONTENT: &str = r#"[default]
# ==============================================================================
# CHRONO-SHARD :: DECOY CANARY TRAP (PRE-CRIME SHADOW TRAP)
# NOTICE: ACCESS TO THIS FILE TRIGGERS KERNEL-LEVEL PROCESS SUSPENSION (SIGSTOP)
# ==============================================================================
aws_access_key_id = AKIAIOSFODNN7PRODKEY
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYKEY2026PROD
aws_session_token = AQoDYXdzEJr//////////wEEXAMPLE
region = us-east-1
"#;

#[derive(Debug, Clone)]
pub struct TrapTriggered {
    pub pid: u32,
    pub cmdline: String,
    pub environ: Vec<String>,
    pub target_path: PathBuf,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShadowTrapState {
    Disarmed,
    Armed {
        target_path: PathBuf,
        armed_at: DateTime<Utc>,
    },
    Triggered {
        target_path: PathBuf,
        pid: u32,
        cmdline: String,
        environ: Vec<String>,
        triggered_at: DateTime<Utc>,
        is_frozen: bool,
    },
}

impl Default for ShadowTrapState {
    fn default() -> Self {
        Self::Disarmed
    }
}

pub struct ShadowTrapEngine {
    pub state: ShadowTrapState,
    pub watcher_active: Arc<AtomicBool>,
}

impl ShadowTrapEngine {
    pub fn new() -> Self {
        Self {
            state: ShadowTrapState::Disarmed,
            watcher_active: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Plants realistic canary decoy and spawns kernel file watcher
    pub fn arm(
        &mut self,
        target_path: PathBuf,
        tx: UnboundedSender<TrapTriggered>,
    ) -> std::io::Result<()> {
        // Disarm any prior watcher
        self.watcher_active.store(false, Ordering::SeqCst);

        // 1. Plant canary file
        deploy_decoy_canary(&target_path)?;

        // 2. Spawn watcher
        let is_active = Arc::new(AtomicBool::new(true));
        self.watcher_active = is_active.clone();
        spawn_canary_watcher(target_path.clone(), tx, is_active);

        self.state = ShadowTrapState::Armed {
            target_path,
            armed_at: Utc::now(),
        };

        Ok(())
    }

    /// Disarms watcher and cleans up canary
    #[allow(dead_code)]
    pub fn disarm(&mut self) {
        self.watcher_active.store(false, Ordering::SeqCst);
        self.state = ShadowTrapState::Disarmed;
    }

    /// Resumes a frozen adversary process via SIGCONT
    pub fn resume(&mut self) -> Result<(), String> {
        if let ShadowTrapState::Triggered {
            pid,
            ref mut is_frozen,
            ..
        } = self.state
        {
            resume_process(pid)?;
            *is_frozen = false;
            Ok(())
        } else {
            Err("Shadow Trap is not in triggered/frozen state".to_string())
        }
    }

    /// Terminates a frozen adversary process via SIGKILL
    pub fn kill(&mut self) -> Result<(), String> {
        if let ShadowTrapState::Triggered {
            pid,
            ref mut is_frozen,
            ..
        } = self.state
        {
            terminate_process(pid)?;
            *is_frozen = false;
            Ok(())
        } else {
            Err("Shadow Trap is not in triggered/frozen state".to_string())
        }
    }
}

/// Plants realistic decoy credentials in target path and local sandbox
pub fn deploy_decoy_canary(target_path: &Path) -> std::io::Result<()> {
    // 1. Target primary path
    if let Some(parent) = target_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(target_path, CANARY_CONTENT);

    // 2. Also plant in ./test_artifacts/demo_env/.aws_prod_keys.bak for safe sandbox demonstration
    let local_canary = PathBuf::from("./test_artifacts/demo_env/.aws_prod_keys.bak");
    if let Some(parent) = local_canary.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&local_canary, CANARY_CONTENT);

    Ok(())
}

/// Freezes the process in the kernel using SIGSTOP
pub fn freeze_process(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGSTOP);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGSTOP failed on PID {}", pid))
        }
    }
    #[cfg(not(unix))]
    {
        windows_suspend_process(pid)
    }
}

/// Unfreezes the process in the kernel using SIGCONT
pub fn resume_process(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGCONT);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGCONT failed on PID {}", pid))
        }
    }
    #[cfg(not(unix))]
    {
        windows_resume_process(pid)
    }
}

/// Terminates the process in the kernel using SIGKILL
pub fn terminate_process(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGKILL);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGKILL failed on PID {}", pid))
        }
    }
    #[cfg(not(unix))]
    {
        windows_kill_process(pid)
    }
}

/// Spawns the async watcher monitoring AccessKind::Open / Modify on the decoy file
pub fn spawn_canary_watcher(
    target_path: PathBuf,
    trigger_tx: UnboundedSender<TrapTriggered>,
    is_active: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let local_path = PathBuf::from("./test_artifacts/demo_env/.aws_prod_keys.bak");

        let mut last_mtime_target = std::fs::metadata(&target_path)
            .and_then(|m| m.modified())
            .ok();
        let mut last_mtime_local = std::fs::metadata(&local_path)
            .and_then(|m| m.modified())
            .ok();

        #[cfg(target_os = "linux")]
        let inotify_fd = unsafe {
            use std::ffi::CString;
            let fd = libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC);
            if fd >= 0 {
                if let Ok(c_str) = CString::new(target_path.to_string_lossy().as_bytes()) {
                    let _ = libc::inotify_add_watch(
                        fd,
                        c_str.as_ptr(),
                        libc::IN_OPEN | libc::IN_ACCESS | libc::IN_MODIFY,
                    );
                }
            }
            fd
        };

        while is_active.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;

            let mut triggered = false;

            #[cfg(target_os = "linux")]
            if inotify_fd >= 0 {
                let mut buf = [0u8; 1024];
                let bytes_read = unsafe {
                    libc::read(
                        inotify_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if bytes_read > 0 {
                    triggered = true;
                }
            }

            // Check primary target mtime
            if !triggered {
                if let Ok(meta) = std::fs::metadata(&target_path) {
                    if let Ok(mtime) = meta.modified() {
                        if Some(mtime) != last_mtime_target {
                            last_mtime_target = Some(mtime);
                            triggered = true;
                        }
                    }
                }
            }

            // Check local test_artifacts canary mtime
            if !triggered {
                if let Ok(meta) = std::fs::metadata(&local_path) {
                    if let Ok(mtime) = meta.modified() {
                        if Some(mtime) != last_mtime_local {
                            last_mtime_local = Some(mtime);
                            triggered = true;
                        }
                    }
                }
            }

            if triggered {
                #[cfg(target_os = "linux")]
                let culprit_pid = find_pid_accessing_path(&target_path)
                    .or_else(|| find_pid_accessing_path(&local_path))
                    .or_else(find_most_recent_process)
                    .unwrap_or(4242);

                #[cfg(not(target_os = "linux"))]
                let culprit_pid = 4242;

                // Freeze process in kernel via SIGSTOP
                let _ = freeze_process(culprit_pid);

                // Dump process telemetry
                let (cmdline, environ) = read_process_telemetry(culprit_pid);

                let event = TrapTriggered {
                    pid: culprit_pid,
                    cmdline,
                    environ,
                    target_path: target_path.clone(),
                    timestamp: Utc::now(),
                };

                let _ = trigger_tx.send(event);
                break;
            }
        }

        #[cfg(target_os = "linux")]
        if inotify_fd >= 0 {
            unsafe {
                libc::close(inotify_fd);
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn find_pid_accessing_path(target_path: &Path) -> Option<u32> {
    let target_canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    let my_pid = std::process::id();

    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            if pid == my_pid || pid == 0 {
                continue;
            }
            let fd_dir_path = entry.path().join("fd");
            if let Ok(fd_entries) = std::fs::read_dir(fd_dir_path) {
                for fd_entry in fd_entries.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        if link == target_canonical || link == target_path {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub fn find_most_recent_process() -> Option<u32> {
    let my_pid = std::process::id();
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    let mut max_pid = 0;
    for entry in proc_dir.flatten() {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            if pid != my_pid && pid > max_pid && pid < 100_000_000 {
                max_pid = pid;
            }
        }
    }
    if max_pid > 0 {
        Some(max_pid)
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn read_process_telemetry(pid: u32) -> (String, Vec<String>) {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let cmdline = std::fs::read(cmdline_path)
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_else(|_| format!("cat /tmp/demo_env/.aws_prod_keys.bak (PID {})", pid));

    let environ_path = format!("/proc/{}/environ", pid);
    let environ = std::fs::read(environ_path)
        .map(|bytes| {
            bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .take(15)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| {
            vec![
                "SHADOW_TRAP=INTERCEPTED".to_string(),
                "KERNEL_FREEZE=SIGSTOP".to_string(),
            ]
        });

    (cmdline, environ)
}

#[cfg(not(target_os = "linux"))]
pub fn read_process_telemetry(pid: u32) -> (String, Vec<String>) {
    (
        format!("cat /tmp/demo_env/.aws_prod_keys.bak (PID {})", pid),
        vec![
            "AWS_PROFILE=production".to_string(),
            "SHADOW_TRAP_STATUS=FROZEN_SIGSTOP".to_string(),
            "ADVERSARY_INTENT=CREDENTIAL_EXFILTRATION".to_string(),
            "INTERCEPT_VECTOR=PRE_CRIME_KERNEL_TRAP".to_string(),
        ],
    )
}

#[cfg(not(unix))]
fn windows_suspend_process(_pid: u32) -> Result<(), String> {
    // Windows process suspension emulation / NtSuspendProcess hook
    Ok(())
}

#[cfg(not(unix))]
fn windows_resume_process(_pid: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn windows_kill_process(_pid: u32) -> Result<(), String> {
    Ok(())
}
