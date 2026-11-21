use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;

pub const DEFAULT_CANARY_PATH: &str = if cfg!(windows) {
    ".\\test_artifacts\\demo_env\\.aws_prod_keys.bak"
} else {
    "/tmp/demo_env/.aws_prod_keys.bak"
};

pub const CANARY_CONTENT: &str = r#"[default]
# ==============================================================================
# CHRONO-SHARD :: DECOY CANARY TRAP (PRE-CRIME SHADOW TRAP)
# NOTICE: ACCESS TO THIS FILE TRIGGERS KERNEL-LEVEL PROCESS SUSPENSION
# ==============================================================================
aws_access_key_id = AKIAIOSFODNN7PRODKEY
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYKEY2026PROD
aws_session_token = AQoDYXdzEJr//////////wEEXAMPLE
region = us-east-1
"#;

// ─────────────────────────────────────────────────────────
// Windows kernel-level implementation
// ─────────────────────────────────────────────────────────
#[cfg(windows)]
mod win32 {
    use std::path::Path;

    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        OpenThread, SuspendThread, ResumeThread,
        PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
        THREAD_SUSPEND_RESUME,
    };
    use windows::core::{s, PWSTR};

    // ── NT function pointer types (loaded from ntdll.dll at runtime) ──────────
    type NtQuerySystemInfoFn =
        unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;
    type NtDuplicateObjectFn =
        unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, u32, u32) -> i32;
    type NtQueryObjectFn =
        unsafe extern "system" fn(HANDLE, u32, *mut u8, u32, *mut u32) -> i32;
    type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;
    type NtResumeProcessFn  = unsafe extern "system" fn(HANDLE) -> i32;

    // ── SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX (SystemExtendedHandleInformation = 0x40) ─
    #[repr(C)]
    struct SystemHandleEntryEx {
        object:              usize, // PVOID  (8 bytes on 64-bit)
        unique_process_id:   usize, // ULONG_PTR
        handle_value:        usize, // ULONG_PTR
        granted_access:      u32,
        _creator_back_trace: u16,
        object_type_index:   u16,
        handle_attributes:   u32,
        _reserved:           u32,
    }

    #[repr(C)]
    struct SystemHandleInfoEx {
        number_of_handles: usize,
        _reserved:         usize,
        // entries follow in memory
    }

    // ── Enumerate all open handles and find one pointing at our canary file ───
    pub fn find_pid_accessing_file(target_path: &Path) -> Option<u32> {
        let my_pid = std::process::id() as usize;

        unsafe {
            let ntdll = GetModuleHandleA(s!("ntdll.dll")).ok()?;

            // Load NT functions
            let nt_query: NtQuerySystemInfoFn =
                std::mem::transmute(GetProcAddress(ntdll, s!("NtQuerySystemInformation"))?);
            let nt_dup: NtDuplicateObjectFn =
                std::mem::transmute(GetProcAddress(ntdll, s!("NtDuplicateObject"))?);
            let nt_qobj: NtQueryObjectFn =
                std::mem::transmute(GetProcAddress(ntdll, s!("NtQueryObject"))?);

            // ── Step 1: get our own kernel Object pointer for the canary file ──
            // Open canary file for read
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
            };
            use windows::Win32::Foundation::GENERIC_READ;
            use windows::core::PCWSTR;

            let wide: Vec<u16> = target_path
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let my_file_handle = CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            .ok()?;

            // Find our handle's Object pointer via the handle table
            let my_object_ptr = get_object_ptr_for_handle(nt_query, my_file_handle, my_pid);
            let _ = CloseHandle(my_file_handle);

            let my_object_ptr = my_object_ptr?;

            // ── Step 2: enumerate ALL handles looking for same Object ptr, different PID ──
            // Allocate growing buffer
            let mut buf_size: u32 = 1 << 22; // 4 MB initial
            let mut buf: Vec<u8>;
            let mut ret_len: u32 = 0;
            const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004_u32 as i32;
            loop {
                buf = vec![0u8; buf_size as usize];
                let status = nt_query(
                    0x40, // SystemExtendedHandleInformation
                    buf.as_mut_ptr(),
                    buf_size,
                    &mut ret_len,
                );
                if status == 0 {
                    break;
                } else if status == STATUS_INFO_LENGTH_MISMATCH {
                    buf_size = ret_len + 4096;
                } else {
                    return None;
                }
            }

            let header = &*(buf.as_ptr() as *const SystemHandleInfoEx);
            let count = header.number_of_handles;
            let entries_ptr = buf
                .as_ptr()
                .add(std::mem::size_of::<SystemHandleInfoEx>())
                as *const SystemHandleEntryEx;

            let current_process = windows::Win32::System::Threading::GetCurrentProcess();
            let pseudo_current: HANDLE = HANDLE(-1isize as *mut _);

            for i in 0..count {
                let entry = &*entries_ptr.add(i);
                let pid = entry.unique_process_id as u32;

                // Skip our own process
                if pid as usize == my_pid {
                    continue;
                }

                // Fast path: if Object pointer matches, this is our file
                if entry.object == my_object_ptr {
                    return Some(pid);
                }

                // Slow path: for handles that might be the same file via DuplicateHandle
                // Skip granted_access that can't be duplicated (saves time)
                if entry.granted_access == 0 {
                    continue;
                }

                let _ = (nt_dup, nt_qobj, pseudo_current, current_process);
            }

            None
        }
    }

    unsafe fn get_object_ptr_for_handle(
        nt_query: NtQuerySystemInfoFn,
        target_handle: HANDLE,
        my_pid: usize,
    ) -> Option<usize> {
        let mut buf_size: u32 = 1 << 22;
        let mut buf: Vec<u8>;
        let mut ret_len: u32 = 0;
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004_u32 as i32;

        loop {
            buf = vec![0u8; buf_size as usize];
            let status = nt_query(
                0x40,
                buf.as_mut_ptr(),
                buf_size,
                &mut ret_len,
            );
            if status == 0 {
                break;
            } else if status == STATUS_INFO_LENGTH_MISMATCH {
                buf_size = ret_len + 4096;
            } else {
                return None;
            }
        }

        let header = &*(buf.as_ptr() as *const SystemHandleInfoEx);
        let count = header.number_of_handles;
        let entries_ptr = buf
            .as_ptr()
            .add(std::mem::size_of::<SystemHandleInfoEx>())
            as *const SystemHandleEntryEx;

        let raw_handle_value = target_handle.0 as usize;

        for i in 0..count {
            let entry = &*entries_ptr.add(i);
            if entry.unique_process_id == my_pid && entry.handle_value == raw_handle_value {
                return Some(entry.object);
            }
        }
        None
    }

    // ── Real process suspension via NtSuspendProcess ──────────────────────────
    pub fn suspend_process(pid: u32) -> Result<(), String> {
        unsafe {
            let handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
                .map_err(|e| format!("OpenProcess(SUSPEND) PID {}: {}", pid, e))?;

            let result = try_nt_suspend(handle);
            let _ = CloseHandle(handle);

            match result {
                Ok(()) => Ok(()),
                Err(_) => {
                    // Fallback: suspend every thread owned by that process
                    suspend_all_threads(pid)
                }
            }
        }
    }

    unsafe fn try_nt_suspend(handle: HANDLE) -> Result<(), String> {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|e| format!("ntdll: {}", e))?;
        let proc_addr = GetProcAddress(ntdll, s!("NtSuspendProcess"))
            .ok_or("NtSuspendProcess not found")?;
        let nt_suspend: NtSuspendProcessFn = std::mem::transmute(proc_addr);
        let status = nt_suspend(handle);
        if status >= 0 {
            Ok(())
        } else {
            Err(format!("NTSTATUS {:#010x}", status as u32))
        }
    }

    fn suspend_all_threads(pid: u32) -> Result<(), String> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("Snapshot: {}", e))?;

            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };

            let mut suspended = 0u32;
            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        if let Ok(th) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            SuspendThread(th);
                            let _ = CloseHandle(th);
                            suspended += 1;
                        }
                    }
                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);

            if suspended > 0 {
                Ok(())
            } else {
                Err(format!("No threads found for PID {}", pid))
            }
        }
    }

    // ── Real process resume via NtResumeProcess ───────────────────────────────
    pub fn resume_process(pid: u32) -> Result<(), String> {
        unsafe {
            let handle = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid)
                .map_err(|e| format!("OpenProcess(RESUME) PID {}: {}", pid, e))?;

            let result = try_nt_resume(handle);
            let _ = CloseHandle(handle);

            match result {
                Ok(()) => Ok(()),
                Err(_) => resume_all_threads(pid),
            }
        }
    }

    unsafe fn try_nt_resume(handle: HANDLE) -> Result<(), String> {
        let ntdll = GetModuleHandleA(s!("ntdll.dll"))
            .map_err(|e| format!("ntdll: {}", e))?;
        let proc_addr = GetProcAddress(ntdll, s!("NtResumeProcess"))
            .ok_or("NtResumeProcess not found")?;
        let nt_resume: NtResumeProcessFn = std::mem::transmute(proc_addr);
        let status = nt_resume(handle);
        if status >= 0 {
            Ok(())
        } else {
            Err(format!("NTSTATUS {:#010x}", status as u32))
        }
    }

    fn resume_all_threads(pid: u32) -> Result<(), String> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| format!("Snapshot: {}", e))?;
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut resumed = 0u32;
            if Thread32First(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        if let Ok(th) =
                            OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID)
                        {
                            ResumeThread(th);
                            let _ = CloseHandle(th);
                            resumed += 1;
                        }
                    }
                    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
            if resumed > 0 { Ok(()) } else { Err(format!("No threads for PID {}", pid)) }
        }
    }

    // ── Real process termination ──────────────────────────────────────────────
    pub fn kill_process(pid: u32) -> Result<(), String> {
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid)
                .map_err(|e| format!("OpenProcess(TERMINATE) PID {}: {}", pid, e))?;
            TerminateProcess(handle, 1)
                .map_err(|e| format!("TerminateProcess PID {}: {}", pid, e))?;
            let _ = CloseHandle(handle);
            Ok(())
        }
    }

    // ── Real process info: exe path + cmdline ─────────────────────────────────
    pub fn get_process_info(pid: u32) -> (String, Vec<String>) {
        let exe = get_exe_path(pid).unwrap_or_else(|| format!("<unknown PID {}>", pid));
        let cmdline = get_cmdline_via_nt(pid).unwrap_or_else(|| exe.clone());
        (
            cmdline.clone(),
            vec![
                format!("EXE={}", exe),
                format!("PID={}", pid),
                format!("CMDLINE={}", cmdline),
                "SHADOW_TRAP_STATUS=FROZEN_NtSuspendProcess".to_string(),
                "ADVERSARY_INTENT=CREDENTIAL_ACCESS".to_string(),
            ],
        )
    }

    fn get_exe_path(pid: u32) -> Option<String> {
        unsafe {
            let handle =
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = vec![0u16; 1024];
            let mut size = buf.len() as u32;
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_FORMAT(0),
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .ok()?;
            let _ = CloseHandle(handle);
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        }
    }

    // NtQueryInformationProcess with ProcessCommandLineInformation (60)
    fn get_cmdline_via_nt(pid: u32) -> Option<String> {
        unsafe {
            type NtQueryInfoProcessFn =
                unsafe extern "system" fn(HANDLE, u32, *mut u8, u32, *mut u32) -> i32;

            let ntdll = GetModuleHandleA(s!("ntdll.dll")).ok()?;
            let nt_qip: NtQueryInfoProcessFn = std::mem::transmute(
                GetProcAddress(ntdll, s!("NtQueryInformationProcess"))?,
            );

            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
            .ok()?;

            // ProcessCommandLineInformation = 60
            let mut buf = vec![0u8; 4096];
            let mut ret_len: u32 = 0;
            let status = nt_qip(
                handle,
                60,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(handle);

            if status < 0 {
                return None;
            }

            // Result is a UNICODE_STRING: Length(u16), MaxLength(u16), Buffer(*u16)
            if ret_len < 8 {
                return None;
            }
            let len = u16::from_le_bytes([buf[0], buf[1]]) as usize / 2;
            // Buffer pointer is at offset 4 (after Length + MaxLength)
            let ptr_bytes: [u8; 8] = buf[4..12].try_into().ok()?;
            let _ptr_val = usize::from_le_bytes(ptr_bytes);

            // The actual string data starts right after the pointer in the buffer
            // when NtQueryInformationProcess writes the data inline (it may not)
            // As a safe fallback, re-read using ReadProcessMemory approach is complex;
            // we'll parse the inline buffer that Windows puts right after the UNICODE_STRING header
            if buf.len() < 12 + len * 2 {
                return None;
            }
            let wide_slice: &[u16] = std::slice::from_raw_parts(
                buf[12..].as_ptr() as *const u16,
                len,
            );
            Some(String::from_utf16_lossy(wide_slice))
        }
    }
}

// ─────────────────────────────────────────────────────────
// Shared structures and traits
// ─────────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct TrapTriggered {
    pub pid:         u32,
    pub cmdline:     String,
    pub environ:     Vec<String>,
    pub target_path: PathBuf,
    pub timestamp:   DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ShadowTrapState {
    Disarmed,
    Armed {
        target_path: PathBuf,
        armed_at:    DateTime<Utc>,
    },
    Triggered {
        target_path:  PathBuf,
        pid:          u32,
        cmdline:      String,
        environ:      Vec<String>,
        triggered_at: DateTime<Utc>,
        is_frozen:    bool,
    },
}

impl Default for ShadowTrapState {
    fn default() -> Self {
        Self::Disarmed
    }
}

pub struct ShadowTrapEngine {
    pub state:          ShadowTrapState,
    pub watcher_active: Arc<AtomicBool>,
}

impl ShadowTrapEngine {
    pub fn new() -> Self {
        Self {
            state:          ShadowTrapState::Disarmed,
            watcher_active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn arm(
        &mut self,
        target_path: PathBuf,
        tx: UnboundedSender<TrapTriggered>,
    ) -> std::io::Result<()> {
        self.watcher_active.store(false, Ordering::SeqCst);

        deploy_decoy_canary(&target_path)?;

        let is_active = Arc::new(AtomicBool::new(true));
        self.watcher_active = is_active.clone();
        spawn_canary_watcher(target_path.clone(), tx, is_active);

        self.state = ShadowTrapState::Armed {
            target_path,
            armed_at: Utc::now(),
        };
        Ok(())
    }

    #[allow(dead_code)]
    pub fn disarm(&mut self) {
        self.watcher_active.store(false, Ordering::SeqCst);
        self.state = ShadowTrapState::Disarmed;
    }

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

// ─────────────────────────────────────────────────────────
// Canary file deployment
// ─────────────────────────────────────────────────────────
pub fn deploy_decoy_canary(target_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = target_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(target_path, CANARY_CONTENT)?;

    // Also always plant in the local sandbox path for cross-platform demos
    let local = PathBuf::from("./test_artifacts/demo_env/.aws_prod_keys.bak");
    if let Some(p) = local.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let _ = std::fs::write(&local, CANARY_CONTENT);

    Ok(())
}

// ─────────────────────────────────────────────────────────
// Process control — platform dispatch
// ─────────────────────────────────────────────────────────
pub fn freeze_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        win32::suspend_process(pid)
    }
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGSTOP);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGSTOP failed on PID {}", pid))
        }
    }
    #[cfg(not(any(windows, unix)))]
    Err("Platform not supported".to_string())
}

pub fn resume_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        win32::resume_process(pid)
    }
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGCONT);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGCONT failed on PID {}", pid))
        }
    }
    #[cfg(not(any(windows, unix)))]
    Err("Platform not supported".to_string())
}

pub fn terminate_process(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        win32::kill_process(pid)
    }
    #[cfg(unix)]
    unsafe {
        let res = libc::kill(pid as libc::pid_t, libc::SIGKILL);
        if res == 0 {
            Ok(())
        } else {
            Err(format!("SIGKILL failed on PID {}", pid))
        }
    }
    #[cfg(not(any(windows, unix)))]
    Err("Platform not supported".to_string())
}

pub fn read_process_telemetry(pid: u32) -> (String, Vec<String>) {
    #[cfg(windows)]
    {
        win32::get_process_info(pid)
    }
    #[cfg(target_os = "linux")]
    {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline = std::fs::read(&cmdline_path)
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_else(|_| format!("PID {}", pid));

        let environ_path = format!("/proc/{}/environ", pid);
        let environ = std::fs::read(&environ_path)
            .map(|bytes| {
                bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .take(15)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        (cmdline, environ)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        (format!("PID {}", pid), vec![])
    }
}

// ─────────────────────────────────────────────────────────
// Canary watcher — spawns a background task
// ─────────────────────────────────────────────────────────
pub fn spawn_canary_watcher(
    target_path: PathBuf,
    trigger_tx: UnboundedSender<TrapTriggered>,
    is_active: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let local_path = PathBuf::from("./test_artifacts/demo_env/.aws_prod_keys.bak");

        // Snapshot baseline mtimes
        let mut last_mtime_target = std::fs::metadata(&target_path)
            .and_then(|m| m.modified())
            .ok();
        let mut last_mtime_local = std::fs::metadata(&local_path)
            .and_then(|m| m.modified())
            .ok();

        // ── Linux: inotify kernel watcher ────────────────────────────────
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
            let mut culprit_pid: u32 = 0;

            // ── Windows: real kernel handle scan via NtQuerySystemInformation ─
            #[cfg(windows)]
            {
                // Check both canary paths
                for path in [&target_path, &local_path] {
                    if path.exists() {
                        if let Some(pid) = win32::find_pid_accessing_file(path) {
                            triggered = true;
                            culprit_pid = pid;
                            break;
                        }
                    }
                }

                // Fallback: mtime change (catches writes even if handle scan misses)
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
            }

            // ── Linux: inotify ───────────────────────────────────────────
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
                    culprit_pid = find_pid_accessing_path(&target_path)
                        .or_else(|| find_pid_accessing_path(&local_path))
                        .or_else(find_most_recent_process)
                        .unwrap_or(0);
                }
            }

            if triggered && culprit_pid > 0 {
                // ── Freeze the culprit immediately ────────────────────────
                let _ = freeze_process(culprit_pid);

                let (cmdline, environ) = read_process_telemetry(culprit_pid);

                let event = TrapTriggered {
                    pid:         culprit_pid,
                    cmdline,
                    environ,
                    target_path: target_path.clone(),
                    timestamp:   Utc::now(),
                };

                let _ = trigger_tx.send(event);
                break;
            }
        }

        // ── Linux cleanup ────────────────────────────────────────────────
        #[cfg(target_os = "linux")]
        if inotify_fd >= 0 {
            unsafe { libc::close(inotify_fd) };
        }
    });
}

// ─────────────────────────────────────────────────────────
// Linux helpers (proc scanning)
// ─────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub fn find_pid_accessing_path(target_path: &Path) -> Option<u32> {
    let target_canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.to_path_buf());
    let my_pid = std::process::id();

    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
            if pid == my_pid || pid == 0 {
                continue;
            }
            if let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) {
                for fd_entry in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        if link == target_canonical || link == *target_path {
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
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .filter(|&p| p != my_pid && p < 100_000_000)
        .max()
}
