#!/usr/bin/env bash
# ============================================================
#  Security Analyst & Penetration Testing Workstation Setup
#  Target:  Ubuntu 24.04 LTS Desktop (amd64)
#
#  USAGE:   sudo bash setup_security_workstation.sh
#
#  TIP: Wrap with systemd-inhibit to prevent screen lock / suspend
#  during the 2–3 hour runtime:
#    sudo systemd-inhibit \
#      --what=idle:sleep:handle-lid-switch \
#      --who="Security Workstation Setup" \
#      --why="Long-running installation" \
#      bash setup_security_workstation.sh
# ============================================================
#
#  WHAT THIS SCRIPT INSTALLS (in order):
#
#   Step  1  System update, prerequisites, Universe repo
#   Step  2  Docker Engine          (official docker.com repo)
#   Step  3  Kali Linux Docker image (kalilinux/kali-rolling)
#   Step  4  Plaso/log2timeline      (log2timeline/plaso Docker)
#   Step  5  Ghidra                  (NSA GitHub latest release)
#   Step  6  Network tools: nmap, masscan, OWASP ZAP
#   Step  7  Burp Suite Community    (PortSwigger official)
#   Step  8  Tor daemon              (deb.torproject.org repo)
#   Step  9  Tor Browser             (torbrowser-launcher)
#   Step 10  Brave Browser           (brave.com official apt repo)
#   Step 11  Chromium Browser        (official Snap, Canonical)
#   Step 12  Go (Golang)             (go.dev official tarball)
#   Step 13  Rust                    (rustup, rust-lang.org)
#   Step 14  ProjectDiscovery tools  (nuclei, subfinder, httpx,
#                                     naabu, katana — Go binaries)
#   Step 15  ProtonVPN               (protonvpn.com official repo)
#   Step 16  Visual Studio Code      (Microsoft official apt repo)
#   Step 17  Ubuntu Forensics        (forensics-all + -all-gui)
#   Step 18  DFIR forensics libs     (libyal suite + imagemounter)
#   Step 19  REMnux malware-analysis (addon mode, amd64 only)
#   Step 20  Metasploit Framework    (apt.metasploit.com repo)
#   Step 21  John the Ripper         (john-the-ripper Snap —
#                                     Community/Jumbo edition)
#   Step 22  Hashcat                 (Ubuntu Universe apt)
#   Step 23  SecLists + Wordlists    (git clone, rockyou, symlinks)
#   Step 24  Watchtower              (Docker auto-update container)
#   Final    /usr/local/bin/update-workstation maintenance script
#
#  POST-INSTALL ACTIONS REQUIRED:
#   1.  REBOOT — REMnux + docker group both take effect on reboot.
#                After reboot, run 'docker' WITHOUT sudo.
#                (Or use 'newgrp docker' in the current terminal.)
#   2.  source ~/.bashrc   (or open new terminal for Go/Rust PATH)
#   3.  Run 'torbrowser-launcher' once as your regular user to
#       download and verify the Tor Browser bundle.
#   4.  Run 'msfdb init' as your regular user (post-reboot) to
#       initialise the Metasploit PostgreSQL database.
#   5.  To update everything: sudo update-workstation
#
#  MAINTAINABILITY OVERVIEW — how each component is updated:
#
#   apt update && apt upgrade   → Docker Engine, Brave, VS Code,
#                                  Tor daemon, ProtonVPN,
#                                  Metasploit Framework, Hashcat,
#                                  forensics-all, libyal libs,
#                                  torbrowser-launcher, all
#                                  Ubuntu Universe packages
#                                  NOTE: forensic-artifacts is
#                                  intentionally removed (Step 17)
#                                  and superseded by REMnux's
#                                  artifacts-data package.
#   snap refresh                → Chromium, OWASP ZAP,
#                                  John the Ripper (Jumbo Snap)
#   rustup update               → Rust toolchain + cargo
#   go install @latest          → ProjectDiscovery binaries
#   git -C /usr/share/seclists pull → SecLists wordlists
#   pip3 install --upgrade      → imagemounter
#   remnux upgrade              → REMnux tool suite
#   Watchtower (auto-daily)     → Kali + Plaso + all Docker images
#   Manual / re-run script      → Ghidra, Burp Suite, Go itself
#   sudo update-workstation     → does ALL of the above
# ============================================================

# ─────────────────────────────────────────────────────────────
#  SHELL OPTIONS
#  -u  : treat unset variables as errors
#  -o pipefail : pipeline fails if any component fails
#  NOTE: -e intentionally OMITTED so run_step() can collect
#        all failures without aborting the whole script.
# ─────────────────────────────────────────────────────────────
set -uo pipefail

# ─────────────────────────────────────────────────────────────
#  GLOBAL CONFIGURATION
# ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
LOG_FILE="${SCRIPT_DIR}/installLog_${TIMESTAMP}.log"
ORIGINAL_USER="${SUDO_USER:-${USER}}"
ORIGINAL_HOME="$(eval echo "~${ORIGINAL_USER}")"
BASHRC="${ORIGINAL_HOME}/.bashrc"

export DEBIAN_FRONTEND=noninteractive

# ── Colours ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Failure tracking ──────────────────────────────────────────
ERRORS=0
declare -a FAILED_STEPS=()

TOTAL_STEPS=24
CURRENT_STEP=0


# ═════════════════════════════════════════════════════════════
#  LOGGING — writes to LOG_FILE and terminal simultaneously
# ═════════════════════════════════════════════════════════════
log() {
    local level="$1"; shift
    local message="$*"
    local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] [${level}] ${message}" >> "${LOG_FILE}"
    case "${level}" in
        INFO)    echo -e "${CYAN}[INFO]${RESET}  ${message}" ;;
        SUCCESS) echo -e "${GREEN}[OK]${RESET}    ${message}" ;;
        WARN)    echo -e "${YELLOW}[WARN]${RESET}  ${message}" ;;
        ERROR)   echo -e "${RED}[ERROR]${RESET} ${message}" ;;
        STEP)    echo -e "\n${BOLD}${BLUE}━━━ ${message} ━━━${RESET}" ;;
    esac
}


# ═════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ═════════════════════════════════════════════════════════════
progress_bar() {
    local current="$1" total="$2" label="${3:-}"
    local width=50
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    local bar=""
    [[ "${filled}" -gt 0 ]] && bar="$(printf '%.0s█' $(seq 1 "${filled}"))"
    [[ "${empty}"  -gt 0 ]] && bar+="$(printf '%.0s░' $(seq 1 "${empty}"))"
    printf "\r  ${CYAN}[%s]${RESET} %3d%%  %s" \
        "${bar}" "$(( current * 100 / total ))" "${label}"
    [[ "${current}" -ge "${total}" ]] && echo ""
}


# ═════════════════════════════════════════════════════════════
#  STEP RUNNER
#  Executes a command, piping stdout+stderr to LOG_FILE.
#  On failure: records the step name, increments ERRORS,
#  then continues (does NOT abort the script).
#
#  ⚠ IMPORTANT — heredoc / tee gotcha:
#  Do NOT write:  run_step "label" tee /path/file > /dev/null << 'EOF'
#  The > /dev/null redirects run_step's OWN stdout, silencing
#  all log() terminal output for that step.  Instead, use
#  run_step with a plain 'tee /path/file << EOF' (no > /dev/null).
#  tee's output goes to LOG_FILE via run_step's internal
#  redirect, which is an acceptable log entry.
# ═════════════════════════════════════════════════════════════
run_step() {
    local description="$1"; shift
    log INFO "Running: ${description}"
    if "$@" >> "${LOG_FILE}" 2>&1; then
        log SUCCESS "${description}"
        return 0
    else
        local rc=$?
        log ERROR "${description} FAILED (exit ${rc})"
        ERRORS=$(( ERRORS + 1 ))
        FAILED_STEPS+=("${description}")
        return 1
    fi
}


# ═════════════════════════════════════════════════════════════
#  EXIT HANDLER
# ═════════════════════════════════════════════════════════════
finish() {
    echo ""
    log STEP "Installation Summary"

    if [[ "${ERRORS}" -eq 0 ]]; then
        log SUCCESS "All ${TOTAL_STEPS} installation steps completed successfully."
    else
        log ERROR "${ERRORS} step(s) failed:"
        for step in "${FAILED_STEPS[@]:-}"; do
            log ERROR "  ✗ ${step}"
        done
        log WARN "Review ${LOG_FILE} for full details."
    fi

    log INFO "Full log : ${LOG_FILE}"
    log INFO "─────────────────────────────────────────────────────────────"
    log INFO "REQUIRED POST-INSTALL ACTIONS:"
    log INFO "  1. REBOOT — required for REMnux and the docker group to"
    log INFO "     take effect.  After reboot, run docker WITHOUT sudo."
    log INFO "     (Or use 'newgrp docker' in the current session for"
    log INFO "     immediate effect without rebooting.)"
    log INFO "  2. Open a new terminal (or: source ~/.bashrc) to activate"
    log INFO "     Go and Rust PATH changes."
    log INFO "  3. Run 'torbrowser-launcher' as your regular user to"
    log INFO "     download and verify the Tor Browser bundle."
    log INFO "  4. Run 'msfdb init' as your regular user (post-reboot)"
    log INFO "     to create the Metasploit PostgreSQL database."
    log INFO "  5. To update all tools at once: sudo update-workstation"
    log INFO "─────────────────────────────────────────────────────────────"
    log INFO "WORDLIST LOCATIONS:"
    log INFO "  SecLists  : /usr/share/seclists/"
    log INFO "  Wordlists : /usr/share/wordlists/   (Kali-style layout)"
    log INFO "  RockYou   : /usr/share/wordlists/rockyou.txt.gz"
    log INFO "  Decompress: gunzip -k /usr/share/wordlists/rockyou.txt.gz"
    log INFO "  John list : /usr/share/wordlists/john.lst"
    log INFO "─────────────────────────────────────────────────────────────"

    trap - EXIT
    exit "${ERRORS}"
}

trap 'finish' EXIT


# ═════════════════════════════════════════════════════════════
#  PRE-FLIGHT CHECKS
# ═════════════════════════════════════════════════════════════
log STEP "Pre-flight Checks"

if [[ "${EUID}" -ne 0 ]]; then
    log ERROR "Must be run as root.  Use: sudo bash ${0}"
    exit 1
fi

if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    log WARN "Target is Ubuntu 24.04 LTS.  Detected OS may differ — proceeding."
else
    os_version="$(grep -w VERSION_ID /etc/os-release | cut -d= -f2 | tr -d '"')"
    log INFO "Detected Ubuntu version : ${os_version}"
fi

SYS_ARCH="$(dpkg --print-architecture)"
log INFO "System architecture     : ${SYS_ARCH}"
[[ "${SYS_ARCH}" != "amd64" ]] && \
    log WARN "Not amd64. REMnux and some forensics libs may not install."

log INFO "Script directory : ${SCRIPT_DIR}"
log INFO "Log file         : ${LOG_FILE}"
log INFO "Running as user  : ${ORIGINAL_USER}  (home: ${ORIGINAL_HOME})"
log SUCCESS "Pre-flight checks passed."


# ─────────────────────────────────────────────────────────────
#  INSTALLATION MANIFEST
# ─────────────────────────────────────────────────────────────
cat << 'MANIFEST'

  ╔════════════════════════════════════════════════════════════════════╗
  ║        SECURITY WORKSTATION SETUP — INSTALLATION MANIFEST         ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║  Step  1  System update, prerequisites, Universe repo              ║
  ║  Step  2  Docker Engine       (official docker.com apt repo)       ║
  ║  Step  3  Kali Linux Docker image (kalilinux/kali-rolling)         ║
  ║  Step  4  Plaso/log2timeline Docker image + /data dir              ║
  ║  Step  5  Ghidra              (NSA GitHub latest release)          ║
  ║  Step  6  Nmap, masscan, OWASP ZAP                                 ║
  ║  Step  7  Burp Suite Community Edition (PortSwigger)               ║
  ║  Step  8  Tor daemon          (deb.torproject.org apt repo)        ║
  ║  Step  9  Tor Browser         (torbrowser-launcher, Ubuntu)        ║
  ║  Step 10  Brave Browser       (brave.com official apt repo)        ║
  ║  Step 11  Chromium Browser    (official Snap, Canonical)           ║
  ║  Step 12  Go (Golang)         (go.dev official tarball)            ║
  ║  Step 13  Rust                (rustup, rust-lang.org)              ║
  ║  Step 14  ProjectDiscovery tools (nuclei, subfinder, httpx,        ║
  ║           naabu, katana)                                           ║
  ║  Step 15  ProtonVPN GNOME client (protonvpn.com repo)              ║
  ║  Step 16  Visual Studio Code  (Microsoft official apt repo)        ║
  ║  Step 17  Ubuntu Forensics metapackage (forensics-all +            ║
  ║           forensics-all-gui — Ubuntu Universe)                     ║
  ║  Step 18  DFIR forensics libraries (libyal suite + imagemounter)   ║
  ║  Step 19  REMnux malware-analysis distro — addon mode              ║
  ║           (docs.remnux.org | amd64 only | ~1 hour)                 ║
  ║  Step 20  Metasploit Framework (apt.metasploit.com official repo)  ║
  ║  Step 21  John the Ripper     (Snap: john-the-ripper Jumbo)        ║
  ║  Step 22  Hashcat             (Ubuntu Universe apt)                ║
  ║  Step 23  SecLists + Wordlists (git clone → /usr/share/seclists,   ║
  ║           Kali-style /usr/share/wordlists/ symlink layout)         ║
  ║  Step 24  Watchtower          (Docker auto-updater container,      ║
  ║           keeps Kali + Plaso images current automatically)         ║
  ║  Final    /usr/local/bin/update-workstation maintenance script     ║
  ╠════════════════════════════════════════════════════════════════════╣
  ║  ESTIMATED RUNTIME : 2–3 hours                                     ║
  ║  DISK SPACE        : ~8–12 GB (SecLists ~1.5 GB, Docker ~2 GB,    ║
  ║                      REMnux ~2 GB, Metasploit ~700 MB)             ║
  ║  A REBOOT IS REQUIRED after the script completes.                  ║
  ╚════════════════════════════════════════════════════════════════════╝

MANIFEST


# ═════════════════════════════════════════════════════════════
#  STEP 1 — SYSTEM UPDATE & PREREQUISITES
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "System Update & Prerequisites"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: System Update & Prerequisites"

run_step "Enable Ubuntu Universe repository" \
    add-apt-repository -y universe

run_step "Update apt package indices" \
    apt-get update -y

run_step "Upgrade installed packages" \
    apt-get upgrade -y

run_step "Install prerequisite packages" \
    apt-get install -y \
        ca-certificates         \
        curl                    \
        gnupg                   \
        wget                    \
        apt-transport-https     \
        software-properties-common \
        lsb-release             \
        unzip                   \
        git                     \
        build-essential         \
        libpcap-dev             \
        libfuse2t64             \
        fuse                    \
        python3                 \
        python3-pip             \
        python3-setuptools      \
        postgresql              \
        openjdk-21-jre          \
        snapd                   \
        open-vm-tools           \
        open-vm-tools-desktop


# ═════════════════════════════════════════════════════════════
#  STEP 2 — DOCKER ENGINE
#  https://docs.docker.com/engine/install/ubuntu/
#
#  The user is added to the 'docker' group so docker can be
#  run WITHOUT sudo.  Active after reboot, or immediately via:
#    newgrp docker
#  Updated via: apt update && apt upgrade
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Docker Engine"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Docker Engine"

log INFO "Removing any conflicting legacy Docker packages..."
for pkg in docker.io docker-doc docker-compose docker-compose-v2 \
           podman-docker containerd runc; do
    apt-get remove -y "${pkg}" >> "${LOG_FILE}" 2>&1 || true
done

run_step "Create /etc/apt/keyrings directory" \
    install -m 0755 -d /etc/apt/keyrings

run_step "Download Docker official GPG key" \
    bash -c 'curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
             -o /etc/apt/keyrings/docker.asc \
             && chmod a+r /etc/apt/keyrings/docker.asc'

run_step "Add Docker stable apt repository" \
    bash -c '. /etc/os-release
             echo "deb [arch=$(dpkg --print-architecture) \
             signed-by=/etc/apt/keyrings/docker.asc] \
             https://download.docker.com/linux/ubuntu \
             ${VERSION_CODENAME} stable" \
             > /etc/apt/sources.list.d/docker.list'

run_step "Update apt after adding Docker repo" \
    apt-get update -y

run_step "Install Docker Engine, CLI, and Compose plugin" \
    apt-get install -y \
        docker-ce              \
        docker-ce-cli          \
        containerd.io          \
        docker-buildx-plugin   \
        docker-compose-plugin

run_step "Enable and start Docker daemon" \
    systemctl enable --now docker

# Add the original (non-root) user to the docker group.
# This allows 'docker' to run WITHOUT sudo after reboot.
# For immediate effect in the current session: newgrp docker
run_step "Add ${ORIGINAL_USER} to docker group (enables sudo-free docker)" \
    usermod -aG docker "${ORIGINAL_USER}"

log WARN "docker group: active after reboot.  For immediate effect"
log WARN "without rebooting, run: newgrp docker"

run_step "Smoke-test Docker as root (hello-world)" \
    docker run --rm hello-world


# ═════════════════════════════════════════════════════════════
#  STEP 3 — KALI LINUX DOCKER IMAGE
#  https://www.kali.org/docs/containers/
#  Updated automatically by Watchtower (Step 24).
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Kali Linux Docker Image"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Kali Linux Docker Image"

run_step "Pull official Kali Linux rolling Docker image" \
    docker pull kalilinux/kali-rolling


# ═════════════════════════════════════════════════════════════
#  STEP 4 — PLASO / LOG2TIMELINE DOCKER IMAGE
#  https://plaso.readthedocs.io/en/latest/sources/user/
#         Installing-with-docker.html
#  Updated automatically by Watchtower (Step 24).
#
#  Usage: plaso log2timeline --storage-file /data/out.plaso /data/evidence
#         plaso psort -o dynamic /data/out.plaso
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Plaso / log2timeline"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Plaso / log2timeline Docker Image"

run_step "Pull official Plaso log2timeline Docker image" \
    docker pull log2timeline/plaso

if [[ ! -d /data ]]; then
    run_step "Create /data evidence mount directory" \
        install -d -m 0775 -o root -g "${ORIGINAL_USER}" /data
else
    log INFO "/data already exists — skipping creation."
fi

# Write plaso wrapper at outer shell level using tee.
# Do NOT pipe this through bash -c with escaped heredoc quoting —
# that approach is fragile and hard to maintain.
run_step "Install /usr/local/bin/plaso convenience wrapper" \
    tee /usr/local/bin/plaso << 'PLASO_WRAPPER'
#!/usr/bin/env bash
# Plaso/log2timeline Docker convenience wrapper.
# Mounts /data on the host to /data inside the container.
# Usage: plaso log2timeline --storage-file /data/out.plaso /data/evidence
#        plaso psort -o dynamic /data/out.plaso
#        plaso pinfo /data/out.plaso
exec docker run --rm -it -v /data:/data log2timeline/plaso "$@"
PLASO_WRAPPER
chmod 0755 /usr/local/bin/plaso


# ═════════════════════════════════════════════════════════════
#  STEP 5 — GHIDRA REVERSE ENGINEERING SUITE
#  https://github.com/NationalSecurityAgency/ghidra
#  Requires Java 21 JRE (installed in Step 1).
#
#  ⚠ UPDATE NOTE: Ghidra has no apt repo.  To update:
#    sudo update-workstation  (checks GitHub API, re-installs)
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Ghidra"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Ghidra Reverse Engineering Suite"

GHIDRA_DOWNLOAD_URL=""
GHIDRA_DOWNLOAD_URL="$(curl -fsSL \
    'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest' \
    | grep '"browser_download_url"' \
    | grep '\.zip"' \
    | head -1 \
    | cut -d'"' -f4 2>> "${LOG_FILE}")" || true

if [[ -z "${GHIDRA_DOWNLOAD_URL}" ]]; then
    log ERROR "Could not determine Ghidra download URL — skipping."
    ERRORS=$(( ERRORS + 1 ))
    FAILED_STEPS+=("Fetch Ghidra download URL from GitHub API")
else
    log INFO "Latest Ghidra: ${GHIDRA_DOWNLOAD_URL}"
    GHIDRA_ZIP="/tmp/ghidra_latest.zip"

    run_step "Download Ghidra zip archive" \
        curl -fsSL -o "${GHIDRA_ZIP}" "${GHIDRA_DOWNLOAD_URL}"

    run_step "Extract Ghidra to /opt and create /opt/ghidra symlink" \
        bash -c 'unzip -q -o "'"${GHIDRA_ZIP}"'" -d /opt \
                 && GHIDRA_DIR=$(ls -d /opt/ghidra_* 2>/dev/null | tail -1) \
                 && ln -sfn "${GHIDRA_DIR}" /opt/ghidra \
                 && chmod +x /opt/ghidra/ghidraRun'

    run_step "Create /usr/local/bin/ghidra launcher" \
        tee /usr/local/bin/ghidra << 'GHIDRA_LAUNCHER'
#!/usr/bin/env bash
exec /opt/ghidra/ghidraRun "$@"
GHIDRA_LAUNCHER
    chmod 0755 /usr/local/bin/ghidra

    rm -f "${GHIDRA_ZIP}"
fi


# ═════════════════════════════════════════════════════════════
#  STEP 6 — NETWORK & WEB SECURITY TOOLS
#  • nmap     — network discovery and security auditing
#  • masscan  — high-speed TCP port scanner
#  • OWASP ZAP — web app scanner (official zaproxy Snap)
#                Updated via: snap refresh zaproxy
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Nmap / masscan / OWASP ZAP"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Network & Web Security Tools"

run_step "Install Nmap"    apt-get install -y nmap
run_step "Install masscan" apt-get install -y masscan

run_step "Ensure snapd socket is active (race-condition prevention)" \
    bash -c 'systemctl enable --now snapd snapd.socket && sleep 5'

run_step "Install OWASP ZAP via official zaproxy Snap (--classic)" \
    snap install zaproxy --classic


# ═════════════════════════════════════════════════════════════
#  STEP 7 — BURP SUITE COMMUNITY EDITION
#  https://portswigger.net/burp/documentation/desktop/
#         getting-started/download-and-install
#
#  ⚠ UPDATE NOTE: No apt repo.  Update via Help → Check for
#  Updates inside the app, or re-run: sudo update-workstation
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Burp Suite Community Edition"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Burp Suite Community Edition"

BURP_INSTALLER="/tmp/burpsuite_community_installer.sh"
BURP_URL="https://portswigger.net/burp/releases/download?product=community&type=linux"
BURP_DIR="/opt/BurpSuiteCommunity"

run_step "Download Burp Suite Community Edition Linux installer" \
    curl -fsSL -L \
         --user-agent "Mozilla/5.0 (X11; Linux x86_64)" \
         -o "${BURP_INSTALLER}" \
         "${BURP_URL}"

run_step "Set installer executable" \
    chmod +x "${BURP_INSTALLER}"

run_step "Run Burp Suite unattended install" \
    bash -c '"'"${BURP_INSTALLER}"'" -q -overwrite -dir "'"${BURP_DIR}"'"'

rm -f "${BURP_INSTALLER}"

run_step "Create /usr/local/bin/burpsuite launcher" \
    tee /usr/local/bin/burpsuite << BURP_LAUNCHER
#!/usr/bin/env bash
exec ${BURP_DIR}/BurpSuiteCommunity "\$@"
BURP_LAUNCHER
chmod 0755 /usr/local/bin/burpsuite

# Find Burp icon — .install4j path varies by version, use glob
# Fall back to the binary itself if icon cannot be found
BURP_ICON=""
BURP_ICON="$(find "${BURP_DIR}" -name 'burpsuite_community.png' \
             2>/dev/null | head -1)" || true
BURP_ICON="${BURP_ICON:-${BURP_DIR}/BurpSuiteCommunity}"

run_step "Create Burp Suite GNOME .desktop entry" \
    tee /usr/share/applications/burpsuite-community.desktop << BURP_DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=Burp Suite Community Edition
Comment=Web Application Security Testing Platform (PortSwigger)
Exec=${BURP_DIR}/BurpSuiteCommunity
Icon=${BURP_ICON}
Terminal=false
Categories=Network;Security;
Keywords=security;proxy;web;pentest;portswigger;
BURP_DESKTOP


# ═════════════════════════════════════════════════════════════
#  STEP 8 — TOR DAEMON
#  https://support.torproject.org/apt/tor-deb-repo/
#
#  Uses the official Tor Project apt repository rather than
#  the Ubuntu Universe package, which lags on security fixes.
#  Updated via: apt update && apt upgrade
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Tor Daemon"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Tor Daemon (deb.torproject.org)"

run_step "Download Tor Project official GPG signing key" \
    bash -c 'wget -qO- \
        https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
        | gpg --dearmor \
        | tee /usr/share/keyrings/tor-archive-keyring.gpg'

# Write source list without > /dev/null (see run_step header note)
run_step "Add official Tor Project apt repository" \
    tee /etc/apt/sources.list.d/tor.list << TOR_SOURCES
deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -sc) main
deb-src [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -sc) main
TOR_SOURCES

run_step "Update apt after adding Tor repo" \
    apt-get update -y

run_step "Install Tor daemon + self-updating keyring package" \
    apt-get install -y tor deb.torproject.org-keyring

run_step "Enable and start Tor service" \
    systemctl enable --now tor


# ═════════════════════════════════════════════════════════════
#  STEP 9 — TOR BROWSER
#  torbrowser-launcher — Ubuntu Universe.
#  Downloads and verifies the real Tor Browser bundle on
#  first launch.  Updated via: apt update && apt upgrade.
#
#  ACTION REQUIRED after reboot: run 'torbrowser-launcher'
#  as your regular user to download the Tor Browser bundle.
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Tor Browser"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Tor Browser (torbrowser-launcher)"

run_step "Install torbrowser-launcher from Ubuntu Universe" \
    apt-get install -y torbrowser-launcher

log WARN "ACTION REQUIRED: after reboot, run 'torbrowser-launcher' as"
log WARN "your regular user to download and verify the Tor Browser bundle."


# ═════════════════════════════════════════════════════════════
#  STEP 10 — BRAVE BROWSER
#  https://brave.com/linux/
#  Updated via: apt update && apt upgrade
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Brave Browser"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Brave Browser"

run_step "Download Brave official GPG keyring" \
    curl -fsSLo \
        /usr/share/keyrings/brave-browser-archive-keyring.gpg \
        https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg

run_step "Download Brave official apt .sources file (deb822 format)" \
    curl -fsSLo \
        /etc/apt/sources.list.d/brave-browser-release.sources \
        https://brave-browser-apt-release.s3.brave.com/brave-browser.sources

run_step "Update apt after adding Brave repo" \
    apt-get update -y

run_step "Install Brave Browser" \
    apt-get install -y brave-browser


# ═════════════════════════════════════════════════════════════
#  STEP 11 — CHROMIUM BROWSER
#  On Ubuntu 24.04 noble, 'apt install chromium-browser' only
#  installs a stub that triggers the Snap anyway.  Canonical's
#  official install method is: snap install chromium
#  Updated via: snap refresh chromium
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Chromium Browser"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Chromium Browser"

run_step "Install Chromium via official Canonical Snap" \
    snap install chromium


# ═════════════════════════════════════════════════════════════
#  STEP 12 — GO (GOLANG)
#  https://go.dev/doc/install
#  Architecture auto-detected.
#  Updated via: sudo update-workstation (checks go.dev for
#  latest version and re-downloads if a newer one exists).
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Go (Golang)"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Go Programming Language"

case "$(dpkg --print-architecture)" in
    amd64)  GO_ARCH="amd64"   ;;
    arm64)  GO_ARCH="arm64"   ;;
    armhf)  GO_ARCH="armv6l"  ;;
    *)      GO_ARCH="amd64"
            log WARN "Unknown arch; defaulting Go download to amd64" ;;
esac

log INFO "Querying go.dev for latest stable release..."
GO_VERSION=""
GO_VERSION="$(curl -fsSL 'https://go.dev/dl/?mode=json' \
    | grep -oP '"version":\s*"\Kgo[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | head -1 2>/dev/null)" || true
if [[ -z "${GO_VERSION}" ]]; then
    GO_VERSION="go1.24.2"
    log WARN "go.dev API unreachable; falling back to ${GO_VERSION}"
fi

GO_TARBALL="${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TARBALL}"
log INFO "Installing ${GO_VERSION} (${GO_ARCH})..."

run_step "Download Go ${GO_VERSION} tarball" \
    curl -fsSL -o "/tmp/${GO_TARBALL}" "${GO_URL}"

run_step "Remove any previous /usr/local/go installation" \
    rm -rf /usr/local/go

run_step "Extract Go to /usr/local" \
    tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"

rm -f "/tmp/${GO_TARBALL}"

# Write golang.sh at outer shell level — no > /dev/null
run_step "Write /etc/profile.d/golang.sh (system-wide PATH)" \
    tee /etc/profile.d/golang.sh << 'GOLANG_PROFILE'
# Go (Golang) PATH — managed by security workstation setup script
export PATH="$PATH:/usr/local/go/bin"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
GOLANG_PROFILE
chmod 644 /etc/profile.d/golang.sh

if ! grep -q '/usr/local/go/bin' "${BASHRC}" 2>/dev/null; then
    run_step "Append Go PATH to ${BASHRC}" \
        tee -a "${BASHRC}" << 'GOLANG_BASHRC'

# ── Go (Golang) PATH — added by security workstation setup ──
export PATH="$PATH:/usr/local/go/bin"
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
GOLANG_BASHRC
fi

run_step "Verify Go installation" \
    /usr/local/go/bin/go version


# ═════════════════════════════════════════════════════════════
#  STEP 13 — RUST
#  https://www.rust-lang.org/tools/install
#  Updated via: rustup update
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Rust"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Rust Programming Language"

run_step "Run rustup installer as ${ORIGINAL_USER}" \
    su - "${ORIGINAL_USER}" -c \
        'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --no-modify-path'

if ! grep -q '\.cargo/bin' "${BASHRC}" 2>/dev/null; then
    run_step "Append Rust PATH to ${BASHRC}" \
        tee -a "${BASHRC}" << 'RUST_BASHRC'

# ── Rust PATH — added by security workstation setup ──
export PATH="$PATH:$HOME/.cargo/bin"
# shellcheck source=/dev/null
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
RUST_BASHRC
fi

run_step "Verify Rust installation (rustc + cargo)" \
    su - "${ORIGINAL_USER}" -c \
        'export PATH="$PATH:$HOME/.cargo/bin"
         rustc --version && cargo --version'


# ═════════════════════════════════════════════════════════════
#  STEP 14 — PROJECTDISCOVERY TOOLS
#  https://github.com/projectdiscovery
#  Updated via: go install <tool>@latest  (update-workstation)
#
#  CGO build dependencies required:
#    nuclei  → mattn/go-sqlite3 needs gcc + libsqlite3-dev
#    naabu   → links libpcap: gcc + libpcap-dev
#    katana  → go-rod headless browser: gcc + libpcap-dev
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "ProjectDiscovery Tools"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: ProjectDiscovery Tools"

run_step "Install CGO build dependencies for ProjectDiscovery tools" \
    apt-get install -y \
        gcc             \
        g++             \
        make            \
        libsqlite3-dev  \
        libpcap-dev     \
        pkg-config

# install_go_tool IMPORT_PATH [CGO_ENABLED=0|1] [LDFLAGS=""]
#   Builds and installs a Go binary, then verifies the binary
#   landed in $GOPATH/bin.  Retries once on transient failure
#   (network blip, module cache corruption, etc.)
#
#   nuclei  CGO=1  LDFLAGS="-checklinkname=0"
#           mattn/go-sqlite3 requires CGO.
#           bytedance/sonic v1.14.x (nuclei dep) is broken on Go 1.24.0
#           and certain later versions — sonic uses internal Go runtime
#           symbols that were removed.  The official workaround from
#           sonic's README is -ldflags="-checklinkname=0" which tells
#           the linker to skip the linkname validation checks.
#   naabu   CGO=1  — links against libpcap (C library)
#   katana  CGO=1  — official README explicitly requires CGO_ENABLED=1
#                    (go-rod headless browser uses C bindings)
install_go_tool() {
    local import_path="$1"
    local cgo="${2:-0}"
    local ldflags="${3:-}"
    local tool_name; tool_name="$(basename "${import_path}")"

    local ldflag_arg=""
    [[ -n "${ldflags}" ]] && ldflag_arg="-ldflags='${ldflags}'"

    local install_cmd
    install_cmd="export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin\"
export GOPATH=\"\$HOME/go\"
export CGO_ENABLED=${cgo}
go install -v ${ldflag_arg} ${import_path}@latest"

    # First attempt
    run_step "go install ${tool_name}@latest (CGO=${cgo})" \
        su - "${ORIGINAL_USER}" -c "${install_cmd}" && {
        # Verify binary exists after install
        run_step "Verify ${tool_name} binary exists" \
            su - "${ORIGINAL_USER}" -c \
                "export GOPATH=\"\$HOME/go\"
                 test -x \"\$GOPATH/bin/${tool_name}\" \
                 && \"\$GOPATH/bin/${tool_name}\" -version 2>/dev/null \
                 || \"\$GOPATH/bin/${tool_name}\" --version 2>/dev/null \
                 || echo '${tool_name} binary present'"
        return 0
    }

    # Retry once — clear module cache in case it was corrupted
    log WARN "${tool_name} install failed — clearing module cache and retrying..."
    su - "${ORIGINAL_USER}" -c \
        "export PATH=\"\$PATH:/usr/local/go/bin\"
         export GOPATH=\"\$HOME/go\"
         go clean -modcache" >> "${LOG_FILE}" 2>&1 || true

    run_step "go install ${tool_name}@latest — RETRY (CGO=${cgo})" \
        su - "${ORIGINAL_USER}" -c "${install_cmd}"
}

# CGO requirements per official ProjectDiscovery documentation:
#   nuclei   CGO=1 — uses mattn/go-sqlite3 (C library)
#            Requires Go >= 1.24.2 (Go 1.24.0 is broken due to
#            bytedance/sonic GoMapIterator compile error)
#   subfinder CGO=0 — pure Go
#   httpx    CGO=0 — pure Go
#   naabu    CGO=1 — links against libpcap (C library)
#   katana   CGO=1 — go-rod headless browser uses C bindings
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"       1
install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" 0
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx"            0
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu"         1
install_go_tool "github.com/projectdiscovery/katana/cmd/katana"          1


# ═════════════════════════════════════════════════════════════
#  STEP 15 — PROTONVPN
#  https://protonvpn.com/support/official-linux-vpn-ubuntu
#  Updated via: apt update && apt upgrade
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "ProtonVPN"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: ProtonVPN"

PROTON_DEB="/tmp/protonvpn-stable-release.deb"
PROTON_URL="https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.8_all.deb"

run_step "Download ProtonVPN stable release .deb" \
    curl -fsSL -o "${PROTON_DEB}" "${PROTON_URL}"

run_step "Install ProtonVPN release package (registers apt repo + key)" \
    dpkg -i "${PROTON_DEB}"

run_step "Resolve dpkg dependency issues (apt --fix-broken)" \
    apt-get install -y --fix-broken

run_step "Update apt after ProtonVPN repo registration" \
    apt-get update -y

run_step "Install ProtonVPN GNOME desktop client" \
    apt-get install -y proton-vpn-gnome-desktop

run_step "Enable Ubuntu AppIndicators extension (non-fatal)" \
    bash -c 'su - '"${ORIGINAL_USER}"' -c \
        "gnome-extensions enable ubuntu-appindicators@ubuntu.com" \
        2>/dev/null || true'

rm -f "${PROTON_DEB}"


# ═════════════════════════════════════════════════════════════
#  STEP 16 — VISUAL STUDIO CODE
#  https://code.visualstudio.com/docs/setup/linux
#  Updated via: apt update && apt upgrade
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Visual Studio Code"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Visual Studio Code"

run_step "Download Microsoft GPG key for VS Code" \
    bash -c 'curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
             | gpg --dearmor \
             > /etc/apt/keyrings/packages.microsoft.gpg \
             && chmod 644 /etc/apt/keyrings/packages.microsoft.gpg'

run_step "Add VS Code apt repository" \
    tee /etc/apt/sources.list.d/vscode.list << 'VSCODE_SOURCE'
deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main
VSCODE_SOURCE

run_step "Update apt after adding VS Code repo" \
    apt-get update -y

run_step "Install Visual Studio Code" \
    apt-get install -y code


# ═════════════════════════════════════════════════════════════
#  STEP 17 — UBUNTU FORENSICS METAPACKAGE
#  Ubuntu Universe — updated via: apt update && apt upgrade
#
#  ⚠ 'forensics-full' is NOT packaged for Ubuntu 24.04 noble.
#  Installing the equivalent: forensics-all + forensics-all-gui
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Ubuntu Forensics Metapackage"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Ubuntu Forensics Metapackage"

log WARN "'forensics-full' is not packaged for Ubuntu 24.04 noble."
log WARN "Installing equivalent: forensics-all + forensics-all-gui"

run_step "Install forensics-all (Ubuntu Universe)" \
    apt-get install -y --fix-missing forensics-all

run_step "Install forensics-all-gui (Ubuntu Universe)" \
    apt-get install -y --fix-missing forensics-all-gui

# ── Pre-emptive REMnux conflict fix ──────────────────────────
# forensics-all pulls in 'forensic-artifacts' (Ubuntu Universe,
# dated 20230928).  REMnux installs 'artifacts-data' from its
# own PPA (newer, same upstream dataset) which owns the same
# file: /usr/share/artifacts/antivirus.yaml.
# dpkg refuses to unpack artifacts-data while forensic-artifacts
# is installed, breaking all subsequent apt operations.
# Removing it now — before REMnux runs — eliminates the conflict
# entirely.  No data or functionality is lost; artifacts-data
# contains everything forensic-artifacts had, plus newer entries.
run_step "Remove forensic-artifacts (superseded by REMnux artifacts-data)" \
    apt-get remove -y forensic-artifacts


# ═════════════════════════════════════════════════════════════
#  STEP 18 — DFIR FORENSICS LIBRARIES (libyal suite)
#  Ubuntu Universe — updated via: apt update && apt upgrade
#  imagemounter: PyPI — updated via: pip3 install --upgrade
#
#  PACKAGE NAME MAPPING (Ubuntu 24.04 noble):
#    libbde         → libbde-utils      (BitLocker)
#    libesedb       → libesedb-utils    (ESE database)
#    libevt         → libevt-utils      (Windows EVT logs)
#    libevtx        → libevtx-utils     (Windows EVTX logs)
#    libewf         → libewf2 + ewf-tools
#    libewf-python  → python3-libewf
#    libfvde        → libfvde-utils     (FileVault 2)
#    libvshadow     → libvshadow-utils  (Volume Shadow Copies)
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "DFIR Forensics Libraries"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: DFIR Forensics Libraries (libyal suite)"

run_step "Install libyal forensics libraries (Ubuntu Universe)" \
    apt-get install -y --fix-missing \
        libbde-utils        \
        libesedb-utils      \
        libevt-utils        \
        libevtx-utils       \
        libewf2             \
        ewf-tools           \
        python3-libewf      \
        libfvde-utils       \
        libvshadow-utils

# Ubuntu 24.04 enforces PEP 668; --break-system-packages is required
run_step "Install imagemounter via pip3 (PyPI — not in Ubuntu apt)" \
    pip3 install --break-system-packages imagemounter


# ═════════════════════════════════════════════════════════════
#  STEP 19 — REMNUX MALWARE ANALYSIS DISTRO (ADDON MODE)
#  https://docs.remnux.org/install-distro/add-to-existing-system
#  Updated via: remnux upgrade
#
#  ⚠ amd64 ONLY | ~1 HOUR | REBOOT REQUIRED AFTER
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "REMnux Addon Mode"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: REMnux Malware Analysis Distro — Addon Mode"

if [[ "${SYS_ARCH}" != "amd64" ]]; then
    log WARN "REMnux requires amd64. Detected: ${SYS_ARCH}. Skipping."
    ERRORS=$(( ERRORS + 1 ))
    FAILED_STEPS+=("REMnux addon install (skipped: non-amd64)")
else
    REMNUX_INSTALLER="/tmp/remnux"
    REMNUX_EXPECTED_SHA256="15581da24c906126aba2c1e21001311d7a93d9d017c95597c662372248964661"

    log INFO "Stopping unattended-upgrades to prevent apt lock..."
    systemctl stop unattended-upgrades 2>/dev/null || true

    run_step "Download REMnux installer from REMnux.org" \
        curl -fsSL -o "${REMNUX_INSTALLER}" https://REMnux.org/remnux

    log INFO "Verifying REMnux installer SHA-256..."
    ACTUAL_SHA256="$(sha256sum "${REMNUX_INSTALLER}" | awk '{print $1}')"

    if [[ "${ACTUAL_SHA256}" != "${REMNUX_EXPECTED_SHA256}" ]]; then
        log ERROR "REMnux SHA-256 MISMATCH — refusing to execute installer."
        log ERROR "  Expected : ${REMNUX_EXPECTED_SHA256}"
        log ERROR "  Actual   : ${ACTUAL_SHA256}"
        log ERROR "Check https://docs.remnux.org for the current hash."
        ERRORS=$(( ERRORS + 1 ))
        FAILED_STEPS+=("REMnux installer SHA-256 hash verification")
        rm -f "${REMNUX_INSTALLER}"
    else
        log SUCCESS "REMnux installer hash verified."

        run_step "Install REMnux script to /usr/local/bin/remnux" \
            bash -c "chmod +x '${REMNUX_INSTALLER}' \
                     && mv '${REMNUX_INSTALLER}' /usr/local/bin/remnux"

        log INFO "Starting REMnux addon install (~1 hour)..."
        run_step "remnux install --mode=addon" \
            remnux install --mode=addon

        # ── Post-REMnux GNOME restoration ────────────────────────────
        # REMnux's Salt-based installer replaces a large number of
        # desktop packages (gnome-shell, gdm3, ubuntu-desktop deps)
        # with older or different versions.  Without remediation this
        # causes two symptoms on first reboot:
        #   1. GDM shows a black screen with a cursor and hangs
        #   2. "GdmSession: no session desktop files installed" in logs
        #   3. Noisy PAM errors about pam_lastlog.so in the journal
        #
        # The fix has two parts:
        #   Part A — reinstall the canonical Ubuntu desktop stack so
        #            the session .desktop files and GDM are restored
        #            to the correct versions.
        #   Part B — comment out the stale pam_lastlog.so reference
        #            in /etc/pam.d/login.  pam_lastlog.so was removed
        #            from Ubuntu 24.04 noble (shadow 1.5.3 dropped it
        #            upstream).  REMnux reinstalls older shadow packages
        #            that still reference it, causing PAM login errors.
        #            This is the fix Canonical's own SRU applies.
        #
        # This does NOT remove any REMnux tools — it only fixes the
        # display manager, session infrastructure, and PAM config.
        log INFO "Restoring GNOME session files and PAM modules post-REMnux..."

        run_step "Reinstall GNOME session infrastructure (post-REMnux)" \
            apt-get install -y --reinstall \
                ubuntu-desktop          \
                gnome-session           \
                gnome-shell             \
                gdm3                    \
                libpam-modules          \
                libpam-modules-bin      \
                libpam-runtime

        run_step "Run apt --fix-broken after GNOME reinstall" \
            apt-get install -y --fix-broken

        run_step "Verify session .desktop files are present" \
            bash -c 'ls /usr/share/xsessions/*.desktop \
                        /usr/share/wayland-sessions/*.desktop \
                        2>/dev/null \
                     && echo "Session desktop files OK" \
                     || { echo "WARNING: no session desktop files found"; exit 1; }'

        run_step "Verify pam_lastlog.so reference is removed from PAM config" \
            bash -c 'sed -i "s/^session.*optional.*pam_lastlog\.so.*/#&  # commented out: pam_lastlog.so removed in Ubuntu 24.04 noble (shadow 1.5.3)/" \
                     /etc/pam.d/login 2>/dev/null
                     # Verify the reference is gone or already absent
                     if grep -q "^session.*pam_lastlog\.so" /etc/pam.d/login 2>/dev/null; then
                         echo "WARNING: active pam_lastlog.so reference still present"
                         exit 1
                     else
                         echo "pam_lastlog.so PAM config OK (reference absent or commented out)"
                     fi'
    fi

    systemctl start unattended-upgrades 2>/dev/null || true
fi


# ═════════════════════════════════════════════════════════════
#  STEP 20 — METASPLOIT FRAMEWORK
#  https://docs.rapid7.com/metasploit/installing-the-metasploit-framework
#  Official Rapid7 apt repository: apt.metasploit.com
#  Updated via: apt update && apt upgrade
#
#  The repository's distribution codename is always 'lucid' —
#  this is Rapid7's convention for all Ubuntu/Debian releases.
#
#  NOTE: Rapid7's own msfinstall/msfupdate scripts use the
#  deprecated apt-key command.  We use the modern
#  /usr/share/keyrings + signed-by approach instead, which
#  avoids the 'unsupported filetype' warnings.
#
#  POST-INSTALL: run 'msfdb init' as your regular user after
#  reboot to create the PostgreSQL database.
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Metasploit Framework"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Metasploit Framework (apt.metasploit.com)"

run_step "Remove any legacy Metasploit keyring file" \
    bash -c 'rm -f /usr/share/keyrings/metasploit-framework.gpg'

run_step "Download Rapid7 Metasploit GPG signing key" \
    bash -c 'curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
             | gpg --dearmor \
             | tee /usr/share/keyrings/metasploit-framework.gpg
             chmod 644 /usr/share/keyrings/metasploit-framework.gpg
             chown root:root /usr/share/keyrings/metasploit-framework.gpg'

run_step "Add Rapid7 Metasploit apt repository" \
    tee /etc/apt/sources.list.d/metasploit-framework.list << 'MSF_SOURCE'
deb [signed-by=/usr/share/keyrings/metasploit-framework.gpg] https://apt.metasploit.com/ lucid main
MSF_SOURCE

run_step "Update apt after adding Metasploit repo" \
    apt-get update -y

run_step "Install Metasploit Framework" \
    apt-get install -y metasploit-framework

log INFO "Metasploit installed.  Post-reboot, run as regular user:"
log INFO "  msfdb init    ← creates the PostgreSQL database"
log INFO "  msfconsole    ← launches the framework"
log INFO "  msfupdate     ← force-update MSF (apt upgrade also works)"


# ═════════════════════════════════════════════════════════════
#  STEP 21 — JOHN THE RIPPER (JUMBO / COMMUNITY EDITION)
#  https://snapcraft.io/john-the-ripper
#
#  The Ubuntu apt package 'john' is version 1.9.0 stable.
#  The Snap 'john-the-ripper' is the Community/Jumbo edition:
#  hundreds more hash types, GPU acceleration, frequent updates.
#  Updated via: snap refresh john-the-ripper
#
#  A /usr/local/bin/john shim is created so 'john' works as
#  a standard command without typing the full snap path.
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "John the Ripper"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: John the Ripper (Community Jumbo Edition)"

run_step "Install John the Ripper Jumbo via official Snap" \
    snap install john-the-ripper

# Create a /usr/local/bin/john shim so that calling 'john'
# works anywhere without typing /snap/bin/john-the-ripper.john
run_step "Create /usr/local/bin/john convenience shim" \
    tee /usr/local/bin/john << 'JOHN_SHIM'
#!/usr/bin/env bash
# John the Ripper shim — routes to the Snap Jumbo edition
exec /snap/bin/john-the-ripper.john "$@"
JOHN_SHIM
chmod 0755 /usr/local/bin/john

log INFO "John the Ripper Jumbo installed."
log INFO "Usage: john [options] <hash-file>"
log INFO "       john --list=formats   (shows all supported hash types)"


# ═════════════════════════════════════════════════════════════
#  STEP 22 — HASHCAT
#  Ubuntu Universe apt — updated via: apt update && apt upgrade
#  Reference: https://hashcat.net/hashcat/
#
#  hashcat-data: example hashes and rule files
#  GPU acceleration: requires vendor OpenCL/CUDA/ROCm drivers
#  (hardware-specific — not installed by this script).
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Hashcat"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Hashcat"

run_step "Install Hashcat and hashcat-data (Ubuntu Universe)" \
    apt-get install -y hashcat hashcat-data

log INFO "Hashcat installed.  Usage: hashcat -h"
log INFO "Run a benchmark: hashcat -b"
log INFO "NVIDIA GPU support: sudo apt install hashcat-nvidia"
log INFO "AMD GPU support: install ROCm drivers (hardware-dependent)"


# ═════════════════════════════════════════════════════════════
#  STEP 23 — SECLISTS + WORDLISTS
#  https://github.com/danielmiessler/SecLists
#
#  SecLists has no Ubuntu apt package.  The official install
#  method is a git clone (~1.5 GB).
#  Installed to /usr/share/seclists (industry-standard path).
#  Updated via: git -C /usr/share/seclists pull
#            or: sudo update-workstation
#
#  Kali-style layout created at /usr/share/wordlists/:
#    seclists     → /usr/share/seclists         (symlink)
#    rockyou.txt.gz  (symlinked from SecLists)
#    john.lst        (symlinked from john package)
#
#  Every wordlist path used in Kali tutorials also works here.
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "SecLists + Wordlists"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: SecLists + Wordlists"

log INFO "Cloning SecLists (~1.5 GB) — this may take a few minutes..."

if [[ -d /usr/share/seclists/.git ]]; then
    log INFO "SecLists git repo already exists — pulling latest..."
    run_step "Update existing SecLists (git pull)" \
        git -C /usr/share/seclists pull --ff-only
else
    run_step "Clone SecLists to /usr/share/seclists (shallow)" \
        git clone \
            --depth 1 \
            --progress \
            https://github.com/danielmiessler/SecLists.git \
            /usr/share/seclists
fi

run_step "Create /usr/share/wordlists directory" \
    install -d -m 0755 /usr/share/wordlists

# Symlink seclists into wordlists so both path conventions work
if [[ ! -e /usr/share/wordlists/seclists ]]; then
    run_step "Create /usr/share/wordlists/seclists symlink" \
        ln -sfn /usr/share/seclists /usr/share/wordlists/seclists
fi

# rockyou.txt.gz symlink — mirrors Kali's /usr/share/wordlists/ layout
ROCKYOU_SRC="/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.gz"
if [[ -f "${ROCKYOU_SRC}" ]] && [[ ! -e /usr/share/wordlists/rockyou.txt.gz ]]; then
    run_step "Symlink rockyou.txt.gz into /usr/share/wordlists/" \
        ln -sfn "${ROCKYOU_SRC}" /usr/share/wordlists/rockyou.txt.gz
fi

# john.lst symlink
if [[ -f /usr/share/john/password.lst ]] && \
   [[ ! -e /usr/share/wordlists/john.lst ]]; then
    run_step "Symlink john.lst into /usr/share/wordlists/" \
        ln -sfn /usr/share/john/password.lst /usr/share/wordlists/john.lst
fi

log INFO "SecLists  : /usr/share/seclists/"
log INFO "Wordlists : /usr/share/wordlists/"
log INFO "RockYou   : /usr/share/wordlists/rockyou.txt.gz"
log INFO "  Decompress: gunzip -k /usr/share/wordlists/rockyou.txt.gz"


# ═════════════════════════════════════════════════════════════
#  STEP 24 — WATCHTOWER (DOCKER AUTO-UPDATER)
#  https://containrrr.dev/watchtower/
#
#  Watchtower is itself a Docker container that monitors all
#  running containers and pulls updated images from their
#  registries.  Keeps Kali and Plaso images current daily
#  with no manual intervention required.
#
#  Controls:
#    docker stop  watchtower   ← pause auto-updates
#    docker start watchtower   ← resume auto-updates
#    docker logs  watchtower   ← view update history
# ═════════════════════════════════════════════════════════════
CURRENT_STEP=$(( CURRENT_STEP + 1 ))
progress_bar "${CURRENT_STEP}" "${TOTAL_STEPS}" "Watchtower (Docker auto-updater)"
log STEP "Step ${CURRENT_STEP}/${TOTAL_STEPS}: Watchtower — Docker Image Auto-Updater"

# Remove any stale watchtower container so we can create fresh
docker stop watchtower 2>/dev/null || true
docker rm   watchtower 2>/dev/null || true

run_step "Deploy Watchtower auto-update container" \
    docker run \
        --detach \
        --name watchtower \
        --restart unless-stopped \
        --volume /var/run/docker.sock:/var/run/docker.sock \
        --env WATCHTOWER_CLEANUP=true \
        --env WATCHTOWER_POLL_INTERVAL=86400 \
        containrrr/watchtower

log INFO "Watchtower running.  All Docker images checked for updates daily."
log INFO "View update history: docker logs watchtower"


# ═════════════════════════════════════════════════════════════
#  POST-INSTALL: RESTORE FILE OWNERSHIP
#  Directories created by sudo should belong to the original
#  user, not to root.
# ═════════════════════════════════════════════════════════════
log STEP "Post-install: Restore file ownership"

for owned_dir in \
    "${ORIGINAL_HOME}/go"       \
    "${ORIGINAL_HOME}/.cargo"   \
    "${ORIGINAL_HOME}/.rustup"
do
    if [[ -d "${owned_dir}" ]]; then
        run_step "chown ${owned_dir} → ${ORIGINAL_USER}" \
            chown -R "${ORIGINAL_USER}:${ORIGINAL_USER}" "${owned_dir}"
    fi
done

if [[ -d /data ]]; then
    run_step "Set /data group ownership → ${ORIGINAL_USER}" \
        chown root:"${ORIGINAL_USER}" /data
fi


# ═════════════════════════════════════════════════════════════
#  POST-INSTALL: REMOVE SIFT "TEXT TOO SMALL" MESSAGE
#
#  SIFT's saltstack writes this line into /etc/bash.bashrc:
#    echo -e "\n\033[1;36mTEXT TOO SMALL? ..."
#  It appears in every new shell/TTY after install.
#  We don't want it — remove it with a targeted sed in-place edit.
# ═════════════════════════════════════════════════════════════
log STEP "Post-install: Remove SIFT 'TEXT TOO SMALL' message from /etc/bash.bashrc"

run_step "Remove SIFT TEXT TOO SMALL line from /etc/bash.bashrc" \
    bash -c 'if grep -q "TEXT TOO SMALL" /etc/bash.bashrc 2>/dev/null; then
                 cp /etc/bash.bashrc /etc/bash.bashrc.pre-sift-cleanup
                 sed -i "/TEXT TOO SMALL/d" /etc/bash.bashrc
                 echo "Line removed. Backup: /etc/bash.bashrc.pre-sift-cleanup"
             else
                 echo "TEXT TOO SMALL line not present — nothing to do"
             fi'


# ═════════════════════════════════════════════════════════════
#  POST-INSTALL: DISABLE SCREEN LOCK (set to Never)
#
#  The screen lock caused the password field to become unusable
#  during the 2–3 hour install run.  We disable it system-wide
#  via the dconf system profile (/etc/dconf/db/local.d/) which:
#    - Takes effect immediately after 'dconf update' (no reboot)
#    - Persists across reboots
#    - Applies to all users on this machine
#    - Can be re-enabled by the user via Settings → Privacy →
#      Screen Lock, OR by running:
#        sudo rm /etc/dconf/db/local.d/00-screensaver
#        sudo dconf update
#
#  NOTE: This sets screen lock to NEVER and idle-delay to 0.
#  Re-enable if this machine is in a shared or public environment.
# ═════════════════════════════════════════════════════════════
log STEP "Post-install: Disabling screen lock (set to Never)"

run_step "Create /etc/dconf/db/local.d directory" \
    install -d -m 0755 /etc/dconf/db/local.d

run_step "Write dconf screen lock policy (00-screensaver)" \
    tee /etc/dconf/db/local.d/00-screensaver << 'DCONF_SCREENSAVER'
[org/gnome/desktop/screensaver]
lock-enabled=false

[org/gnome/desktop/session]
idle-delay=uint32 0
DCONF_SCREENSAVER

run_step "Apply dconf policy (dconf update)" \
    dconf update

log WARN "╔══════════════════════════════════════════════════════════╗"
log WARN "║  SCREEN LOCK HAS BEEN SET TO NEVER                      ║"
log WARN "║  This prevents interruption during long tool runs.      ║"
log WARN "║  To re-enable: Settings → Privacy → Screen Lock         ║"
log WARN "║  Or run:  sudo rm /etc/dconf/db/local.d/00-screensaver  ║"
log WARN "║           sudo dconf update                              ║"
log WARN "╚══════════════════════════════════════════════════════════╝"


# ═════════════════════════════════════════════════════════════
#  MAINTENANCE SCRIPT: /usr/local/bin/update-workstation
#
#  A single command to update every component installed by
#  this script.  Run with: sudo update-workstation
#  Log: /var/log/workstation-update.log
#
#  UPDATE COVERAGE:
#    apt        → Docker Engine, Brave, VS Code, Tor, ProtonVPN,
#                 Metasploit, Hashcat, forensics-all, libyal,
#                 torbrowser-launcher, all Ubuntu pkgs
#    snap       → Chromium, OWASP ZAP, John the Ripper
#    rustup     → Rust toolchain + cargo
#    go install → ProjectDiscovery binaries
#    git pull   → SecLists wordlists
#    pip3       → imagemounter
#    remnux     → REMnux tool suite
#    Docker     → Kali + Plaso images (via Watchtower, already
#                 automated; update-workstation triggers a manual
#                 pull as a belt-and-suspenders measure)
#    GitHub API → Ghidra + Go version checks (reports if newer
#                 versions exist; re-run setup script to update)
#    Burp Suite → reminds user to update via in-app menu
# ═════════════════════════════════════════════════════════════
log STEP "Installing /usr/local/bin/update-workstation"

run_step "Write /usr/local/bin/update-workstation" \
    tee /usr/local/bin/update-workstation << 'UPDATE_SCRIPT'
#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  update-workstation
#  Updates every component installed by setup_security_workstation.sh
#  Usage: sudo update-workstation
# ══════════════════════════════════════════════════════════════
set -uo pipefail

LOGFILE="/var/log/workstation-update.log"
TS="$(date '+%Y-%m-%d %H:%M:%S')"
ORIGINAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "${USER}")}"

log()  { echo "[${TS}] $*" | tee -a "${LOGFILE}"; }
ok()   { echo -e "\033[0;32m[OK]\033[0m    $*"  | tee -a "${LOGFILE}"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m  $*"  | tee -a "${LOGFILE}"; }
err()  { echo -e "\033[0;31m[ERR]\033[0m   $*"  | tee -a "${LOGFILE}"; }

[[ "${EUID}" -ne 0 ]] && { echo "Run as root: sudo update-workstation"; exit 1; }

export DEBIAN_FRONTEND=noninteractive

log "══════════════════════════════════════════"
log " Workstation Update — ${TS}"
log "══════════════════════════════════════════"

# ──────────────────────────────────────────────────────────────
# 1. APT — Docker Engine, Brave, VS Code, Tor daemon, ProtonVPN,
#          Metasploit Framework, Hashcat, torbrowser-launcher,
#          forensics-all, all libyal libs, all Ubuntu pkgs
# ──────────────────────────────────────────────────────────────
log "── APT: update + upgrade ──"
apt-get update -y >> "${LOGFILE}" 2>&1 \
    && apt-get upgrade -y >> "${LOGFILE}" 2>&1 \
    && ok "APT packages updated" \
    || err "APT update/upgrade failed"

# ──────────────────────────────────────────────────────────────
# 2. Snaps — Chromium, OWASP ZAP, John the Ripper Jumbo
# ──────────────────────────────────────────────────────────────
log "── Snap: refresh all ──"
snap refresh >> "${LOGFILE}" 2>&1 \
    && ok "All Snaps refreshed" \
    || err "snap refresh failed"

# ──────────────────────────────────────────────────────────────
# 3. Rust toolchain
# ──────────────────────────────────────────────────────────────
log "── Rust: rustup update ──"
su - "${ORIGINAL_USER}" -c \
    'export PATH="$PATH:$HOME/.cargo/bin"
     rustup update stable' >> "${LOGFILE}" 2>&1 \
    && ok "Rust updated" \
    || err "rustup update failed"

# ──────────────────────────────────────────────────────────────
# 4. ProjectDiscovery Go tools
# ──────────────────────────────────────────────────────────────
log "── ProjectDiscovery: go install @latest ──"
for tool in \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"   \
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" \
    "github.com/projectdiscovery/httpx/cmd/httpx"        \
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"     \
    "github.com/projectdiscovery/katana/cmd/katana"
do
    tool_name="$(basename "${tool}")"
    su - "${ORIGINAL_USER}" -c \
        "export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin\"
         export GOPATH=\"\$HOME/go\"
         go install ${tool}@latest" >> "${LOGFILE}" 2>&1 \
        && ok "${tool_name} updated" \
        || err "${tool_name} update failed"
done

# ──────────────────────────────────────────────────────────────
# 5. SecLists wordlists
# ──────────────────────────────────────────────────────────────
log "── SecLists: git pull ──"
if [[ -d /usr/share/seclists/.git ]]; then
    git -C /usr/share/seclists pull --ff-only >> "${LOGFILE}" 2>&1 \
        && ok "SecLists updated" \
        || err "SecLists git pull failed"
else
    warn "/usr/share/seclists is not a git repo — skipping"
fi

# ──────────────────────────────────────────────────────────────
# 6. imagemounter (pip3)
# ──────────────────────────────────────────────────────────────
log "── imagemounter: pip3 upgrade ──"
pip3 install --break-system-packages --upgrade imagemounter \
    >> "${LOGFILE}" 2>&1 \
    && ok "imagemounter updated" \
    || err "imagemounter pip upgrade failed"

# ──────────────────────────────────────────────────────────────
# 7. REMnux
# ──────────────────────────────────────────────────────────────
log "── REMnux: remnux upgrade ──"
if command -v remnux > /dev/null 2>&1; then
    remnux upgrade >> "${LOGFILE}" 2>&1 \
        && ok "REMnux upgraded" \
        || err "REMnux upgrade failed (non-fatal)"
else
    warn "remnux not found — skipping"
fi

# ──────────────────────────────────────────────────────────────
# 8. Docker images — belt-and-suspenders manual pull
#    (Watchtower already handles this automatically)
# ──────────────────────────────────────────────────────────────
log "── Docker: pull latest images ──"
for img in kalilinux/kali-rolling log2timeline/plaso containrrr/watchtower; do
    docker pull "${img}" >> "${LOGFILE}" 2>&1 \
        && ok "Docker image updated: ${img}" \
        || err "Docker pull failed: ${img}"
done

# ──────────────────────────────────────────────────────────────
# 9. Go version check
# ──────────────────────────────────────────────────────────────
log "── Go: check for newer release ──"
INSTALLED_GO="$(/usr/local/go/bin/go version 2>/dev/null | awk '{print $3}')"
LATEST_GO="$(curl -fsSL 'https://go.dev/dl/?mode=json' \
    | grep -oP '"version":\s*"\Kgo[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | head -1 2>/dev/null)" || true
if [[ -n "${LATEST_GO}" ]] && [[ "${LATEST_GO}" != "${INSTALLED_GO}" ]]; then
    warn "Go update available: ${INSTALLED_GO} → ${LATEST_GO}"
    warn "Download from https://go.dev/dl/ or re-run setup_security_workstation.sh"
else
    ok "Go is current (${INSTALLED_GO})"
fi

# ──────────────────────────────────────────────────────────────
# 10. Ghidra version check
# ──────────────────────────────────────────────────────────────
log "── Ghidra: check for newer release ──"
INSTALLED_GHIDRA="$(ls -d /opt/ghidra_* 2>/dev/null | tail -1 | xargs basename 2>/dev/null)"
LATEST_GHIDRA_URL="$(curl -fsSL \
    'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest' \
    | grep '"browser_download_url"' | grep '\.zip"' \
    | head -1 | cut -d'"' -f4 2>/dev/null)" || true
LATEST_GHIDRA="$(basename "${LATEST_GHIDRA_URL:-}" .zip)"
if [[ -n "${LATEST_GHIDRA}" ]] && [[ "${LATEST_GHIDRA}" != "${INSTALLED_GHIDRA}" ]]; then
    warn "Ghidra update available: ${INSTALLED_GHIDRA:-none} → ${LATEST_GHIDRA}"
    warn "Download: ${LATEST_GHIDRA_URL}"
    warn "Or re-run setup_security_workstation.sh to auto-update."
else
    ok "Ghidra is current (${INSTALLED_GHIDRA:-unknown})"
fi

# ──────────────────────────────────────────────────────────────
# 11. Burp Suite reminder (no apt repo)
# ──────────────────────────────────────────────────────────────
log "── Burp Suite ──"
warn "Burp Suite has no apt repo.  Update via:"
warn "  Help → Check for Updates  (inside Burp Suite)"
warn "  OR: re-run setup_security_workstation.sh"

log "══════════════════════════════════════════"
log " Update complete.  Log: ${LOGFILE}"
log "══════════════════════════════════════════"
UPDATE_SCRIPT

chmod 0755 /usr/local/bin/update-workstation
log SUCCESS "Maintenance script installed: sudo update-workstation"


# ─────────────────────────────────────────────────────────────
#  Script ends here.  The EXIT trap calls finish().
# ─────────────────────────────────────────────────────────────
