# Battlestation 2026
An overhauled script to turn an Ubuntu 24.04 LTS VM into a Forensics workstation with a light flare of penetration testing tools onboard.

Simply run this script as root. It will attempt to the following, along with creating a log file of errors etc. I made this with the assistance of Claude Code.

# WHAT THIS SCRIPT INSTALLS (in order):
   Step  1  System update, prerequisites, Universe repo
   
   Step  2  Docker Engine          (official docker.com repo)
   
   Step  3  Kali Linux Docker image (kalilinux/kali-rolling)
   
   Step  4  Plaso/log2timeline      (log2timeline/plaso Docker)
   
   Step  5  Ghidra                  (NSA GitHub latest release)
   
   Step  6  Network tools: nmap, masscan, OWASP ZAP
   
   Step  7  Burp Suite Community    (PortSwigger official)
   
   Step  8  Tor daemon              (deb.torproject.org repo)
   
   Step  9  Tor Browser             (torbrowser-launcher)
   
   Step 10  Brave Browser           (brave.com official apt repo)
   
   Step 11  Chromium Browser        (official Snap, Canonical)
   
   Step 12  Go (Golang)             (go.dev official tarball)
   
   Step 13  Rust                    (rustup, rust-lang.org)
   
   Step 14  ProjectDiscovery tools  (nuclei, subfinder, httpx, naabu, katana — Go binaries)
   
   Step 15  ProtonVPN               (protonvpn.com official repo)
   
   Step 16  Visual Studio Code      (Microsoft official apt repo)
   
   Step 17  Ubuntu Forensics        (forensics-all + -all-gui)
   
   Step 18  DFIR forensics libs     (libyal suite + imagemounter)
   
   Step 19  REMnux malware-analysis (addon mode, amd64 only)
   
   Step 20  Metasploit Framework    (apt.metasploit.com repo)
   
   Step 21  John the Ripper         (john-the-ripper Snap — Community/Jumbo edition)
   
   Step 22  Hashcat                 (Ubuntu Universe apt)
   
   Step 23  SecLists + Wordlists    (git clone, rockyou, symlinks)
   
   Step 24  Watchtower              (Docker auto-update container)
   
   Final    /usr/local/bin/update-workstation maintenance script

  POST-INSTALL ACTIONS REQUIRED:
   
   1.  REBOOT — REMnux + docker group both take effect on reboot.
                After reboot, run 'docker' WITHOUT sudo.
                (Or use 'newgrp docker' in the current terminal.)
   
   2.  source ~/.bashrc   (or open new terminal for Go/Rust PATH)
   
   3.  Run 'torbrowser-launcher' once as your regular user to
       download and verify the Tor Browser bundle.
   
   4.  Run 'msfdb init' as your regular user (post-reboot) to
       initialise the Metasploit PostgreSQL database.
   
   5.  To update everything: sudo update-workstation

# MAINTAINABILITY OVERVIEW — how each component is updated:

   apt update && apt upgrade   → Docker Engine, Brave, VS Code, Tor daemon, ProtonVPN, Metasploit Framework, Hashcat, forensics-all, libyal libs, torbrowser-launcher, all Ubuntu Universe packages
   
   snap refresh                → Chromium, OWASP ZAP, John the Ripper (Jumbo Snap)
   
   rustup update               → Rust toolchain + cargo
   
   go install @latest          → ProjectDiscovery binaries
   
   git -C /usr/share/seclists pull → SecLists wordlists
   
   pip3 install --upgrade      → imagemounter
   
   remnux upgrade              → REMnux tool suite
   
   Watchtower (auto-daily)     → Kali + Plaso + all Docker images
   Manual / re-run script      → Ghidra, Burp Suite, Go itself
   sudo update-workstation     → does ALL of the above
