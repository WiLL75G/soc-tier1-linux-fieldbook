# 🎯 MITRE ATT&CK Mapping for Linux SOC Analysts

> A practical mapping of Linux indicators to MITRE ATT&CK techniques. For every technique a Tier 1 analyst encounters: what it is, what to look for, and which commands to run.

**Author:** James Williams ([@WilliamCyberSec](https://x.com/WilliamCyberSec))  
**Companion to:** [COMMANDS.md](./COMMANDS.md), [FILESYSTEM.md](./FILESYSTEM.md), [DAILY-COMMANDS.md](./DAILY-COMMANDS.md)

---

## 📖 What Is MITRE ATT&CK?

**MITRE ATT&CK** is a free, globally-used knowledge base of attacker behaviors. It catalogs *how* real attackers operate, organized into:

- **Tactics** — the *why* (the attacker's goal at a stage)
- **Techniques** — the *how* (the specific method used)
- **Sub-techniques** — granular variants of techniques

Every technique gets an ID like **T1059** (Command and Scripting Interpreter) or **T1053.003** (Scheduled Task/Job: Cron). When you read a SOC analyst's incident report, those IDs aren't decoration — they're the universal language of the field. Learn to think in technique IDs and your reports, conversations, and interviews instantly sound professional.

**The 14 ATT&CK tactics, in attack order:**

1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

This document focuses on tactics 3–14 (post-compromise) since that's where Tier 1 analysts spend their time on Linux systems.

---

## 📚 Table of Contents

1. [Initial Access](#1-initial-access)
2. [Execution](#2-execution)
3. [Persistence](#3-persistence)
4. [Privilege Escalation](#4-privilege-escalation)
5. [Defense Evasion](#5-defense-evasion)
6. [Credential Access](#6-credential-access)
7. [Discovery](#7-discovery)
8. [Lateral Movement](#8-lateral-movement)
9. [Collection](#9-collection)
10. [Command and Control](#10-command-and-control)
11. [Exfiltration](#11-exfiltration)
12. [Impact](#12-impact)
13. [Master Detection Table](#13-master-detection-table)

---

## 1. Initial Access

How the attacker gets in.

### T1078 — Valid Accounts

**What:** Attacker uses legitimate credentials (stolen, leaked, or default).

**Where to look:** `/var/log/auth.log`, `last -a`

**Commands:**
```bash
last -a | head -50
sudo grep "Accepted" /var/log/auth.log | tail -50
sudo grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c
```

**Red flag:** successful login from an IP that has never been seen before, or at an unusual hour.

---

### T1190 — Exploit Public-Facing Application

**What:** Attacker exploits a vulnerability in an internet-facing service (web app, SSH, etc.).

**Where to look:** Web server logs, application logs, `journalctl`

**Commands:**
```bash
tail -100 /var/log/apache2/access.log
tail -100 /var/log/nginx/access.log
journalctl -u apache2 --since "1 hour ago"
```

**Red flag:** sudden 500 errors, unusual POST requests with shell-like syntax, requests for `/.env` or `/admin.php`.

---

## 2. Execution

How the attacker runs code.

### T1059 — Command and Scripting Interpreter

#### T1059.004 — Unix Shell

**What:** Attacker uses bash, sh, or zsh to execute commands.

**Where to look:** `auth.log` for sudo activity, bash history, process listings

**Commands:**
```bash
cat ~/.bash_history
cat /root/.bash_history
ps auxf | grep -E "sh -c|bash -c"
```

#### T1059.006 — Python

**What:** Attacker runs Python scripts (common for reverse shells).

**Commands:**
```bash
ps aux | grep python
journalctl --since "1 hour ago" | grep -i python
```

**Red flag:** `python -c 'import socket...'` is a classic reverse-shell signature.

---

## 3. Persistence

How the attacker survives a reboot. **The most important tactic for Tier 1 to master.**

### T1053.003 — Scheduled Task/Job: Cron

**Where to look:**
```bash
crontab -l                                  # current user
sudo crontab -l                             # root
cat /etc/crontab
ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
ls -la /etc/cron.d/
sudo ls -la /var/spool/cron/crontabs/
```

**Red flag:** any cron entry pointing to `/tmp`, `/dev/shm`, or a hidden file. Cron jobs with curl/wget downloads.

---

### T1098.004 — Account Manipulation: SSH Authorized Keys

**What:** Attacker adds their public key to a user's `authorized_keys` file for passwordless persistent access.

**Where to look:**
```bash
sudo find / -name "authorized_keys" 2>/dev/null
sudo find / -name "authorized_keys" -exec ls -la {} \; -exec cat {} \; 2>/dev/null
```

**Red flag:** any `authorized_keys` file you didn't create, or new keys appended to one you did.

---

### T1136 — Create Account

#### T1136.001 — Local Account

**What:** Attacker creates a new user account.

**Where to look:**
```bash
getent passwd | tail -20
sudo grep "useradd" /var/log/auth.log
sudo grep "new user" /var/log/auth.log
```

**Red flag:** account creation events you didn't authorize, or accounts with unusual names (e.g., backup, test, system).

---

### T1543.002 — Create or Modify System Process: Systemd Service

**What:** Attacker creates a systemd service or modifies an existing one to run their code.

**Where to look:**
```bash
sudo ls -la /etc/systemd/system/
sudo ls -la /usr/lib/systemd/system/
systemctl list-unit-files --state=enabled
systemctl list-units --type=service --state=running
```

**Red flag:** new `.service` files with ExecStart paths pointing to `/tmp/`, `/var/tmp/`, or user home directories.

---

### T1546.004 — Event Triggered Execution: Unix Shell Configuration Modification

**What:** Attacker modifies shell startup files (`.bashrc`, `.profile`, `/etc/profile`) to execute code at login.

**Where to look:**
```bash
cat ~/.bashrc ~/.bash_profile ~/.profile
sudo cat /etc/profile /etc/bash.bashrc
ls -la /etc/profile.d/
```

**Red flag:** appended lines that download or execute scripts.

---

## 4. Privilege Escalation

How the attacker becomes root.

### T1548.001 — Abuse Elevation Control Mechanism: SUID/SGID

**What:** Attacker exploits SUID binaries (files that run as their owner regardless of who executes them).

**Where to look:**
```bash
sudo find / -perm -4000 -type f 2>/dev/null
sudo find / -perm -2000 -type f 2>/dev/null
```

**Red flag:** new SUID binaries in `/tmp`, `/home`, or anywhere outside standard system paths. Check against your baseline.

---

### T1068 — Exploitation for Privilege Escalation

**What:** Attacker exploits a kernel or service vulnerability to escalate.

**Where to look:**
```bash
uname -r                                    # kernel version for CVE lookup
sudo journalctl -p err --since "1 hour ago"
dmesg | tail -50
```

**Red flag:** kernel oopses, segfaults in services, sudden privilege transitions in auth.log.

---

## 5. Defense Evasion

How the attacker hides.

### T1070 — Indicator Removal

#### T1070.002 — Clear Linux Logs

**Where to look:**
```bash
ls -la /var/log/
sudo wc -l /var/log/auth.log /var/log/syslog
```

**Red flag:** log files that are much smaller than yesterday, or completely empty, or have very recent mtimes for old entries.

#### T1070.003 — Clear Command History

**Where to look:**
```bash
cat ~/.bash_history
ls -la ~/.bash_history
```

**Red flag:** empty `.bash_history` on a long-active user, or a `.bash_history` symlinked to `/dev/null`.

#### T1070.006 — Timestomp

**What:** Attacker modifies file timestamps to evade time-based detection.

**Where to look:**
```bash
stat /suspicious/file
```

**Red flag:** `Access`, `Modify`, and `Change` times that don't make sense together (e.g., Change time before Modify time is impossible naturally).

---

### T1027 — Obfuscated Files or Information

**What:** Attacker base64-encodes, packs, or obfuscates payloads.

**Where to look:**
```bash
strings /suspicious/binary | head -50
file /suspicious/binary
```

**Red flag:** binaries containing long base64 strings, or scripts starting with `eval $(echo ... | base64 -d)`.

---

### T1564.001 — Hide Artifacts: Hidden Files and Directories

**Where to look:**
```bash
ls -la ~                                   # files starting with .
find / -name ".*" -type f 2>/dev/null
find /tmp -name ".*" -type f 2>/dev/null
```

**Red flag:** hidden files in /tmp, hidden directories with executables in home dirs.

---

## 6. Credential Access

How the attacker steals credentials.

### T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow

**Where to look:**
```bash
sudo grep "passwd\|shadow" /var/log/auth.log
sudo stat /etc/shadow                       # check last access time
```

**Red flag:** unexpected reads of `/etc/shadow`. Any process other than auth tools accessing it is suspicious.

---

### T1110 — Brute Force

#### T1110.001 — Password Guessing

```bash
sudo grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
sudo lastb -n 50
```

**Red flag:** dozens or hundreds of failed logins from a single IP.

---

### T1552.004 — Unsecured Credentials: Private Keys

**Where to look:**
```bash
sudo find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
```

**Red flag:** private keys with overly permissive permissions (e.g., 644 instead of 600).

---

## 7. Discovery

How the attacker learns the environment.

### T1083 — File and Directory Discovery

**Bash history will show:**
```
ls -la /etc
find / -name "*.conf" 2>/dev/null
ls -la /home
```

### T1087 — Account Discovery

**Bash history will show:**
```
cat /etc/passwd
getent passwd
id
groups
```

### T1057 — Process Discovery

**Bash history will show:**
```
ps aux
ps -ef
top
```

### T1018 — Remote System Discovery

**Bash history will show:**
```
arp -a
ip route
cat /etc/hosts
```

**Where to look:** `~/.bash_history` is your best friend after a compromise — you can see what the attacker explored.

---

## 8. Lateral Movement

How the attacker spreads.

### T1021.004 — Remote Services: SSH

**Where to look:**
```bash
last -a                                     # who connected from where
sudo grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort -u
```

**Red flag:** SSH sessions originating *from* this host to other internal hosts (check outbound connections):
```bash
sudo ss -tnp | grep ":22"
```

---

## 9. Collection

How the attacker gathers data before exfiltration.

### T1005 — Data from Local System

**Bash history will show:**
```
find /home -name "*.pdf"
tar -czf /tmp/loot.tar.gz /home/user/documents
```

**Where to look:**
```bash
find / -name "*.tar.gz" -mtime -1 2>/dev/null
find /tmp -size +10M 2>/dev/null
```

---

## 10. Command and Control

How the attacker communicates with the compromised host.

### T1071.001 — Application Layer Protocol: Web Protocols

**Where to look:**
```bash
sudo ss -tnp state established
sudo ss -tnp state established | grep -E ":80 |:443 "
```

**Red flag:** persistent HTTPS connections to IPs (not domains), connections to known C2 infrastructure.

---

### T1090 — Proxy

**Where to look:**
```bash
ps aux | grep -E "proxychains|tor|ssh.*-L|ssh.*-R"
```

---

## 11. Exfiltration

How the attacker steals the data.

### T1048 — Exfiltration Over Alternative Protocol

**Where to look:**
```bash
sudo ss -tnp state established                # active connections
sudo iptables -L -n -v                        # firewall traffic counters
```

**Red flag:** large outbound transfers, especially to non-business destinations.

---

### T1041 — Exfiltration Over C2 Channel

**Where to look:** same connection as the C2 channel above. The attacker uses one tunnel for both control and exfil.

---

## 12. Impact

The damage phase.

### T1486 — Data Encrypted for Impact (Ransomware)

**Where to look:**
```bash
find / -name "*.encrypted" -o -name "*.locked" -o -name "*README*RANSOM*" 2>/dev/null
```

### T1490 — Inhibit System Recovery

**Where to look:**
```bash
systemctl status backup.service             # are backups running?
ls -la /etc/cron.*/                          # have backup jobs been removed?
```

### T1496 — Resource Hijacking (Cryptomining)

**Where to look:**
```bash
ps aux --sort=-%cpu | head -10
ps aux | grep -E "xmrig|minerd|stratum"
```

**Red flag:** high-CPU process you can't identify; outbound connections to mining pool ports (3333, 5555, 7777, 14444, stratum+tcp://).

---

## 13. Master Detection Table

A consolidated quick-reference table. **Print this. Tape it to your monitor.**

| MITRE ID | Technique | Linux Detection Command |
|---|---|---|
| **T1078** | Valid Accounts | `last -a` |
| **T1059.004** | Unix Shell | `cat ~/.bash_history` |
| **T1053.003** | Cron | `crontab -l; sudo ls -la /etc/cron.*` |
| **T1098.004** | SSH Authorized Keys | `sudo find / -name "authorized_keys" 2>/dev/null` |
| **T1136.001** | Create Account | `getent passwd \| tail` |
| **T1543.002** | Systemd Service | `sudo ls -la /etc/systemd/system/` |
| **T1546.004** | Shell Config Mod | `cat ~/.bashrc /etc/profile` |
| **T1548.001** | SUID/SGID | `sudo find / -perm -4000 -type f 2>/dev/null` |
| **T1070.002** | Clear Linux Logs | `ls -la /var/log/` (compare sizes vs. baseline) |
| **T1070.003** | Clear History | `cat ~/.bash_history` (empty = flag) |
| **T1027** | Obfuscation | `strings <binary> \| grep -E "base64\|eval"` |
| **T1564.001** | Hidden Files | `find /tmp -name ".*" 2>/dev/null` |
| **T1003.008** | passwd/shadow Dump | `stat /etc/shadow` |
| **T1110** | Brute Force | `sudo lastb \| head -20` |
| **T1552.004** | Private Keys | `sudo find / -name "id_rsa" 2>/dev/null` |
| **T1021.004** | SSH Lateral | `sudo ss -tnp \| grep ":22"` |
| **T1071.001** | HTTPS C2 | `sudo ss -tnp state established` |
| **T1496** | Cryptomining | `ps aux --sort=-%cpu \| head -10` |

---

## 🎓 How To Use This in Real Investigations

When you write an incident report, every finding should reference its MITRE ID. Example:

> *"At 14:23 UTC, host `webserver-01` showed 487 failed SSH login attempts from 185.220.x.x targeting accounts `root` and `admin` (**MITRE T1110.001 — Password Guessing**). No successful logins followed. Recommendation: block source IP at perimeter."*

That single sentence — with the technique ID — instantly communicates analyst maturity to anyone reading the ticket.

---

## 📚 Where To Learn More

- **MITRE ATT&CK Linux Matrix:** https://attack.mitre.org/matrices/enterprise/linux/
- **MITRE ATT&CK Navigator:** https://mitre-attack.github.io/attack-navigator/ — free tool for mapping coverage
- **Atomic Red Team:** open-source library that lets you simulate ATT&CK techniques in your lab safely

---

## 📄 License

[MIT](./LICENSE) — fork, adapt, use freely.
