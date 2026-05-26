# SOC Tier 1 Analyst Linux Command Reference

> A domain-grouped command reference for entry-level SOC Tier 1 Analyst work on Linux systems. Built and maintained as part of my ongoing SOC training journey.
>  

---

## About This Reference

This isn't a generic Linux tutorial. It's the working command set used during daily SOC morning ritual exercises in my home lab every command here has been selected because a SOC Tier 1 Analyst genuinely runs it during real shifts. Commands are grouped by **operational domain** (system, network, processes, logs, etc.) so the mental model matches how analysts actually think during investigations.

Each entry follows the same pattern:

- **Command syntax**
- *What it does in plain English*
- *Why a SOC analyst cares*
- *Example or note*

MITRE ATT&CK technique IDs are cited where relevant.

---

## How To Use This

1. **Don't memorize all of it at once.** Pick 5–7 commands per week. Type them daily in your lab until the output is recognizable without thinking.
2. **Read every output line by line.** The skill isn't typing the command it's recognizing when output looks *off*.
3. **Practice in a controlled lab.** Mine runs on macOS host with UTM managing Ubuntu Server (target), Kali Linux (attacker), and Windows 11 (target). Splunk lives on the macOS host for log analysis.
4. **Journal findings daily.** Pattern recognition is built one observation at a time.

---

## Table of Contents

1. [System Information & Orientation](#1-system-information--orientation)
2. [Users & Authentication](#2-users--authentication)
3. [File System Operations](#3-file-system-operations)
4. [Search & Filter Utilities](#4-search--filter-utilities)
5. [Process Inspection](#5-process-inspection)
6. [Network Inspection](#6-network-inspection)
7. [Log Analysis](#7-log-analysis)
8. [Persistence & Scheduled Tasks](#8-persistence--scheduled-tasks)
9. [Service Management](#9-service-management)
10. [File Integrity & Hashing](#10-file-integrity--hashing)
11. [Permissions & Ownership](#11-permissions--ownership)
12. [Package Management](#12-package-management)
13. [History & Forensics](#13-history--forensics)
14. [Pipes, Redirects & Glue](#14-pipes-redirects--glue)
15. [SOC Workflow One-Liners](#15-soc-workflow-one-liners)

---

## 1. System Information & Orientation

The first commands you run after SSH'ing into any system. Establishes *where you are, who you are, and what you're working with*.

| Command | Purpose |
|---|---|
| `pwd` | Print current working directory. Confirms where commands will land. |
| `whoami` | Effective username. Confirms whose privileges are active. |
| `id` | UID, GID, and group memberships. Reveals if you're in `sudo`, `adm`, `docker` attackers target these groups. |
| `hostname` | System name. Confirms which box you're on. |
| `uname -a` | Kernel version, architecture, OS. Needed for CVE lookups. |
| `date` | Current system time. Every log timestamp depends on accurate clock. |
| `uptime` | How long the system has been up + load average. Unexpected reboot = investigate. |
| `timedatectl` | NTP / time-sync status. Always verify before trusting timelines. |
| `lscpu` | CPU info. Useful when investigating high-CPU malware (cryptominers). |
| `free -h` | Memory usage in human-readable form. Memory pressure may indicate compromise. |

**SOC mindset:** *"Am I on the right system, at the right time, with the right access?"*

---

## 2. Users & Authentication

Who can log in, who is logged in, and who has tried. **New accounts are the #1 sign of compromise** (MITRE T1136 Create Account).

| Command | Purpose |
|---|---|
| `getent passwd` | Every account on the system, from all account sources. |
| `getent passwd \| awk -F: '$7 !~ /nologin\|false/ {print}'` | Only accounts with real login shells. |
| `getent group sudo` | Members of the sudo group. Anyone here can become root. |
| `who` | Currently logged-in users. |
| `w` | Like `who` but also shows what each user is doing. |
| `last -a` | Successful login history with source IPs. Anomalous geographies jump out here. |
| `sudo lastb` | Failed login history. The brute-force evidence file. |
| `sudo -l` | Lists what commands your user can run with sudo. |
| `cat /etc/passwd` | Raw passwd file (use `getent passwd` instead for full picture). |
| `cat /etc/shadow` | Password hashes (root only). |

**SOC mindset:** *"Who has access to this system, and who has used it?"*

---

## 3. File System Operations

Navigation, inspection, and basic forensics on files.

| Command | Purpose |
|---|---|
| `ls -lah` | List with permissions, owner, size, mtime. The most-used SOC command. |
| `cd <path>` | Change directory. `cd -` jumps to previous; `cd ~` to home. |
| `cat <file>` | Print file contents. For short files only. |
| `less <file>` | Page through long files. `/pattern` searches inside, `q` quits. |
| `head -n 20 <file>` | First 20 lines. |
| `tail -n 20 <file>` | Last 20 lines. Workhorse log command. |
| `tail -f <file>` | Watch a file live as it grows. Essential during active incidents. |
| `stat <file>` | Full metadata: size, permissions, access/modify/change times. Forensics gold. |
| `file <file>` | Identifies file type by content, not extension. Reveals binaries renamed as `.txt`. |
| `strings <binary>` | Extracts readable text from a binary. Quick triage of suspicious executables. |
| `find <path> [criteria]` | The hunter's command. See examples below. |
| `du -sh <dir>` | Directory size, human-readable. |
| `df -h` | Disk space per filesystem. Disks filling up = possible exfil staging or log floods. |

**Common `find` patterns:**
```bash
find /tmp -type f -mtime -1                    # files in /tmp modified in last 24h
find / -perm -4000 -type f 2>/dev/null         # all SUID binaries
find /home -name ".*history"                   # all hidden history files
find / -mmin -60 -type f 2>/dev/null           # files changed in last 60 minutes
find / -name "authorized_keys" 2>/dev/null     # all SSH key files (T1098.004)
```

**SOC mindset:** *"What appeared, what changed, what shouldn't be here?"*

---

## 4. Search & Filter Utilities

**The analyst's bread and butter.** Chained together, these four commands do 80% of log analysis.

| Command | Purpose |
|---|---|
| `grep "pattern" file` | Print matching lines. Core log filter. |
| `awk '{print $1}' file` | Extract specific columns. `$NF` for last column. |
| `sort` | Sort lines. `-r` reverse, `-n` numeric, `-u` unique. |
| `uniq -c` | Count consecutive duplicates (input must be sorted first). |
| `cut -d':' -f1 file` | Extract fields from delimited files. |
| `wc -l file` | Count lines. |
| `sed 's/old/new/g' file` | Find and replace in streams. |
| `tr ' ' '\n'` | Translate / squeeze characters. Useful for reformatting. |

**Essential `grep` flags:**

| Flag | Effect |
|---|---|
| `-i` | Case-insensitive |
| `-v` | Invert (lines NOT matching) |
| `-c` | Count matches |
| `-r` | Recursive search through directories |
| `-A 3` | Show 3 lines after match |
| `-B 3` | Show 3 lines before match |
| `-E` | Extended regex |

**SOC mindset:** *"Out of thousands of log lines, which ones matter?"*

---

## 5. Process Inspection

What is currently executing on the system. **Processes from `/tmp`, `/dev/shm`, or `/var/tmp` are a major red flag.**

| Command | Purpose |
|---|---|
| `ps aux` | All running processes, snapshot view. |
| `ps auxf` | Same but as a tree (parent → child). Reveals web shells (e.g., bash spawned by apache2). |
| `ps aux --sort=-%cpu \| head -10` | Top 10 CPU consumers. Cryptominers live here. |
| `ps aux --sort=-%mem \| head -10` | Top 10 memory consumers. |
| `top` | Live process view, refreshes every second. `q` to quit. |
| `htop` | Prettier interactive `top`. |
| `pgrep <name>` | Find PIDs by name. `pgrep sshd` confirms SSH is running. |
| `pstree` | Visual process tree. |
| `lsof -i` | Open network connections with process owners. |
| `lsof -p <pid>` | All files a specific process has open. |
| `kill <pid>` / `kill -9 <pid>` | Terminate a process; `-9` is forceful. |

**SOC mindset:** *"What is running that shouldn't be?"*

---

## 6. Network Inspection

Attack surface and active connections. **Unknown listening ports are how backdoors hide.**

| Command | Purpose |
|---|---|
| `ss -tulnp` | Listening TCP/UDP ports with process names. THE command for attack-surface review. |
| `ss -tnp state established` | Active TCP connections. Catches active C2 channels. |
| `ip addr` (or `ip a`) | Network interfaces and their IPs. New interface = possible tunnel. |
| `ip route` | Routing table. Changed default route = traffic hijack risk. |
| `ping <host>` | ICMP reachability test. |
| `traceroute <host>` | Network path to a host. |
| `dig <domain>` | DNS lookup. Investigate suspicious domains. |
| `nslookup <domain>` | Alternative DNS lookup tool. |
| `host <domain>` | Simple DNS resolution. |
| `curl -I https://example.com` | Fetch HTTP headers only. Safely probe a suspicious URL. |
| `wget <url>` | Download a file. Common in attacker bash history. |
| `sudo iptables -L -n -v` | Active firewall rules (legacy). |
| `sudo ufw status verbose` | UFW firewall status (modern Ubuntu). |

**`ss` flag breakdown** memorize these:
- `-t` TCP
- `-u` UDP
- `-l` listening sockets only
- `-n` numeric (don't resolve hostnames)
- `-p` show process

**SOC mindset:** *"What is exposed to the network, and what is it talking to?"*

---

## 7. Log Analysis

Where investigations live. On modern Ubuntu, `journalctl` is now the primary tool — `/var/log/*` files still exist but `journalctl` is more powerful.

### journalctl Modern systemd log query

| Command | Purpose |
|---|---|
| `journalctl -u ssh` | Logs for SSH service only. |
| `journalctl --since "1 hour ago"` | Time-bounded query. |
| `journalctl --since "2026-01-15" --until "2026-01-16"` | Specific date range. |
| `journalctl -p err` | Errors only (priority filter). |
| `journalctl -f` | Live tail. |
| `journalctl _PID=1234` | Logs from one specific process. |
| `journalctl -b` | Logs from current boot only. |
| `journalctl -b -1` | Logs from previous boot. |
| `journalctl --disk-usage` | How much disk the journal is using. |

### Key Log Files

| File | What's In It |
|---|---|
| `/var/log/auth.log` | Authentication events: logins, sudo, SSH |
| `/var/log/syslog` | General system events |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dpkg.log` | Package installation history |
| `/var/log/apache2/access.log` | Web server hits (if Apache) |
| `/var/log/nginx/access.log` | Web server hits (if nginx) |
| `~/.bash_history` | Shell command history (per user) |

### Other Log Tools

| Command | Purpose |
|---|---|
| `dmesg` | Kernel ring buffer. USB insertions, hardware events, kernel exploit traces. |
| `tail -f /var/log/auth.log` | Live monitoring of authentication events. |

**SOC mindset:** *"What happened, when, and to whom?"*

---

## 8. Persistence & Scheduled Tasks

How attackers maintain access after reboot. **MITRE T1053 Scheduled Task/Job** is the #1 Linux persistence technique.

| Command | Purpose |
|---|---|
| `crontab -l` | Your user's scheduled jobs. Usually empty for normal users. |
| `sudo crontab -l` | Root's scheduled jobs. |
| `ls -la /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly` | System-wide scheduled scripts. |
| `cat /etc/crontab` | The master system crontab. |
| `ls -la /var/spool/cron/crontabs/` | All user crontabs (root-readable). |
| `systemctl list-timers --all` | Systemd timers modern cron alternative. Often overlooked. |
| `at -l` | Pending one-time scheduled jobs. |

**SOC mindset:** *"What is set to run later that I didn't authorize?"*

---

## 9. Service Management

What's running now and what's configured to run at boot.

| Command | Purpose |
|---|---|
| `systemctl status <service>` | Is this service running? What was its last output? |
| `systemctl list-units --type=service --state=running` | All currently running services. |
| `systemctl list-unit-files --state=enabled` | What starts at boot (persistence). |
| `systemctl list-units --failed` | Failed services often a tampering or exploitation signal. |
| `systemctl start <service>` | Start a service. |
| `systemctl stop <service>` | Stop a service. |
| `systemctl restart <service>` | Restart a service. |
| `systemctl enable <service>` | Set service to start on boot. |
| `systemctl disable <service>` | Remove from boot startup. |

**SOC mindset:** *"What services are running, and which will come back if I reboot?"*

---

## 10. File Integrity & Hashing

Detect tampering. Hashes are the foundation of file integrity monitoring (FIM).

| Command | Purpose |
|---|---|
| `sha256sum <file>` | SHA-256 hash. Modern standard. Submit unknowns to VirusTotal by hash. |
| `md5sum <file>` | MD5 hash. Weaker but still common in older threat intel. |
| `sha1sum <file>` | SHA-1 hash. Used in many older feeds. |
| `diff file1 file2` | Show line-by-line differences. Compare baseline to current. |
| `cmp file1 file2` | Byte-by-byte comparison of two files. |

**SOC mindset:** *"Has anything been modified that shouldn't have been?"*

---

## 11. Permissions & Ownership

Reading and changing the access rights on files and directories.

| Command | Purpose |
|---|---|
| `ls -l` | Shows permissions in the leftmost column. |
| `chmod` | Change permissions. `chmod 755 file`, `chmod +x file`. |
| `chown user:group file` | Change owner / group. |
| `chgrp group file` | Change group only. |
| `find / -perm -4000 -type f 2>/dev/null` | All SUID binaries. Top privilege-escalation vector. |
| `find / -perm -2000 -type f 2>/dev/null` | All SGID binaries. |
| `find / -perm -o+w -type f 2>/dev/null` | World-writable files attacker payload landing zones. |

**Reading `rwxr-xr-x` left to right:** owner perms, group perms, others perms.

**SOC mindset:** *"Who can read, write, or execute this and should they?"*

---

## 12. Package Management

Installed software inventory and source verification.

| Command | Purpose |
|---|---|
| `dpkg -l` | All installed Debian packages. |
| `apt list --installed` | Same plus version info. |
| `dpkg -L <pkg>` | List files installed by a package. |
| `dpkg -S <file>` | Which package does this file belong to? |
| `apt-cache policy <pkg>` | Where did this package come from? Which repo? |
| `cat /etc/apt/sources.list` | Configured APT repositories. |
| `ls /etc/apt/sources.list.d/` | Third-party repo configs. |
| `which <command>` | Where does this binary live? `which nc` → `/tmp/nc` is wildly suspicious. |
| `whereis <command>` | Locates binary, source, and man page. |

**SOC mindset:** *"What software exists here, and where did it come from?"*

---

## 13. History & Forensics

User activity reconstruction.

| Command | Purpose |
|---|---|
| `history` | Your shell history (current and past sessions). |
| `cat ~/.bash_history` | Persistent history on disk. |
| `history \| grep <pattern>` | Search shell history. |
| `find /home -name ".*history"` | Locate all hidden history files. |

**Red flag:** an empty `~/.bash_history` on a system that's been used for weeks = log-clearing attempt (MITRE T1070.003).

**SOC mindset:** *"What did this user actually do?"*

---

## 14. Pipes, Redirects & Glue

The connective tissue of Linux analysis. The entire art of log triage is built on these.

| Operator | Effect |
|---|---|
| `\|` | Pipe feed one command's output into the next. |
| `>` | Redirect output to a file (overwrites). |
| `>>` | Redirect output to a file (appends). |
| `2>` | Redirect error output to a file. |
| `2>&1` | Combine error and normal output streams. |
| `&&` | Run next command only if previous succeeded. |
| `\|\|` | Run next command only if previous failed. |
| `;` | Run commands sequentially regardless of exit code. |

**Bonus:**

| Command | Purpose |
|---|---|
| `man <command>` | Built-in manual page. When you forget flags, `man ss` is your friend. |
| `tldr <command>` | Community-friendly cheatsheets (requires installation). |
| `which <command>` | Locate a command in your PATH. |

---

## 15. SOC Workflow One-Liners

Real one-liners that combine multiple commands. These are what separates someone who *knows* the commands from someone who *uses* them.

**Top 10 IPs with failed SSH logins:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $11}' \
  | sort | uniq -c | sort -rn | head -10
```

**Top 10 usernames being targeted in failed logins:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $9}' \
  | sort | uniq -c | sort -rn | head -10
```

**All files modified in the last hour, system-wide:**
```bash
sudo find / -mmin -60 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

**All listening ports + the process names behind them:**
```bash
sudo ss -tulnp
```

**Recent successful root logins:**
```bash
last -a root | head -10
```

**Five largest files in /var (look for log floods or staged data):**
```bash
sudo du -ah /var 2>/dev/null | sort -rh | head -5
```

**Recent sudo activity:**
```bash
sudo grep "sudo:" /var/log/auth.log | tail -20
```

**All processes running from suspicious directories:**
```bash
ps aux | grep -E "/tmp/|/dev/shm/|/var/tmp/" | grep -v grep
```

**Find all files owned by a specific user:**
```bash
find / -user <username> -type f 2>/dev/null
```

**Hash every binary in /tmp (for VirusTotal lookups):**
```bash
find /tmp -type f -executable -exec sha256sum {} \;
```

---

## What To Grow Into Next

These tools exist beyond the entry-level scope but are worth knowing about as you progress:

- **`tcpdump`** packet capture
- **`tshark`** terminal Wireshark; packet analysis
- **`nmap`** network scanning
- **`auditd`** Linux audit framework
- **`osquery`** SQL-style system queries (Facebook open source)
- **`Sysmon` (via Sysinternals)** Windows equivalent for endpoint visibility
- **`Wazuh` / `OSSEC`** open-source HIDS that automate much of the above

---

## Daily Practice Routine

This reference pairs with my morning SOC ritual. The workflow:

1. Run a focused subset of these commands every morning (different focus each day of the week).
2. Read every line of output carefully.
3. Compare mentally to what "normal" looked like yesterday.
4. Journal findings in plain analyst-voice English in `~/soc-journal/YYYY-MM-DD.md`.
5. Once per week, simulate an anomaly (add a fake user, open a fake port, drop a file in /tmp) and check whether the ritual catches it.

The skill isn't typing the command it's recognizing when output looks *off*. That recognition only develops through repetition.

---

## License

MIT feel free to fork, adapt, and use this for your own SOC training journey.

---

*Maintained as part of an ongoing SOC Tier 1 Analyst training journey. Last updated: May 2026.*
