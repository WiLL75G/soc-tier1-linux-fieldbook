# SOC Tier 1 Daily Investigation Commands

> The 80/20 command set. The commands an analyst actually grabs during shift, organized by investigation phase. If you only learn 25 commands, these are the ones.
 
**Companion to:** SOC Tier 1 Linux Command Reference + Filesystem Reference

---

## Why This Subset Exists

The full command reference covers 70+ commands. That's necessary breadth, but it's **not** what a working analyst uses on a Tuesday afternoon during an alert investigation. This document is the working subset the commands an analyst reaches for without thinking, multiple times per shift.

Master these and you can handle the majority of Tier 1 investigations.

---

## The Investigation Mindset

Real SOC investigations follow a repeatable pattern. Every alert, every incident, every "is this weird?" moment runs through roughly the same phases:

```
ORIENT  →  WHO  →  WHAT'S RUNNING  →  WHAT'S CONNECTED  →  WHAT HAPPENED  →  WHAT CHANGED  →  WILL IT COME BACK  →  DOCUMENT
```

Each phase has 3–5 go-to commands. Learn the commands in the order an analyst would actually run them.

---

## Phase 1 ORIENT (where am I, who am I?)

You just SSH'd into a system or pulled it up from an alert. First 15 seconds:

| Command | What It Does |
|---|---|
| `whoami` | Confirms your effective username. |
| `id` | Your UID, GID, and groups (are you in sudo/adm/docker?). |
| `hostname` | Confirms which system you're on. |
| `date` | Verifies system clock every timestamp depends on this. |
| `uptime` | How long since last reboot. Unexpected reboot? Investigate. |

**Why these:** every investigation needs these answers before you do anything else. Wrong clock = wrong timeline = wrong conclusions.

---

## Phase 2 WHO has been here? (authentication review)

The single highest-signal phase of any Linux investigation.

| Command | What It Does |
|---|---|
| `last -a` | Successful login history with source IPs. |
| `sudo lastb` | Failed login history (brute-force evidence). |
| `who` / `w` | Currently logged-in users and what they're doing. |
| `sudo grep "Failed password" /var/log/auth.log \| tail -20` | Recent failed SSH attempts. |
| `sudo grep "Accepted" /var/log/auth.log \| tail -20` | Recent successful SSH logins. |
| `sudo grep "sudo:" /var/log/auth.log \| tail -20` | Recent sudo activity. |

**Killer one-liner — top attacker IPs:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
```

**What you're hunting:** brute force (high failure count from one IP), successful logins from unexpected geographies, sudo escalation by accounts that shouldn't have it.

---

## Phase 3 WHAT'S RUNNING? (process inspection)

| Command | What It Does |
|---|---|
| `ps auxf` | All processes as a parent → child tree. |
| `ps aux --sort=-%cpu \| head -10` | Top 10 CPU consumers. |
| `top` (or `htop`) | Live process view. `q` to quit. |
| `pgrep <name>` | Find PIDs by process name. |
| `lsof -p <pid>` | All files a specific process has open. |
| `ls -la /proc/<pid>/exe` | Real path to a process's executable. |

**Killer one-liner processes from suspicious directories:**
```bash
ps aux | grep -E "/tmp/|/dev/shm/|/var/tmp/" | grep -v grep
```

**What you're hunting:** binaries running from `/tmp`, unfamiliar process names, high CPU from unknown processes, processes whose `/proc/<pid>/exe` points to deleted files (running malware whose file was removed).

---

## Phase 4 WHAT'S CONNECTED? (network state)

| Command | What It Does |
|---|---|
| `ss -tulnp` | Listening TCP/UDP ports with process names. THE attack surface command. |
| `ss -tnp state established` | Active TCP connections. |
| `lsof -i` | Open network connections with owning processes. |
| `ip addr` | Network interfaces and their IPs. |
| `dig <domain>` / `nslookup <domain>` | DNS lookup for investigating suspicious URLs. |
| `curl -I <url>` | Fetch HTTP headers only (safe URL probing). |

**`ss` flags to memorize:** `-t` TCP, `-u` UDP, `-l` listening, `-n` numeric, `-p` show process.

**What you're hunting:** listening ports you didn't open, connections to IPs you don't recognize, processes listening on high random ports (4444, 8888, 31337 are classic).

---

## Phase 5 WHAT HAPPENED? (log triage the biggest phase)

This is where Tier 1 analysts spend the most time. Logs tell the story; you just have to read them.

### Core Log Commands

| Command | What It Does |
|---|---|
| `tail -n 50 <file>` | Last 50 lines of a log. |
| `tail -f <file>` | Watch a log live. Ctrl+C to stop. |
| `less <file>` | Page through a long log. `/pattern` searches inside. |
| `grep "pattern" <file>` | Filter for matching lines. |
| `journalctl -u <service>` | All logs for one service. |
| `journalctl --since "1 hour ago"` | Time-bounded query. |
| `journalctl -p err` | Errors only. |
| `dmesg` | Kernel ring buffer (USB inserts, kernel errors). |

### Critical Log Files

| File | Contents |
|---|---|
| `/var/log/auth.log` | Authentication: logins, sudo, SSH |
| `/var/log/syslog` | General system events |
| `/var/log/dpkg.log` | Package installations |
| `~/.bash_history` | Shell command history per user |

### The grep Flags That Matter

| Flag | Effect |
|---|---|
| `-i` | Case-insensitive |
| `-v` | Invert (lines NOT matching) |
| `-c` | Count matches only |
| `-A 3` | 3 lines after match (Context-After) |
| `-B 3` | 3 lines before match (Context-Before) |
| `-r` | Recursive search through directories |

**Killer one-liner top targeted usernames in failed logins:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $9}' | sort | uniq -c | sort -rn | head -10
```

---

## Phase 6 WHAT CHANGED? (file system check)

| Command | What It Does |
|---|---|
| `ls -lah <dir>` | Permissions, owner, size, mtime. |
| `stat <file>` | Full file metadata, including all timestamps. |
| `find / -mmin -60 -type f 2>/dev/null` | Files modified in the last hour. |
| `find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null` | Recent files in attacker playgrounds. |
| `file <suspicious_file>` | Identify file type by content (not extension). |
| `strings <binary>` | Extract readable text from a binary — quick triage. |
| `sha256sum <file>` | Hash a file (for VirusTotal lookups). |

**What you're hunting:** files dropped in `/tmp`, `/dev/shm`, or web roots; modified config files; binaries renamed as `.txt`; recent changes to authentication files.

---

## Phase 7 WILL IT COME BACK? (persistence check)

After finding something suspicious, always ask: *"How would this attacker survive a reboot?"*

| Command | What It Does |
|---|---|
| `crontab -l` | Your user's scheduled jobs. |
| `sudo crontab -l` | Root's scheduled jobs. |
| `sudo ls -la /etc/cron.*` | System-wide cron jobs. |
| `systemctl list-timers --all` | Systemd timers (modern cron). |
| `systemctl list-unit-files --state=enabled` | Services configured to start at boot. |
| `cat ~/.bashrc /etc/profile` | Shell startup scripts. |
| `find / -name "authorized_keys" 2>/dev/null` | All SSH key files. |
| `getent passwd \| tail` | Recently added user accounts. |

**Killer one-liner every authorized_keys file plus its contents:**
```bash
sudo find / -name "authorized_keys" -exec ls -la {} \; -exec cat {} \; 2>/dev/null
```

---

## Phase 8 DOCUMENT (close the loop)

Every investigation ends with notes. Real Tier 1 analysts write tickets, comments, and journal entries constantly.

```bash
mkdir -p ~/soc-journal
nano ~/soc-journal/$(date +%Y-%m-%d).md
```

Write in plain analyst voice. Example entry:

> *Investigation 14:32 Alert on host webserver-01: SSH brute force from 185.220.x.x. Reviewed `/var/log/auth.log`: 487 failed attempts targeting `root` and `admin` between 14:00–14:25. No successful follow-up confirmed via `last -a`. Source IP geolocates to Tor exit node. Recommendation: block at perimeter firewall, no host-level action needed. Escalating to Tier 2 for IP block ticket.*

That's exactly the writing style hiring managers want to see in portfolios.

---

## The 80/20 List Master These 25 First

If you learn nothing else, master these. They cover the majority of daily SOC work.

### Search & Filter (the analyst's bread and butter)
```
grep      awk      sort      uniq -c      wc -l      find
```

### File & Log Reading
```
tail      head      less      cat      ls -lah      stat
```

### Process & Network
```
ps auxf      ss -tulnp      lsof      pgrep      top
```

### Authentication & Identity
```
last      lastb      who      id      whoami
```

### Persistence & Services
```
crontab -l      systemctl status      journalctl
```

### Triage & Hashing
```
file      strings      sha256sum
```

---

## The Killer One-Liners Worth Memorizing

These are the chained commands real analysts run from muscle memory.

**Top 10 IPs trying to brute force SSH:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $11}' | sort | uniq -c | sort -rn | head -10
```

**Top 10 targeted usernames:**
```bash
sudo grep "Failed password" /var/log/auth.log \
  | awk '{print $9}' | sort | uniq -c | sort -rn | head -10
```

**Recently modified files in attacker playgrounds:**
```bash
find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null
```

**All processes running from suspicious paths:**
```bash
ps aux | grep -E "/tmp/|/dev/shm/|/var/tmp/" | grep -v grep
```

**System-wide file changes in the last hour:**
```bash
sudo find / -mmin -60 -type f -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```

**Established connections + owning processes:**
```bash
sudo ss -tnp state established
```

**Recent sudo activity:**
```bash
sudo grep "sudo:" /var/log/auth.log | tail -20
```

**All listening ports (the attack surface):**
```bash
sudo ss -tulnp
```

**Hash everything executable in /tmp (for VirusTotal):**
```bash
find /tmp -type f -executable -exec sha256sum {} \;
```

**Recent successful root logins:**
```bash
last -a root | head -10
```

---

## How To Practice

1. **Lab setup:** Ubuntu Server VM in your home lab.
2. **Daily ritual:** run through Phases 1–7 in order every morning. Aim for under 20 minutes.
3. **Self-induced anomalies:** once a week, plant a change (new user, fake cron job, file in /tmp). Run the ritual cold. See if you catch it.
4. **Journal:** Phase 8 is non-negotiable. Write something every day in `~/soc-journal/`.
5. **Push the journal to GitHub.** 30 dated entries = real portfolio artifact.

The skill isn't typing the commands. The skill is recognizing when output looks *off*. That only develops through repetition with the same commands, day after day.

---

## License

MIT — fork, adapt, use freely for your own SOC training journey.

---

*Maintained as part of an ongoing SOC Tier 1 Analyst training journey. Last updated: May 2026.*
