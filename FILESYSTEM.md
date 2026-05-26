# Linux Filesystem Reference for SOC Tier 1 Analysts

> A walkthrough of the Linux filesystem hierarchy from a SOC analyst's perspective. Where evidence lives, where attackers hide, and what to watch.
  
**Companion to:** SOC Tier 1 Linux Command Reference

---

## Why This Matters

Commands are only useful if you understand the paths they operate on. `cat /var/log/auth.log` means nothing if you don't know what `/var/log/` is, why authentication events live there, or what would look suspicious. The Linux filesystem follows the **Filesystem Hierarchy Standard (FHS)** a stable layout shared across nearly all Linux distros. Learn it once and every Linux system you ever touch makes sense.

This guide is built around what a SOC Tier 1 analyst actually cares about: **where evidence lives, where attackers like to hide, and which paths to baseline and monitor**.

---

## Table of Contents

1. [The Filesystem at a Glance](#1-the-filesystem-at-a-glance)
2. [`/etc` — System Configuration](#2-etc--system-configuration)
3. [`/var` — Logs & Variable Data](#3-var--logs--variable-data)
4. [`/home` — User Data](#4-home--user-data)
5. [`/root` — Root User's Home](#5-root--root-users-home)
6. [`/tmp`, `/var/tmp`, `/dev/shm` — Temporary Directories](#6-tmp-vartmp-devshm--temporary-directories)
7. [`/proc` — Live Process & Kernel Info](#7-proc--live-process--kernel-info)
8. [`/sys` — Kernel Objects](#8-sys--kernel-objects)
9. [`/usr` — Installed Software](#9-usr--installed-software)
10. [`/bin`, `/sbin`, `/lib` — Core Binaries & Libraries](#10-bin-sbin-lib--core-binaries--libraries)
11. [`/boot` — Bootloader & Kernel](#11-boot--bootloader--kernel)
12. [`/dev` — Device Files](#12-dev--device-files)
13. [`/run` — Runtime State](#13-run--runtime-state)
14. [`/opt`, `/srv`, `/mnt`, `/media`](#14-opt-srv-mnt-media)
15. [Critical Files Cheat Sheet](#15-critical-files-cheat-sheet)
16. [Hunting Patterns by Location](#16-hunting-patterns-by-location)

---

## 1. The Filesystem at a Glance

| Directory | One-Line Description | SOC Priority |
|---|---|---|
| `/` | The root of everything | — |
| `/etc` | System configuration files | 🔴 HIGH |
| `/var` | Logs, mail, spools, variable data | 🔴 HIGH |
| `/home` | User home directories | 🔴 HIGH |
| `/root` | Root user's home directory | 🔴 HIGH |
| `/tmp` | World-writable temporary files | 🔴 HIGH |
| `/var/tmp` | Temp files preserved across reboots | 🔴 HIGH |
| `/dev/shm` | Shared memory (world-writable) | 🔴 HIGH |
| `/proc` | Virtual: live process & kernel data | 🟡 MEDIUM |
| `/sys` | Virtual: kernel objects | 🟡 MEDIUM |
| `/usr` | Installed software & libraries | 🟡 MEDIUM |
| `/bin`, `/sbin`, `/lib` | Core system binaries (symlinks to /usr/*) | 🟡 MEDIUM |
| `/boot` | Kernel and bootloader files | 🟡 MEDIUM |
| `/dev` | Device files | 🟢 LOW |
| `/run` | Runtime state (sockets, PIDs) | 🟢 LOW |
| `/opt`, `/srv`, `/mnt`, `/media` | Optional software, services, mounts | 🟢 LOW |

**Rule of thumb:** if it's marked HIGH, baseline it, watch it, and know it cold.

---

## 2. `/etc` System Configuration

The brain of the system. Nearly every configuration file lives here. If you understand `/etc`, you understand the system.

### Key Files

| Path | What It Contains |
|---|---|
| `/etc/passwd` | All user accounts (one per line, colon-delimited). World-readable. |
| `/etc/shadow` | Password hashes for those users. Root-readable only. |
| `/etc/group` | Group definitions and memberships. |
| `/etc/sudoers` | Who can run sudo and what they can run. Use `visudo` to edit. |
| `/etc/sudoers.d/` | Drop-in sudo rules (often missed during audits). |
| `/etc/ssh/sshd_config` | SSH daemon configuration the primary attack vector's settings. |
| `/etc/ssh/ssh_config` | SSH client configuration. |
| `/etc/hostname` | The system's hostname. |
| `/etc/hosts` | Local hostname-to-IP mappings (overrides DNS). |
| `/etc/resolv.conf` | DNS server configuration. |
| `/etc/crontab` | Master system cron table. |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | System-wide scheduled scripts. |
| `/etc/cron.d/` | Drop-in cron jobs. |
| `/etc/systemd/system/` | Systemd unit files (services and timers). |
| `/etc/profile`, `/etc/bash.bashrc` | Shell startup files all users. |
| `/etc/fstab` | Filesystem mount table. |
| `/etc/apt/sources.list` | APT package repositories. |
| `/etc/apt/sources.list.d/` | Drop-in repository configs (third-party). |

### SOC Relevance

- **Persistence:** new entries in `/etc/sudoers.d/`, `/etc/cron.d/`, `/etc/systemd/system/`, or `/etc/profile.d/` are classic persistence implants (MITRE T1037, T1053, T1543.002).
- **Credential access:** `/etc/passwd` and `/etc/shadow` are top targets (T1003.008).
- **Defense evasion:** modified `/etc/hosts` redirects traffic (T1565.001).
- **Backdoors:** modified `/etc/ssh/sshd_config` (e.g., `PermitRootLogin yes`) opens doors.

### Red Flags

- New files in `/etc/sudoers.d/` you didn't create.
- Modified `/etc/passwd` mtime (check with `stat`).
- `PermitRootLogin yes` or `PasswordAuthentication yes` in `sshd_config` (if you'd previously hardened them).
- Strange entries in `/etc/hosts` (e.g., trusted domain pointing to attacker IP).
- New `.conf` files in `/etc/apt/sources.list.d/` (malicious repo).

---

## 3. `/var` Logs & Variable Data

The most operationally important directory for a SOC analyst. Logs, mail queues, spools, and other data that grows over time.

### Key Subdirectories

| Path | Contents |
|---|---|
| `/var/log/` | **All system logs.** The investigator's first stop. |
| `/var/log/auth.log` | Authentication events: logins, sudo, SSH (Debian/Ubuntu). |
| `/var/log/syslog` | General system messages. |
| `/var/log/kern.log` | Kernel messages. |
| `/var/log/dpkg.log` | Package installation history. |
| `/var/log/apt/history.log` | APT command history (who installed what, when). |
| `/var/log/wtmp` | Successful login history (binary; read with `last`). |
| `/var/log/btmp` | Failed login history (binary; read with `lastb`). |
| `/var/log/journal/` | Systemd binary journal (read with `journalctl`). |
| `/var/log/apache2/`, `/var/log/nginx/` | Web server logs. |
| `/var/spool/cron/crontabs/` | User crontab files. |
| `/var/mail/`, `/var/spool/mail/` | Local mail queues. |
| `/var/tmp/` | Temp files preserved across reboots. |
| `/var/lib/` | Per-service application data (databases, package state). |
| `/var/cache/` | Cached data for applications. |
| `/var/www/` | Default web root for Apache/nginx. |

### SOC Relevance

- **Primary evidence source.** Almost every investigation starts with `tail`, `grep`, or `journalctl` against `/var/log/`.
- **Log tampering detection.** Shrinking log files, truncated logs, or missing entries = MITRE T1070.002 (Clear Linux Logs).
- **Disk exhaustion attacks.** Filling `/var/log/` can cause services to crash or stop logging.
- **Web shell location.** `/var/www/` is the classic place to drop PHP web shells.

### Red Flags

- `/var/log/auth.log` suddenly truncated or much smaller than yesterday.
- Files named `*.log.bak.*` or `*.log.old` you didn't create (attacker preserving logs while cleaning).
- New files in `/var/www/` that aren't part of legitimate web content.
- New entries in `/var/spool/cron/crontabs/` for users who shouldn't have cron jobs.
- `/var/log/apt/history.log` showing package installs you didn't authorize.

---

## 4. `/home` User Data

Every regular user gets a directory here, typically `/home/<username>`.

### Key Files (per user)

| Path | Contents |
|---|---|
| `~/.bash_history` | Shell command history. |
| `~/.bashrc`, `~/.profile`, `~/.bash_profile` | Shell startup scripts (persistence target). |
| `~/.ssh/` | SSH keys and config (huge persistence target). |
| `~/.ssh/authorized_keys` | Public keys allowed to log in as this user **T1098.004**. |
| `~/.ssh/known_hosts` | Hosts this user has connected to. |
| `~/.ssh/config` | Per-user SSH client config. |
| `~/.config/`, `~/.local/` | Application configs and data. |
| `~/.local/bin/` | User-installed binaries (often missed by sysadmins). |

### SOC Relevance

- **Persistence via startup files.** Malicious code added to `.bashrc` runs every time the user opens a shell (T1546.004).
- **SSH key persistence.** A rogue public key in `authorized_keys` = passwordless backdoor forever.
- **User-installed tools.** `~/.local/bin/` is a common stash for attacker-installed binaries because it bypasses standard PATH inspection if you only check system paths.
- **Forensic timeline.** `~/.bash_history` is your first read during user activity investigation.

### Red Flags

- Empty `~/.bash_history` on a long-active account (T1070.003).
- Unknown public keys in any `authorized_keys` file.
- Recently modified `~/.bashrc` with appended lines you don't recognize.
- Executable files in `~/.local/bin/` you didn't install.
- Hidden directories in home (`ls -la ~`) you don't recognize.

---

## 5. `/root` Root User's Home

Same as `/home/<user>` but for the root user. Access requires sudo or root.

Same red flags apply, but **doubly important** because root compromise means total system compromise. Always check:
- `/root/.bash_history`
- `/root/.ssh/authorized_keys`
- `/root/.bashrc`

---

## 6. `/tmp`, `/var/tmp`, `/dev/shm` Temporary Directories

The attacker's playground. All three are **world-writable**, meaning any process or user can drop files there. Differences:

| Directory | Cleared on Reboot? | Storage |
|---|---|---|
| `/tmp` | Yes | Disk |
| `/var/tmp` | No (persists) | Disk |
| `/dev/shm` | Yes | RAM (tmpfs) faster, leaves less forensic trace |

### SOC Relevance

These three directories are the **#1 location for malware staging** on Linux:
- Dropped payloads (T1105 Ingress Tool Transfer)
- Web shell dropping points
- Cryptominer binaries
- Persistence scripts before they're moved elsewhere

`/dev/shm` is particularly dangerous because it's in RAM files there leave fewer disk forensics artifacts.

### Red Flags

- **Any** executable file in these directories. Normal use rarely produces ELF binaries here.
- Hidden files (`.something`) — `ls -la /tmp`.
- Files owned by `www-data`, `apache`, or `nginx` (web-shell artifacts).
- Recently created scripts (`.sh`, `.py`, `.pl`).
- Processes whose executable path is `/tmp/*`, `/var/tmp/*`, or `/dev/shm/*` (check with `ls -la /proc/<pid>/exe`).

### Quick Hunt

```bash
find /tmp /var/tmp /dev/shm -type f -mtime -1 -ls 2>/dev/null
ls -lah /tmp /var/tmp /dev/shm
```

---

## 7. `/proc` — Live Process & Kernel Info

A **virtual filesystem** files here don't exist on disk. The kernel creates them on the fly. Every running process gets a `/proc/<pid>/` directory.

### Key Per-Process Paths

| Path | Contents |
|---|---|
| `/proc/<pid>/cmdline` | The exact command line used to start the process. |
| `/proc/<pid>/exe` | Symlink to the actual executable on disk. |
| `/proc/<pid>/cwd` | Symlink to the process's current working directory. |
| `/proc/<pid>/environ` | Environment variables the process was started with. |
| `/proc/<pid>/status` | Human-readable status including UID/GID. |
| `/proc/<pid>/fd/` | All file descriptors the process has open. |
| `/proc/<pid>/maps` | Memory map (loaded libraries, executable segments). |

### Global Files

| Path | Contents |
|---|---|
| `/proc/cpuinfo` | CPU details. |
| `/proc/meminfo` | Memory usage. |
| `/proc/mounts` | Currently mounted filesystems. |
| `/proc/net/tcp`, `/proc/net/udp` | Raw socket data. |
| `/proc/sys/kernel/` | Kernel runtime parameters. |

### SOC Relevance

`/proc` is **live forensics gold**:
- Find a process's real executable even if the attacker deleted it: `ls -la /proc/<pid>/exe`
- Recover deleted files still held by a running process via `/proc/<pid>/fd/`
- See what arguments a process was launched with (`/proc/<pid>/cmdline`)

### Red Flags

- A process whose `/proc/<pid>/exe` points to `/tmp/`, `/dev/shm/`, or shows `(deleted)` running malware whose file has been removed.

---

## 8. `/sys` Kernel Objects

Another virtual filesystem, exposing kernel internals (devices, drivers, kernel parameters). You'll touch this rarely as a Tier 1, but know it exists. Used heavily by udev and hardware-aware tools.

---

## 9. `/usr` Installed Software

The bulk of the operating system. Most software, libraries, and documentation lives here.

| Subdirectory | Contents |
|---|---|
| `/usr/bin/` | User binaries (most commands you run). |
| `/usr/sbin/` | System administration binaries. |
| `/usr/lib/`, `/usr/lib64/` | Shared libraries. |
| `/usr/local/` | Locally installed software (not package-managed). |
| `/usr/local/bin/` | Locally compiled binaries. |
| `/usr/share/` | Architecture-independent data (man pages, docs). |
| `/usr/src/` | Kernel source headers. |

### SOC Relevance

- **`/usr/local/bin/`** is a sysadmin's manual install location — but also where attackers drop custom binaries to blend in.
- Modified system binaries (e.g., a trojanized `/usr/bin/ls`) are a classic rootkit technique (T1554 Compromise Host Software Binary).
- Hash baselines of `/usr/bin/` and `/usr/sbin/` catch this.

### Red Flags

- A `/usr/bin/` binary whose hash differs from the package manager's expected hash.
- New binaries in `/usr/local/bin/` you didn't install.
- Files in `/usr/bin/` owned by a non-root user.

---

## 10. `/bin`, `/sbin`, `/lib` Core Binaries & Libraries

On modern Linux (Ubuntu 22.04+, RHEL 9+), these are **symlinks** into `/usr/`:
- `/bin → /usr/bin`
- `/sbin → /usr/sbin`
- `/lib → /usr/lib`

They contain the essential binaries needed to boot and rescue the system. Treat them with the same suspicion as `/usr/bin/`.

---

## 11. `/boot` Bootloader & Kernel

| Path | Contents |
|---|---|
| `/boot/vmlinuz-*` | The Linux kernel. |
| `/boot/initrd.img-*` or `/boot/initramfs-*` | Initial RAM disk. |
| `/boot/grub/` | GRUB bootloader config. |

### SOC Relevance

- **Bootkit persistence** (T1542.003) lives here. Rare in routine SOC work but high impact.
- Unusual files in `/boot/` warrant immediate investigation.

---

## 12. `/dev` Device Files

In Linux, everything is a file including hardware. `/dev` contains device files:

| Path | Represents |
|---|---|
| `/dev/sda`, `/dev/nvme0n1` | Disk drives. |
| `/dev/tty*` | Terminal devices. |
| `/dev/null` | The bit bucket (discards anything written to it). |
| `/dev/zero` | Stream of zeros. |
| `/dev/random`, `/dev/urandom` | Randomness sources. |
| `/dev/shm/` | Shared memory (the world-writable one see Section 6). |

### Red Flags

- Files in `/dev/` that aren't device files. Attackers occasionally hide payloads here knowing analysts skim past.

---

## 13. `/run` — Runtime State

Replaces older `/var/run/` on modern systems. Contains:
- PID files for running services
- Unix domain sockets
- Lock files

Cleared at every boot. Rarely a target, but useful for understanding service state.

---

## 14. `/opt`, `/srv`, `/mnt`, `/media`

| Directory | Purpose |
|---|---|
| `/opt` | Optional, self-contained third-party software (often vendor-supplied). |
| `/srv` | Data served by the system (web roots, FTP roots on some distros). |
| `/mnt` | Manual mount points (sysadmin scratch space). |
| `/media` | Auto-mounted removable media (USB drives, CDs). |

### SOC Relevance

- `/opt/<vendor>/` packages are often missed during audits check them too.
- `/media/` shows what removable storage has been attached (USB-borne malware vector).

---

## 15. Critical Files Cheat Sheet

Memorize these. They control authentication, trust, persistence, and access.

| File | Purpose | Sensitivity |
|---|---|---|
| `/etc/passwd` | User accounts (no passwords) | 🟡 |
| `/etc/shadow` | Password hashes | 🔴 |
| `/etc/sudoers` | Sudo permissions | 🔴 |
| `/etc/ssh/sshd_config` | SSH daemon config | 🔴 |
| `/etc/crontab` | System cron schedule | 🟡 |
| `/etc/hosts` | Local hostname overrides | 🟡 |
| `/etc/resolv.conf` | DNS resolution | 🟡 |
| `/etc/fstab` | Mount table | 🟡 |
| `/etc/apt/sources.list` | Package sources | 🟡 |
| `~/.ssh/authorized_keys` | SSH login keys | 🔴 |
| `~/.bashrc` | Shell startup | 🟡 |
| `~/.bash_history` | Shell history | 🟡 |
| `/var/log/auth.log` | Authentication log | 🔴 |
| `/var/log/syslog` | General system log | 🟡 |

Hash baseline the 🔴 files. Re-hash periodically. Any mismatch = investigate.

```bash
sudo sha256sum /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab > ~/soc-baseline/critical_hashes.txt
```

---

## 16. Hunting Patterns by Location

Quick reference for "if I'm hunting X, where do I look?"

| Hunt Target | Where to Look |
|---|---|
| New user accounts | `/etc/passwd`, `/etc/shadow`, `/etc/group` |
| SSH key persistence | `~/.ssh/authorized_keys` for every user, `/root/.ssh/authorized_keys` |
| Cron persistence | `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/crontabs/` |
| Systemd persistence | `/etc/systemd/system/`, `~/.config/systemd/user/` |
| Shell startup persistence | `~/.bashrc`, `~/.profile`, `/etc/profile`, `/etc/profile.d/` |
| Dropped payloads | `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/var/www/` |
| Web shells | `/var/www/`, `/srv/`, anything web-server-readable |
| Modified system binaries | `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/` |
| User activity reconstruction | `~/.bash_history`, `/var/log/auth.log`, `last`/`lastb` output |
| Package install audit trail | `/var/log/dpkg.log`, `/var/log/apt/history.log` |
| Recently active processes | `/proc/<pid>/` for each suspicious PID |
| Recently modified files | `find / -mtime -1 -type f 2>/dev/null` |
| Hidden files anywhere | `find / -name ".*" -type f 2>/dev/null` |
| Sudo abuse | `/var/log/auth.log` (grep "sudo:") |

---

## Daily Practice Tip

Once a week, pick **one directory** from this guide. Spend 10 minutes inside it: `ls`, `cat` a few files, run `stat` on the critical ones, read the contents. Don't move on until you can answer: *"If something here changed without my knowledge tomorrow, would I spot it?"*

That question is the entire SOC mindset, condensed.

---

## License

MIT fork, adapt, use freely for your own SOC training journey.

---

*Maintained as part of an ongoing SOC Tier 1 Analyst training journey. Last updated: May 2026.*
