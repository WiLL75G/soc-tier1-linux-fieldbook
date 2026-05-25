# 🛡️ SOC Tier 1 Linux Fieldbook

> A working reference for SOC Tier 1 Analysts who investigate, hunt, and defend on Linux systems.  
> Three companion documents: **commands**, **filesystem**, and **daily investigation workflow**.

---

## 📚 What's Inside

| Document | Purpose | Use When |
|---|---|---|
| [**COMMANDS.md**](./COMMANDS.md) | Comprehensive command reference. 70+ commands grouped by operational domain (system, network, processes, logs, persistence, etc.) | You need to look up syntax, flags, or example output. |
| [**FILESYSTEM.md**](./FILESYSTEM.md) | Linux filesystem walkthrough from a SOC analyst's perspective. Where evidence lives, where attackers hide. | You need to understand *why* a path matters and what to monitor there. |
| [**DAILY-COMMANDS.md**](./DAILY-COMMANDS.md) | The 80/20 daily-driver subset, organized by investigation workflow. | You're learning the *flow* of an investigation, not just the commands. |

---

## 🎯 Who This Is For

- **Entry-level SOC analysts** building Linux investigation skills
- **Career-changers** preparing for Tier 1 SOC interviews
- **Students** working through SOC labs (TryHackMe, BTL1, LetsDefend, CyberDefenders)
- **Self-learners** who want to know what blue-team analysts actually run during a shift

This isn't a Linux tutorial. It's the working command set used during real SOC investigations, distilled into a portable reference.

---

## 🗺️ Recommended Reading Order

1. **Start here:** [DAILY-COMMANDS.md](./DAILY-COMMANDS.md) — to see how investigations actually flow in practice.
2. **Build the mental map:** [FILESYSTEM.md](./FILESYSTEM.md) — to understand where evidence lives on Linux.
3. **Use as lookup:** [COMMANDS.md](./COMMANDS.md) — to find any command's syntax, flags, or SOC relevance.

---

## 🧪 Practice Lab Setup

This reference is designed to be practiced in a home lab. My setup:

| Role | System | Purpose |
|---|---|---|
| Host | macOS (any modern Mac) | Hypervisor host + Splunk Free for SIEM analysis |
| Hypervisor | UTM (free, Apple Silicon native) | Manages three VMs below |
| Target | Ubuntu Server 22.04 LTS | The system you investigate |
| Attacker | Kali Linux | Generates the attacks you detect |
| Endpoint | Windows 11 | Additional target for cross-platform practice |

**Free SIEM options:** Splunk Free, Wazuh, Security Onion.

---

## 🥋 The Daily Practice Ritual

A repeatable 20–30 minute morning routine that builds SOC instincts through repetition:

1. **Orient** — `whoami`, `id`, `hostname`, `date`, `uptime`
2. **Authentication review** — `last -a`, `sudo lastb`, `auth.log` greps
3. **Process inspection** — `ps auxf`, `top`, `lsof`
4. **Network state** — `ss -tulnp`, `ss -tnp state established`
5. **Log triage** — `journalctl`, `tail`, `grep`
6. **File system check** — `find`, `stat`, `file`
7. **Persistence audit** — `crontab -l`, `systemctl list-timers`
8. **Document** — journal findings in plain analyst voice

Full workflow with commands → [DAILY-COMMANDS.md](./DAILY-COMMANDS.md)

---

## 🧠 The Skill This Builds

The reference is the easy part. The skill is **pattern recognition** — knowing what "normal" looks like on your system, so that "abnormal" jumps off the screen during a real alert.

That recognition only develops through repetition. Run the commands daily. Read every line of output. Journal your observations. The eyes train themselves.

---

## 🗂️ MITRE ATT&CK Coverage

This reference cross-references the following MITRE ATT&CK techniques where relevant:

- **T1003.008** — OS Credential Dumping: /etc/passwd & /etc/shadow
- **T1037** — Boot or Logon Initialization Scripts
- **T1053** — Scheduled Task/Job (cron, systemd timers)
- **T1070** — Indicator Removal (log clearing, history clearing)
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1105** — Ingress Tool Transfer (/tmp staging)
- **T1136** — Create Account
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1554** — Compromise Host Software Binary
- **T1565.001** — Stored Data Manipulation

---

## 🤝 Contributing

This is a living document. If you spot an error, have a sharper one-liner, or want to suggest an additional section, please open an issue or submit a PR.

---

## 👤 About The Author

**James Williams** — SOC Tier 1 Analyst (entry-level), building public learning artifacts as part of the path into blue-team work.

**Certifications & training:**
- ISC2 Certified in Cybersecurity (CC)
- Healthcare IT Support Specialization (Johns Hopkins)
- Tata Cybersecurity Analyst Job Simulation (Forage)
- TryHackMe Pre Security

**Connect:**
- 🐦 X / Twitter: [@WilliamCyberSec](https://x.com/WilliamCyberSec)
- 💻 GitHub: [@willcyber756](https://github.com/willcyber756)

---

## 📄 License

[MIT](./LICENSE) — fork, adapt, use freely for your own SOC training journey.

---

*Maintained as part of an ongoing SOC Tier 1 Analyst training journey. Built in public.*
