# 🛡️ SOC Tier 1 Linux Fieldbook

> A complete beginner-to-intermediate working reference for SOC Tier 1 Analysts. Linux commands, filesystem paths, daily workflows, Splunk queries, Windows commands, MITRE ATT&CK mapping, and incident report templates everything you'd reach for in a real shift.

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-000000?style=for-the-badge&logo=splunk&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C7102E?style=for-the-badge&logo=target&logoColor=white)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](./LICENSE)
[![Made with Markdown](https://img.shields.io/badge/Made_with-Markdown-1f425f.svg?style=flat-square&logo=markdown)](https://www.markdownguide.org/)
[![Built In Public](https://img.shields.io/badge/Built_In-Public-success?style=flat-square)](https://x.com/WilliamCyberSec)

---

## 📚 What's Inside

### Core Linux References
| Document | Purpose | Use When |
|---|---|---|
| [**COMMANDS.md**](./COMMANDS.md) | Comprehensive Linux command reference — 70+ commands grouped by operational domain | Looking up syntax, flags, or example output |
| [**FILESYSTEM.md**](./FILESYSTEM.md) | Linux filesystem from a SOC analyst's perspective | Understanding *where* evidence lives and *what* to monitor |
| [**DAILY-COMMANDS.md**](./DAILY-COMMANDS.md) | The 80/20 daily-driver subset, organized by investigation workflow | Learning the *flow* of an investigation |

### Cross-Platform & Tooling
| Document | Purpose | Use When |
|---|---|---|
| [**WINDOWS-COMMANDS.md**](./WINDOWS-COMMANDS.md) | PowerShell + cmd companion for Windows investigations | Investigating Windows hosts; prepping for Windows-focused SOC interviews |
| [**SPLUNK-QUERIES.md**](./SPLUNK-QUERIES.md) | Splunk SPL queries for entry-level SOC work | Working in Splunk; analyzing logs from any platform |

### Framework & Documentation
| Document | Purpose | Use When |
|---|---|---|
| [**MITRE-MAPPING.md**](./MITRE-MAPPING.md) | Linux indicators mapped to MITRE ATT&CK techniques with detection commands | Writing reports; understanding *why* a behavior matters |
| [**INCIDENT-REPORT.md**](./INCIDENT-REPORT.md) | Incident report template + worked example | Documenting investigations; building portfolio artifacts |

---

## 🎯 Who This Is For

- **Complete beginners** entering cybersecurity from any background
- **Career-changers** preparing for Tier 1 SOC interviews
- **Students** working through SOC labs (TryHackMe, BTL1, LetsDefend, CyberDefenders, BOTS)
- **Self-learners** who want to know what blue-team analysts actually run during a shift

This isn't a Linux tutorial. It's the working command set used during real SOC investigations, distilled into a portable reference.

---

## 🗺️ Recommended Reading Order

### For Total Beginners
1. **[DAILY-COMMANDS.md](./DAILY-COMMANDS.md)** see how a real investigation flows
2. **[FILESYSTEM.md](./FILESYSTEM.md)** build the mental map of where things live
3. **[COMMANDS.md](./COMMANDS.md)** use as deep-dive lookup as you encounter new commands
4. **[MITRE-MAPPING.md](./MITRE-MAPPING.md)** connect what you see to attacker techniques
5. **[WINDOWS-COMMANDS.md](./WINDOWS-COMMANDS.md)** extend to the other major platform
6. **[SPLUNK-QUERIES.md](./SPLUNK-QUERIES.md)** bring it all together in a SIEM
7. **[INCIDENT-REPORT.md](./INCIDENT-REPORT.md)** document everything you've learned

### For Interview Prep
1. **[DAILY-COMMANDS.md](./DAILY-COMMANDS.md)** the workflow story you'll tell
2. **[MITRE-MAPPING.md](./MITRE-MAPPING.md)** the framework vocabulary
3. **[INCIDENT-REPORT.md](./INCIDENT-REPORT.md)** the artifact you'll point to

---

## 🧪 Practice Lab Setup

This reference is designed to be practiced in a home lab. The companion setup:

| Role | System | Purpose |
|---|---|---|
| Host | macOS | Hypervisor host + Splunk Free for SIEM analysis |
| Hypervisor | UTM (free, Apple Silicon native) | Manages the VMs below |
| Target | Ubuntu Server 22.04 LTS | The Linux system you investigate |
| Attacker | Kali Linux | Generates the attacks you detect |
| Endpoint | Windows 11 | Cross-platform investigation target |

**Free SIEM options:** Splunk Free, Wazuh, Security Onion.

---

## 🥋 The Daily Practice Ritual

A repeatable 20–30 minute morning routine that builds SOC instincts through repetition:

1. **Orient** `whoami`, `id`, `hostname`, `date`, `uptime`
2. **Authentication review** `last -a`, `sudo lastb`, auth.log triage
3. **Process inspection** `ps auxf`, `top`, `lsof`
4. **Network state** `ss -tulnp`, `ss -tnp state established`
5. **Log triage** `journalctl`, `tail`, `grep`
6. **File system check** `find`, `stat`, `file`
7. **Persistence audit** `crontab -l`, `systemctl list-timers`
8. **Document** journal findings in plain analyst voice

Full workflow with commands → [DAILY-COMMANDS.md](./DAILY-COMMANDS.md)

---

## 🧠 The Skill This Builds

The reference is the easy part. The skill is **pattern recognition** knowing what "normal" looks like on your system, so that "abnormal" jumps off the screen during a real alert.

That recognition only develops through repetition. Run the commands daily. Read every line of output. Journal your observations. The eyes train themselves.

---

## 🗂️ MITRE ATT&CK Coverage

This reference cross-references key MITRE ATT&CK techniques throughout:

- **Initial Access:** T1078, T1190
- **Execution:** T1059.004, T1059.006
- **Persistence:** T1053.003, T1098.004, T1136, T1543.002, T1546.004
- **Privilege Escalation:** T1548.001, T1068
- **Defense Evasion:** T1027, T1070, T1564.001
- **Credential Access:** T1003.008, T1110, T1552.004
- **Discovery:** T1018, T1057, T1083, T1087
- **Lateral Movement:** T1021.004
- **Collection:** T1005
- **Command and Control:** T1071.001, T1090
- **Exfiltration:** T1041, T1048
- **Impact:** T1486, T1490, T1496

Full mapping with detection commands → [MITRE-MAPPING.md](./MITRE-MAPPING.md)

---

## 🤝 Contributing

This is a living document. If you spot an error, have a sharper one-liner, or want to suggest an additional section, please open an issue or submit a PR.

---

## 👤 About The Author

**William** SOC Tier 1 Analyst (entry-level), building public learning artifacts as part of the path into blue-team work.


---

## 📄 License

[MIT](./LICENSE) fork, adapt, use freely for your own SOC training journey.

---

*Maintained as part of an ongoing SOC Tier 1 Analyst training journey. Built in public.*
