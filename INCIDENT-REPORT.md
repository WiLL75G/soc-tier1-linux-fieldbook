# SOC Incident Report Template + Worked Example

> The structure SOC Tier 1 analysts use to document investigations. Includes a complete worked example based on a real home-lab scenario (SSH brute force detection).

**Companion to:** [COMMANDS.md](./COMMANDS.md), [MITRE-MAPPING.md](./MITRE-MAPPING.md)

---

## Why Incident Reports Matter

A SOC analyst's job isn't done when they spot the threat. It's done when they *document* it in a way that any reader another analyst, a manager, an auditor, an executive can understand what happened, what was done about it, and what's next. The incident report is the **deliverable**.

In an interview, "Tell me about a time you investigated an incident" is the most-asked question. A polished report is the artifact you point to. This template gives you the structure to write one that sounds professional from day one.

---

## Table of Contents

1. [The Template Structure](#1-the-template-structure)
2. [Section-by-Section Guidance](#2-section-by-section-guidance)
3. [IOC Formatting Standards](#3-ioc-formatting-standards)
4. [MITRE ATT&CK Table Format](#4-mitre-attck-table-format)
5. [Worked Example: SSH Brute Force Detection](#5-worked-example-ssh-brute-force-detection)
6. [Writing Tips for Beginners](#6-writing-tips-for-beginners)

---

## 1. The Template Structure

Every incident report in this fieldbook follows this exact structure. Stick to it for consistency across your portfolio.

```
1. Title
2. Incident Summary
3. Executive Summary
4. Affected System
5. Investigation Methodology
   - Numbered steps
   - Screenshots
   - SOC Observations (subsection per step)
6. Indicators of Compromise (IOCs)
7. MITRE ATT&CK Mapping (table)
8. SOC Analyst Findings
9. SOC Analyst Response
10. Analyst Insight (1 paragraph)
11. Learning Outcome (bullets)
12. Repository Structure (tree)
13. Conclusion
```

---

## 2. Section-by-Section Guidance

### 1. Title

Format: `Day [N]: [Short Descriptive Title] SOC Tier 1 Investigation`

Example: `Day 05: SSH Brute Force Detection on Ubuntu Server — SOC Tier 1 Investigation`

### 2. Incident Summary

One paragraph, 3–5 sentences. The 30-second version of the story. *What happened, when, where, and how it was discovered.*

### 3. Executive Summary

A non-technical version of the incident for a manager or executive reader. Avoid jargon. Focus on business impact and resolution.

### 4. Affected System

A clean table of the system's identifying info:

| Field | Value |
|---|---|
| Hostname | ubuntu-server |
| IP Address | 192.168.64.10 |
| OS | Ubuntu Server 22.04 LTS |
| Role | Lab target server |
| Time Zone | UTC |

### 5. Investigation Methodology

The meat. Numbered steps in chronological order. For each step:

- **What you ran** (the command)
- **What you found** (the output, ideally with a screenshot)
- **SOC Observations** subsection: your interpretation

Example structure:

```
Step 1: Confirmed system identity and time sync
- Command: hostnamectl
- Output: [screenshot]
- SOC Observations: Time sync via NTP confirmed; timestamps in subsequent log analysis are trustworthy.

Step 2: Reviewed authentication logs
- Command: sudo grep "Failed password" /var/log/auth.log | tail -20
- Output: [screenshot]
- SOC Observations: 487 failed login attempts identified from source IP 192.168.64.20 (Kali attacker VM) targeting accounts root, admin, and ubuntu.
```

### 6. Indicators of Compromise (IOCs)

A clean table of forensic artifacts another analyst could pivot on:

| Indicator | Type | Value |
|---|---|---|
| Source IP | Network | 192.168.64.20 |
| Targeted Username | Account | root, admin, ubuntu |
| Failed Login Count | Behavioral | 487 events in 4 minutes |
| Tool Signature | TTP | Hydra (default rate pattern) |

### 7. MITRE ATT&CK Mapping (table)

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Password Guessing | T1110.001 | 487 failed SSH attempts from single source |
| Initial Access | Valid Accounts | T1078 | Attempted valid usernames (root, admin) |

### 8. SOC Analyst Findings

A bulleted list of factual conclusions drawn from the evidence. No speculation — only what the data supports.

### 9. SOC Analyst Response

What you did (or would do in a real environment). Examples:

- Blocked source IP at perimeter firewall
- Enforced SSH key-based authentication
- Disabled root SSH login (`PermitRootLogin no`)
- Implemented fail2ban with 10-attempt threshold
- Documented incident and closed ticket as resolved

### 10. Analyst Insight (1 paragraph)

Your personal reflection. What did this teach you about attacker behavior? What pattern do you recognize now that you wouldn't have before?

### 11. Learning Outcome (bullets)

Specific skills or concepts learned. Examples:

- Practiced log triage with grep/awk/sort/uniq one-liners
- Built familiarity with auth.log structure
- Mapped real-world brute-force activity to MITRE T1110.001

### 12. Repository Structure (tree)

```
day-05-ssh-brute-force/
├── README.md
├── screenshots/
│   ├── 01-hostnamectl.png
│   ├── 02-auth-log-failures.png
│   └── 03-top-attacker-ips.png
├── iocs/
│   └── indicators.csv
└── splunk/
    └── detection-queries.spl
```

### 13. Conclusion

Two to three sentences. The wrap-up. *What was learned, what was demonstrated, and what comes next.*

---

## 3. IOC Formatting Standards

Use these standard types in your IOC tables:

| Type | Examples |
|---|---|
| **Network** | IPv4, IPv6, FQDN, URL, Port, ASN |
| **File** | SHA-256, MD5, file path, filename |
| **Account** | Username, UID, email |
| **Behavioral** | Login attempt rate, request pattern |
| **TTP** | Tool signature, command pattern |
| **Registry** (Windows) | Key path, value name |

Stick to this taxonomy across all your reports. Recruiters who skim three reports will notice the consistency.

---

## 4. MITRE ATT&CK Table Format

Always include:

| Tactic | Technique | ID | Evidence |
|---|---|---|---|

- **Tactic:** the high-level "why" (Initial Access, Persistence, etc.)
- **Technique:** the specific method (use sub-technique if applicable)
- **ID:** the MITRE ID (T1234 or T1234.001 format)
- **Evidence:** one line citing the log or artifact that proves it

Reference [MITRE-MAPPING.md](./MITRE-MAPPING.md) in this repo for the technique catalog.

---

## 5. Worked Example: SSH Brute Force Detection

Below is a complete, anonymized example you can adapt for your own lab work.

---

### Day 05: SSH Brute Force Detection on Ubuntu Server — SOC Tier 1 Investigation

#### Incident Summary

On 24 November 2025, repeated failed SSH login attempts were detected on the lab Ubuntu Server VM. Investigation through `/var/log/auth.log` and Splunk SPL queries identified 487 failed authentication events from a single source IP over a 4-minute window, consistent with an automated brute-force attack. The source was confirmed as the lab Kali Linux VM running Hydra.

#### Executive Summary

An automated password-guessing attack was detected against the lab server. The attack was identified within minutes through routine log review and matched a known attacker behavior pattern (brute force). No successful compromise occurred. The source was blocked and authentication hardening was applied.

#### Affected System

| Field | Value |
|---|---|
| Hostname | ubuntu-lab-target |
| IP Address | 192.168.64.10 |
| OS | Ubuntu Server 22.04 LTS |
| Role | Lab target server (SSH-enabled) |
| Time Zone | UTC |

#### Investigation Methodology

**Step 1 — Confirmed system identity and time sync**
- Command: `hostnamectl && timedatectl`
- Output: hostname `ubuntu-lab-target`, NTP sync active
- *SOC Observations:* Time sync confirmed; subsequent log timestamps are reliable.

**Step 2 — Reviewed recent authentication events**
- Command: `sudo tail -n 50 /var/log/auth.log`
- Output: large volume of `Failed password` entries
- *SOC Observations:* Visual scan confirms high-frequency authentication failures requiring deeper analysis.

**Step 3 — Quantified failed login attempts**
- Command:
  ```bash
  sudo grep "Failed password" /var/log/auth.log | wc -l
  ```
- Output: `487`
- *SOC Observations:* 487 failed authentications in the current log abnormal for a lab system that should have near-zero login activity.

**Step 4 — Identified top source IPs**
- Command:
  ```bash
  sudo grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -5
  ```
- Output: `487 192.168.64.20`
- *SOC Observations:* All failures originate from a single internal IP (192.168.64.20 = Kali attacker VM). Single-source, high-volume pattern is consistent with automated brute force.

**Step 5 — Identified targeted usernames**
- Command:
  ```bash
  sudo grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -rn
  ```
- Output:
  ```
  201 root
  142 admin
  98 ubuntu
  46 user
  ```
- *SOC Observations:* Top targets are common default usernames — confirms automated tool with a default username list.

**Step 6 — Confirmed no successful logins followed**
- Command:
  ```bash
  sudo grep "Accepted" /var/log/auth.log | tail -20
  ```
- Output: no entries from 192.168.64.20
- *SOC Observations:* No successful compromise. The brute force failed.

#### Indicators of Compromise (IOCs)

| Indicator | Type | Value |
|---|---|---|
| Source IP | Network | 192.168.64.20 |
| Targeted Usernames | Account | root, admin, ubuntu, user |
| Event Volume | Behavioral | 487 failures in 4 minutes |
| Tool Signature | TTP | Hydra default rate pattern |
| Time Window | Behavioral | 14:23–14:27 UTC, 24 Nov 2025 |

#### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 | 487 failed SSH attempts from single source |
| Initial Access | Valid Accounts | T1078 | Attempted common usernames (root, admin) |

#### SOC Analyst Findings

- Automated brute-force attack confirmed against SSH service.
- Single source IP (192.168.64.20) responsible for 100% of failure events.
- Attack targeted common default usernames no evidence of targeted reconnaissance.
- No successful authentication followed the attack window.
- No secondary indicators of compromise (no new accounts, no new processes from /tmp, no modified `authorized_keys`).

#### SOC Analyst Response

1. Blocked source IP `192.168.64.20` at host firewall (`sudo ufw deny from 192.168.64.20`).
2. Disabled root SSH login by setting `PermitRootLogin no` in `/etc/ssh/sshd_config`.
3. Enforced SSH key-based authentication only (`PasswordAuthentication no`).
4. Installed `fail2ban` with a 5-attempt threshold and 1-hour ban window.
5. Created Splunk alert for >10 failed logins from a single source IP within 5 minutes.

#### Analyst Insight

This investigation reinforced the value of high-signal one-liners for log triage. A four-command pipeline (`grep | awk | sort | uniq -c | sort -rn | head`) reduced 487 events into a single actionable insight one source IP, four targeted usernames in under 60 seconds. The exercise also highlighted that Tier 1 work is rarely about complex tooling; it's about pattern recognition built through repetition.

#### Learning Outcome

- Practiced auth.log triage with grep/awk/sort/uniq one-liners
- Mapped real-world brute-force activity to MITRE T1110.001
- Configured SSH hardening (PermitRootLogin, PasswordAuthentication)
- Deployed fail2ban as a host-based countermeasure
- Built a Splunk SPL alert for brute force detection

#### Repository Structure

```
day-05-ssh-brute-force/
├── README.md
├── screenshots/
│   ├── 01-hostnamectl.png
│   ├── 02-auth-log-failures.png
│   ├── 03-top-attacker-ips.png
│   └── 04-targeted-usernames.png
├── iocs/
│   └── indicators.csv
├── splunk/
│   └── brute-force-detection.spl
└── hardening/
    ├── sshd_config.diff
    └── fail2ban-jail.local
```

#### Conclusion

This investigation simulated and detected a successful brute-force attack pattern using only Linux native tooling and Splunk. The work demonstrated end-to-end Tier 1 workflow: detection, triage, attribution, MITRE mapping, response, and reporting. Future lab work will extend to credential-stuffing variants and key-based authentication bypass attempts.

---

## 6. Writing Tips for Beginners

1. **Write in past tense, third person.** *"487 failed attempts were identified"* not *"I found 487 failed attempts."* It sounds professional and depersonalizes the work.
2. **Lead with the punchline.** The Incident Summary should answer *"what happened?"* in one read. Save the methodology for the methodology section.
3. **Show, don't tell.** Always include the actual command and the actual output. *"I checked the logs"* is weak. *"`sudo grep \"Failed password\" /var/log/auth.log | wc -l` returned 487"* is strong.
4. **Use MITRE IDs in every report.** Even if the technique feels obvious. The IDs are the analyst's vocabulary.
5. **Keep the Analyst Insight personal but professional.** This is the only section where you reflect make it count without sounding casual.
6. **Don't speculate.** If the data doesn't support a conclusion, leave it out or mark it as *"hypothesis, pending further evidence."*
7. **Always end with "what's next."** A good report points forward to the next investigation, the next hardening step, or the next skill to build.

---

## 🎯 How To Use This Template

For every home-lab investigation you complete:

1. Copy this template structure into a new folder (e.g., `day-NN-topic/README.md`).
2. Fill out each section as you investigate.
3. Capture screenshots as you go never rely on remembering later.
4. Commit to your portfolio repo when complete.
5. Reference the report in your résumé under Projects.

After ten of these, your GitHub will tell a story no résumé bullet point ever could: that you do the work, document it, and think like an analyst.

---

## 📄 License

[MIT](./LICENSE) fork, adapt, use freely.
