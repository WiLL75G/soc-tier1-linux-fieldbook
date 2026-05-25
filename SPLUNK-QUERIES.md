# 🔎 Splunk SPL Queries for SOC Tier 1 Analysts

> The Splunk Search Processing Language (SPL) queries an entry-level SOC analyst actually runs during a shift. Built around the home-lab setup: Splunk Free on macOS host, ingesting logs from Ubuntu Server, Kali, and Windows 11 VMs.

**Author:** James Williams ([@WilliamCyberSec](https://x.com/WilliamCyberSec))  
**Companion to:** [COMMANDS.md](./COMMANDS.md), [FILESYSTEM.md](./FILESYSTEM.md), [DAILY-COMMANDS.md](./DAILY-COMMANDS.md)

---

## 📖 What Is SPL?

**Search Processing Language** is Splunk's query language. Every Splunk search is a pipeline — you start broad, filter, then transform the data into useful output. The basic shape:

```spl
<search terms> | <filter> | <transform> | <visualize>
```

Real example:

```spl
index=linux sourcetype=syslog "Failed password"
| stats count by src_ip
| sort - count
| head 10
```

This reads as: *"In the Linux index, find lines containing 'Failed password', count them grouped by source IP, sort highest first, show top 10."* That's a brute-force detection in five lines.

---

## 📚 Table of Contents

1. [SPL Anatomy: The 5 Building Blocks](#1-spl-anatomy-the-5-building-blocks)
2. [Search Fundamentals](#2-search-fundamentals)
3. [Authentication & Login Queries](#3-authentication--login-queries)
4. [Process & Execution Queries](#4-process--execution-queries)
5. [Network Queries](#5-network-queries)
6. [File & Persistence Queries](#6-file--persistence-queries)
7. [Stats, Charts & Aggregation](#7-stats-charts--aggregation)
8. [Top 10 Essential Queries to Memorize](#8-top-10-essential-queries-to-memorize)
9. [The Tier 1 Daily SPL Workflow](#9-the-tier-1-daily-spl-workflow)

---

## 1. SPL Anatomy: The 5 Building Blocks

Every SPL query is built from these five components, in order. Learn this and SPL stops feeling intimidating.

| Component | Purpose | Example |
|---|---|---|
| **Search terms** | What logs to look at | `index=linux sourcetype=syslog` |
| **Filter** | Narrow down to what matters | `"Failed password"` |
| **Time** | Bound the time window | `earliest=-24h latest=now` |
| **Transform** | Aggregate or count | `\| stats count by src_ip` |
| **Visualize/Format** | Make it readable | `\| sort - count \| head 10` |

The **pipe character (`|`)** chains them together. Output of one stage becomes input to the next — just like Linux shell pipes.

---

## 2. Search Fundamentals

### Specifying What to Search

| Operator | What It Does |
|---|---|
| `index=<name>` | Search a specific data index (e.g., `index=linux`) |
| `sourcetype=<type>` | Filter by data format (e.g., `sourcetype=syslog`) |
| `host=<hostname>` | Limit to one host |
| `source=<path>` | Limit to a specific log file |

### Boolean Logic

| Operator | Example |
|---|---|
| `AND` (implicit) | `error AND ssh` |
| `OR` | `failed OR denied` |
| `NOT` | `error NOT cron` |
| Parentheses | `(failed OR denied) AND ssh` |

### Time Modifiers

| Time Range | Modifier |
|---|---|
| Last 15 minutes | `earliest=-15m` |
| Last 1 hour | `earliest=-1h` |
| Last 24 hours | `earliest=-24h` |
| Last 7 days | `earliest=-7d` |
| Specific window | `earliest="01/15/2026:00:00:00" latest="01/16/2026:00:00:00"` |

### Field Extraction

| Command | What It Does |
|---|---|
| `\| fields src_ip, user, action` | Show only these fields |
| `\| rex field=_raw "user=(?<user>\w+)"` | Extract custom field with regex |
| `\| eval new_field=lower(user)` | Create or transform a field |

---

## 3. Authentication & Login Queries

The single highest-signal log category for Tier 1 work.

### Failed SSH logins, last 24 hours

```spl
index=linux sourcetype=syslog "Failed password"
earliest=-24h
| stats count by src_ip
| sort - count
```

### Brute force candidates (more than 10 failures from one IP)

```spl
index=linux sourcetype=syslog "Failed password"
| stats count by src_ip
| where count > 10
| sort - count
```

### Successful logins after a streak of failures (potential compromise)

```spl
index=linux sourcetype=syslog ("Failed password" OR "Accepted")
| transaction src_ip maxspan=5m
| where eventcount > 5 AND searchmatch("Accepted")
```

### Top targeted usernames

```spl
index=linux sourcetype=syslog "Failed password"
| rex "for (invalid user )?(?<user>\w+) from"
| stats count by user
| sort - count
| head 10
```

### All sudo activity in the last hour

```spl
index=linux sourcetype=syslog "sudo:"
earliest=-1h
| table _time, host, user, _raw
```

### Successful root logins (always investigate)

```spl
index=linux sourcetype=syslog "Accepted" user=root
| table _time, src_ip, host
```

---

## 4. Process & Execution Queries

### All processes started in the last hour

```spl
index=linux sourcetype=auditd type=EXECVE
earliest=-1h
| table _time, host, exe, comm
```

### Processes running from suspicious directories

```spl
index=linux (path="/tmp/*" OR path="/dev/shm/*" OR path="/var/tmp/*")
| stats count by host, path, user
```

### Reverse shell command patterns

```spl
index=linux ("bash -i" OR "nc -e" OR "/bin/sh -i" OR "python -c 'import socket'")
| table _time, host, user, _raw
```

### Cryptominer indicators

```spl
index=linux ("xmrig" OR "minerd" OR "stratum+tcp")
| table _time, host, user, _raw
```

---

## 5. Network Queries

### Connections to suspicious ports

```spl
index=linux sourcetype=netstat dest_port IN (4444, 8888, 31337, 6667)
| stats count by host, dest_ip, dest_port
```

### Outbound connections to non-RFC1918 IPs

```spl
index=linux sourcetype=netstat
NOT (dest_ip="10.0.0.0/8" OR dest_ip="172.16.0.0/12" OR dest_ip="192.168.0.0/16")
| stats count by host, dest_ip, dest_port
| sort - count
```

### DNS queries to unusual TLDs

```spl
index=dns NOT (query="*.com" OR query="*.net" OR query="*.org" OR query="*.io")
| stats count by query, src_ip
| sort - count
```

### Top talkers (most network volume)

```spl
index=linux sourcetype=netstat
| stats sum(bytes) as total_bytes by src_ip, dest_ip
| sort - total_bytes
| head 20
```

---

## 6. File & Persistence Queries

### New cron jobs

```spl
index=linux sourcetype=auditd path="/etc/cron*"
| table _time, host, user, path, action
```

### Modified SSH authorized_keys

```spl
index=linux sourcetype=auditd path="*authorized_keys*"
| table _time, host, user, path, action
```

### New user account creation

```spl
index=linux sourcetype=syslog ("new user" OR "useradd")
| table _time, host, user, _raw
```

### SUID binary changes

```spl
index=linux sourcetype=auditd "suid"
| table _time, host, path, action
```

---

## 7. Stats, Charts & Aggregation

The `stats` command is the most powerful in SPL. Master these patterns.

### Count by single field

```spl
... | stats count by src_ip
```

### Count by multiple fields

```spl
... | stats count by src_ip, dest_port
```

### Sum, average, max

```spl
... | stats sum(bytes) as total, avg(bytes) as average, max(bytes) as peak by host
```

### Distinct count (how many unique values)

```spl
... | stats dc(user) as unique_users by host
```

### First and last seen

```spl
... | stats earliest(_time) as first_seen, latest(_time) as last_seen by src_ip
| convert ctime(first_seen) ctime(last_seen)
```

### Timechart for visualization

```spl
... | timechart count by src_ip
```

### Top values

```spl
... | top limit=10 src_ip
```

### Rare values (useful for hunting outliers)

```spl
... | rare limit=10 user
```

---

## 8. Top 10 Essential Queries to Memorize

If you only memorize ten queries, these are the ones. Each one solves a real Tier 1 problem.

### 1. Brute-force candidates (top 10 attacker IPs)

```spl
index=linux "Failed password"
| stats count by src_ip
| sort - count
| head 10
```

### 2. Targeted users in brute force

```spl
index=linux "Failed password"
| rex "for (invalid user )?(?<user>\w+) from"
| stats count by user
| sort - count
| head 10
```

### 3. Successful logins from anomalous IPs

```spl
index=linux "Accepted"
| stats count, values(user) as users by src_ip
| sort - count
```

### 4. All sudo activity

```spl
index=linux "sudo:"
| table _time, host, user, _raw
```

### 5. Listening ports change detection

```spl
index=linux sourcetype=netstat
| stats values(dest_port) as ports by host
```

### 6. Processes from suspicious paths

```spl
index=linux (path="/tmp/*" OR path="/dev/shm/*")
| table _time, host, path, user
```

### 7. New cron jobs created

```spl
index=linux path="/etc/cron*" action=created
| table _time, host, user, path
```

### 8. SSH authorized_keys modifications

```spl
index=linux path="*authorized_keys*"
| table _time, host, user, path, action
```

### 9. Login geographic anomalies (requires GeoIP)

```spl
index=linux "Accepted"
| iplocation src_ip
| stats count by user, Country, City
| sort - count
```

### 10. Beaconing detection (regular outbound connections)

```spl
index=linux sourcetype=netstat dest_ip="<external_ip>"
| timechart span=5m count
```

---

## 9. The Tier 1 Daily SPL Workflow

This is the Splunk side of your morning ritual. Run alongside the Linux command ritual.

| Step | Query | Looking For |
|---|---|---|
| 1 | Failed login leaderboard (Query #1 above) | Brute force attempts |
| 2 | Top targeted users (Query #2) | Common username attacks |
| 3 | All sudo events last 24h (Query #4) | Unauthorized escalation |
| 4 | Successful logins (Query #3) | Compromised credentials |
| 5 | Processes from /tmp (Query #6) | Malware staging |
| 6 | New cron jobs (Query #7) | Persistence implants |
| 7 | authorized_keys changes (Query #8) | Backdoor SSH keys |

**Total time:** ~10 minutes in Splunk + the Linux ritual = ~30-minute total morning routine.

---

## 🎓 Pro Tips for Beginners

1. **Always set a time range.** Splunk searches "All time" by default — this is slow and noisy. Use `earliest=-24h` or set the time picker.
2. **Pipe builds work left-to-right.** Each `|` is a new transformation. Read SPL like a recipe.
3. **`stats` is more powerful than `chart`** for tabular output. Use `chart` only for visualizations.
4. **Save your favorites as Reports** in Splunk so you can re-run them in one click.
5. **Use `_time` for time fields.** It's the standard Splunk time field, automatically parsed.

---

## 📚 Where To Learn More

- **Splunk Search Reference:** https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- **Splunk Boss of the SOC (BOTS):** Free CTF-style SOC labs with realistic Splunk data
- **Free Splunk Fundamentals 1:** Splunk's official free training

---

## 📄 License

[MIT](./LICENSE) — fork, adapt, use freely.
