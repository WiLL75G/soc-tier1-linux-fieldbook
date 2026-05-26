# Windows Commands for SOC Tier 1 Analysts

> The PowerShell and Command Prompt commands an entry-level SOC analyst runs during Windows investigations. Companion to the Linux Fieldbook together they cover the two platforms every SOC role tests on.
 
**Companion to:** [COMMANDS.md](./COMMANDS.md), [FILESYSTEM.md](./FILESYSTEM.md)

---

## PowerShell vs Command Prompt Which to Learn?

Both. But here's the modern reality:

| | **Command Prompt (cmd)** | **PowerShell (pwsh)** |
|---|---|---|
| Age | Legacy, since DOS | Modern, since Windows 7 |
| Output | Plain text | Structured objects |
| Power | Limited | Full .NET access |
| When to use | Quick legacy commands (`netstat`, `tasklist`) | Anything serious |

**Modern SOC analysts default to PowerShell.** Cmd is still useful for muscle-memory commands and older systems. This reference covers both, but leans PowerShell.

To open PowerShell: press `Win + X`, then click **"Terminal (Admin)"** or **"Windows PowerShell (Admin)"**. Run as Administrator for full visibility.

---

## Table of Contents

1. [System Orientation](#1-system-orientation)
2. [Users & Authentication](#2-users--authentication)
3. [Process Inspection](#3-process-inspection)
4. [Network Inspection](#4-network-inspection)
5. [Windows Event Logs](#5-windows-event-logs)
6. [Persistence Hunting](#6-persistence-hunting)
7. [File System Investigation](#7-file-system-investigation)
8. [Critical Windows Event IDs](#8-critical-windows-event-ids)
9. [The Tier 1 Windows Daily Ritual](#9-the-tier-1-windows-daily-ritual)

---

## 1. System Orientation

The first commands when you start an investigation on a Windows box.

### PowerShell

| Command | Purpose |
|---|---|
| `whoami` | Your current username. |
| `whoami /all` | Username, groups, privileges, SID. **Critical** for understanding context. |
| `hostname` | Computer name. |
| `Get-ComputerInfo` | Comprehensive system info. |
| `[System.Environment]::OSVersion` | OS version detail. |
| `Get-Date` | Current system time. |
| `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` | Last boot time (uptime equivalent). |

### Command Prompt

| Command | Purpose |
|---|---|
| `whoami` | Current username. |
| `hostname` | Computer name. |
| `systeminfo` | Full system summary (slow but comprehensive). |
| `ver` | Windows version. |

**SOC mindset:** *"What system am I on, who am I, and is the clock right?"*

---

## 2. Users & Authentication

Who has access, who is logged in, who has tried.

### PowerShell

| Command | Purpose |
|---|---|
| `Get-LocalUser` | All local user accounts. |
| `Get-LocalGroup` | All local groups. |
| `Get-LocalGroupMember -Group "Administrators"` | Members of the Administrators group. |
| `Get-LocalGroupMember -Group "Remote Desktop Users"` | RDP-enabled accounts. |
| `query user` | Currently logged-in users (also works in cmd). |
| `Get-CimInstance Win32_LoggedOnUser` | All active logon sessions. |

### Command Prompt

| Command | Purpose |
|---|---|
| `net user` | All local users. |
| `net user <username>` | Details for one user. |
| `net localgroup administrators` | Administrators group members. |
| `query user` | Currently logged-in users. |

**Red flags:**
- New accounts in `Get-LocalUser` you didn't create
- Unexpected members in Administrators or Remote Desktop Users
- Accounts with `PasswordLastSet` in the future (clock manipulation)

---

## 3. Process Inspection

### PowerShell

| Command | Purpose |
|---|---|
| `Get-Process` | All running processes. |
| `Get-Process \| Sort-Object CPU -Descending \| Select-Object -First 10` | Top 10 by CPU. |
| `Get-Process \| Sort-Object WS -Descending \| Select-Object -First 10` | Top 10 by memory. |
| `Get-Process -Name <name>` | Filter by name. |
| `Get-Process \| Where-Object {$_.Path -like "*Temp*"}` | Processes running from Temp. |
| `Get-CimInstance Win32_Process \| Select Name, ProcessId, ParentProcessId, CommandLine` | Processes with command lines + parent PIDs (critical for malware analysis). |

### Command Prompt

| Command | Purpose |
|---|---|
| `tasklist` | All running processes. |
| `tasklist /v` | Verbose (includes username). |
| `tasklist /svc` | Shows services hosted by each process. |
| `wmic process get name,processid,parentprocessid,commandline` | Process tree info (legacy WMIC). |
| `taskkill /PID <pid> /F` | Force-kill a process. |

**Red flags:**
- Processes running from `C:\Users\<user>\AppData\` or `C:\Temp\` or `C:\Windows\Temp\`
- Processes whose parent is `winword.exe` or `excel.exe` spawning `cmd.exe` or `powershell.exe` (classic macro-based malware)
- PowerShell with `-EncodedCommand` flag — almost always malicious
- Multiple `svchost.exe` instances NOT spawned by `services.exe`

---

## 4. Network Inspection

### PowerShell

| Command | Purpose |
|---|---|
| `Get-NetTCPConnection` | Active TCP connections. |
| `Get-NetTCPConnection -State Listen` | Listening ports only. |
| `Get-NetTCPConnection -State Established` | Active connections. |
| `Get-NetUDPEndpoint` | UDP listeners. |
| `Get-NetIPAddress` | Network interfaces and IPs. |
| `Get-NetRoute` | Routing table. |
| `Get-DnsClientServerAddress` | Configured DNS servers. |
| `Resolve-DnsName <domain>` | DNS lookup (like `dig`). |
| `Test-NetConnection <host> -Port 443` | Connectivity test. |

### Command Prompt

| Command | Purpose |
|---|---|
| `netstat -ano` | All connections with owning PIDs. THE classic Windows network command. |
| `netstat -anob` | Same but with executable names (requires admin). |
| `ipconfig /all` | All network adapter info. |
| `ipconfig /displaydns` | Cached DNS entries. |
| `route print` | Routing table. |
| `arp -a` | ARP cache. |
| `nslookup <domain>` | DNS lookup. |

**Killer one-liner connections to suspicious ports:**

```powershell
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in 4444,8888,31337,6667}
```

**Red flags:**
- Listening on ports you didn't open
- Established connections to high random ports
- Connections to known bad IPs (cross-check against threat intel)

---

## 5. Windows Event Logs

The crown jewels of Windows forensics. Three primary logs:

| Log | Contains |
|---|---|
| **Security** | Logons, logoffs, privilege use, audit events |
| **System** | OS events, services, drivers |
| **Application** | Application errors and events |

### PowerShell — `Get-WinEvent` (modern)

| Command | Purpose |
|---|---|
| `Get-WinEvent -LogName Security -MaxEvents 50` | Last 50 Security events. |
| `Get-WinEvent -LogName Security -FilterHashtable @{ID=4625}` | All failed logon events. |
| `Get-WinEvent -LogName Security -FilterHashtable @{ID=4624} -MaxEvents 20` | Recent successful logons. |
| `Get-WinEvent -LogName Security -FilterHashtable @{ID=4688} -MaxEvents 50` | Process creation events (critical!). |
| `Get-WinEvent -ListLog *` | Every available log channel. |
| `Get-WinEvent -LogName Security -FilterHashtable @{ID=4625; StartTime=(Get-Date).AddHours(-24)}` | Failed logons in last 24h. |

### Command Prompt — `wevtutil` (legacy)

| Command | Purpose |
|---|---|
| `wevtutil qe Security /c:50 /f:text` | Last 50 Security events as text. |
| `wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /f:text` | Last 20 failed logons. |

**Killer one-liner — top source IPs of failed logons:**

```powershell
Get-WinEvent -LogName Security -FilterHashtable @{ID=4625} -MaxEvents 1000 |
  ForEach-Object { $_.Properties[19].Value } |
  Group-Object | Sort-Object Count -Descending | Select-Object -First 10
```

---

## 6. Persistence Hunting

How attackers maintain access on Windows. Five main locations to check.

### Scheduled Tasks (MITRE T1053.005)

```powershell
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
Get-ScheduledTask -TaskName "*" | Where-Object { $_.Triggers.Enabled -eq $true }
```

Command Prompt: `schtasks /query /fo TABLE /v`

### Services (MITRE T1543.003)

```powershell
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-CimInstance Win32_Service | Where-Object {$_.PathName -notlike "*\\Windows\\*"}  # Non-system services
```

Command Prompt: `sc query state= all`

### Registry Run Keys (MITRE T1547.001)

The classic Windows persistence locations:

```powershell
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
```

### Startup Folder

```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

### WMI Event Subscriptions (advanced)

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
```

**Red flags:**
- Registry Run entries pointing to `C:\Users\<user>\AppData\` or temp paths
- Scheduled tasks with PowerShell encoded commands
- Services whose binary path is in `C:\Users\` or `C:\Temp\`

---

## 7. File System Investigation

### Recently modified files (PowerShell)

```powershell
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)} |
  Select-Object FullName, LastWriteTime
```

### Files in suspicious locations

```powershell
Get-ChildItem -Path "C:\Windows\Temp", "C:\Users\Public", "$env:TEMP" -Recurse -File -ErrorAction SilentlyContinue
```

### File hashing for VirusTotal lookups

```powershell
Get-FileHash -Algorithm SHA256 "C:\path\to\suspicious.exe"
```

### File signature verification

```powershell
Get-AuthenticodeSignature "C:\path\to\file.exe"
```

If status is **NotSigned** or **HashMismatch**, treat as suspicious.

### Alternate Data Streams (classic Windows hiding trick)

```powershell
Get-Item -Path "C:\path\to\file.exe" -Stream *
```

---

## 8. Critical Windows Event IDs

Memorize these. They appear in every Windows-focused SOC interview.

### Logon & Authentication

| Event ID | Meaning |
|---|---|
| **4624** | Successful logon |
| **4625** | Failed logon |
| **4634** | Logoff |
| **4648** | Logon using explicit credentials (RunAs) |
| **4672** | Special privileges assigned at logon (admin login) |
| **4768** | Kerberos ticket granted (TGT) |
| **4769** | Kerberos service ticket granted |
| **4776** | NTLM authentication |

### Logon Types (in Event 4624 / 4625)

| Type | Meaning |
|---|---|
| **2** | Interactive (console) |
| **3** | Network (e.g., file share) |
| **4** | Batch (scheduled task) |
| **5** | Service |
| **7** | Unlock |
| **10** | RemoteInteractive (RDP) |
| **11** | CachedInteractive (cached creds) |

### Process & Execution

| Event ID | Meaning |
|---|---|
| **4688** | Process creation (THE key event for execution tracking) |
| **4689** | Process termination |
| **1** (Sysmon) | Process creation (richer than 4688) |

### Account Management

| Event ID | Meaning |
|---|---|
| **4720** | User account created |
| **4722** | User account enabled |
| **4724** | Password reset attempt |
| **4728** | Member added to security-enabled global group |
| **4732** | Member added to security-enabled local group (e.g., Administrators) |
| **4738** | User account changed |
| **4740** | User account locked out |

### Services & Persistence

| Event ID | Meaning |
|---|---|
| **7045** | A service was installed (T1543.003 persistence) |
| **4697** | A service was installed (Security log version) |
| **4698** | Scheduled task created (T1053.005) |
| **4702** | Scheduled task updated |

### Log Tampering (T1070)

| Event ID | Meaning |
|---|---|
| **1102** | Audit log cleared (red alert) |
| **104** | System log cleared |

---

## 9. The Tier 1 Windows Daily Ritual

Parallel to the Linux ritual run on your Windows 11 VM.

| Step | Command | Looking For |
|---|---|---|
| 1 | `whoami /all` | Your context |
| 2 | `Get-LocalUser` | New accounts |
| 3 | `Get-LocalGroupMember -Group Administrators` | Admin group changes |
| 4 | `Get-Process \| Where-Object {$_.Path -like "*Temp*"}` | Suspicious processes |
| 5 | `Get-NetTCPConnection -State Listen` | Listening ports |
| 6 | `Get-NetTCPConnection -State Established` | Active connections |
| 7 | `Get-WinEvent -LogName Security -FilterHashtable @{ID=4625} -MaxEvents 50` | Failed logons |
| 8 | `Get-WinEvent -LogName Security -FilterHashtable @{ID=4720}` | New users created |
| 9 | `Get-ScheduledTask \| Where-Object {$_.State -eq "Ready"}` | Scheduled task review |
| 10 | `Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"` | Registry persistence |

**Total time:** ~10 minutes. Run alongside the Linux ritual on alternating days, or both daily if time permits.

---

## Pro Tips for Beginners

1. **Always run PowerShell as Administrator** when investigating many commands return incomplete data without it.
2. **Use Sysmon** for better visibility. It's free, from Microsoft, and gives you Event ID 1 (richer than 4688) plus network and file events.
3. **Learn the pipe.** PowerShell pipes pass objects, not text much more powerful than cmd. `Get-Process | Where-Object {...} | Select-Object ...` is the standard pattern.
4. **`Get-Help <cmdlet> -Full`** is the equivalent of `man` for PowerShell.
5. **Sysmon + Splunk** is the gold-standard small SOC setup. Install both on your Windows 11 VM and forward to Splunk on macOS.

---

## Where To Learn More

[![LOLBAS Project](https://img.shields.io/badge/LOLBAS-Project-2D2D2D?style=for-the-badge&logo=github&logoColor=white)](https://lolbas-project.github.io)
[![Sysinternals Suite](https://img.shields.io/badge/Microsoft-Sysinternals-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/)
[![Microsoft Event Logs](https://img.shields.io/badge/Microsoft-Event%20Log%20Reference-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/)

- **LOLBAS** (Living Off the Land Binaries and Scripts) every legitimate Windows binary attackers abuse
- **Sysinternals Suite** free toolkit from Microsoft (Process Monitor, Process Explorer, Autoruns)
- **Microsoft Event Log Reference** official documentation for Windows Security Event IDs

---

## 📄 License

[MIT](./LICENSE) fork, adapt, use freely.
