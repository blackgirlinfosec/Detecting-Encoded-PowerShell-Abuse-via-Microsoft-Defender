# 🧪 PowerShell Encoded Command Threat Hunting Lab

## 📌 Overview

This lab simulates an attacker using an encoded PowerShell command (`-EncodedCommand`) to execute a potentially malicious payload. Using Microsoft Defender for Endpoint and KQL, I simulated the attack and hunted for the encoded command activity within Defender logs. This lab walks through simulation, detection, and basic remediation logic.

---

## ⚙️ Event Creation

### 🎭 Threat Simulation

A harmless PowerShell command was encoded in Base64 and executed using the `-EncodedCommand` flag to simulate obfuscated attacker behavior. This is a common evasion tactic in real-world attacks.

#### 💻 Command Used:
```powershell
powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAdQBzAHAAaQBjAGkAbwB1AHMAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAQQBiAHUAcwBlACAAUwBpAG0AdQBsAGEAdABpAG8AbgAiAA==
```

This command decodes to:
```powershell
Write-Output "Suspicious PowerShell Abuse Simulation"
```

---

## 🔍 Detection via KQL

### 🧠 Query Used:
```kql
DeviceProcessEvents
| where Timestamp > ago(2h)
| where FileName endswith "powershell.exe"
| where ProcessCommandLine has "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

📎 [Download the query as a `.kql` file](powershell_encoded_command_query_v2.kql)

---

### 🖼️ Screenshots
- ![⚙️ Attacker Command Executed](encoded-command-simulation-executed.png)
- ![🛡️ Defender Detection](encoded-command-detected-in-defender.png)
- ![📄 Event Details](encoded-command-event-details.png)

---

## 🧩 Device Onboarding

The virtual machine was onboarded to Microsoft Defender using a custom script provided by the lab environment. This step ensured logging of PowerShell activity in Defender for advanced hunting.

🖥️ ![Onboarding Confirmation](vm-onboarding-success.png)

---

## 🛡️ Remediation (Simulated)

If this were a real attack, these steps would follow detection:

- 🔍 Review full process tree and timeline
- 🕵🏽 Investigate parent and child processes
- 🚫 Isolate the endpoint if malicious behavior is confirmed
- ❌ Terminate the suspicious process
- 📦 Quarantine downloaded files
- 🚨 Escalate per incident response procedures

---

## 📝 SOC-Style Incident Report

**Title**: Suspicious Encoded PowerShell Command Detected  
**Analyst**: Fee Bolden  
**Date**: June 2, 2025  
**Device**: blueteamwin10  
**User**: system

### ⚠️ Alert Type:
Suspicious Command-Line Activity

### 🧪 Behavior:
A PowerShell process was executed with the `-EncodedCommand` flag, commonly used by attackers to hide malicious scripts in Base64 format.

The decoded command in this instance was harmless:
```powershell
Write-Output "Suspicious PowerShell Abuse Simulation"
```

No additional payloads or network connections were observed.

### 🔍 Actions Taken:
- Investigated device timeline in Microsoft Defender
- Verified that no additional processes or file drops occurred
- Confirmed activity was part of a controlled simulation
- No remediation required

### 📌 Lessons Learned / Next Steps:
- Added custom detection for encoded PowerShell usage
- Recommended monitoring for follow-up behaviors (like downloads or reverse shells)

---

## 🗣️ Interview-Ready Summary

> “In one of my labs, I simulated an attacker using PowerShell’s `-EncodedCommand` flag to execute a hidden command. After running the command on a test VM, I used Microsoft Defender Advanced Hunting to detect it through KQL.  
Once I confirmed the activity, I pivoted to look at the process timeline and verified that no other payloads or lateral movement occurred. In a real-world setting, I would isolate the device, terminate the process, and investigate file events to find and remove any malicious payloads.”

---

## 🧰 Tools Used

- Microsoft Defender for Endpoint  
- Microsoft Defender Advanced Hunting  
- PowerShell  
- KQL (Kusto Query Language)

---

## ✅ Outcome

Successfully simulated and detected the use of an obfuscated PowerShell command. Demonstrated real-world detection, triage, and basic response logic using Microsoft Defender and KQL.
