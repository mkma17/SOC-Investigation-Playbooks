# SOC Investigation Playbooks
### Practical Security Monitoring, Detection & Incident Investigation

A practical reference for SOC Analysts to investigate common cyberattacks using **Splunk SPL, Wireshark, Windows Event Logs, and MITRE ATT&CK**.

> **Purpose:** Provide reusable detection queries, network filters, important IOCs, investigation steps, and incident-report templates.

**Tools:** Splunk | Wireshark | Windows Security Logs | Sysmon | MITRE ATT&CK

---

## Table of Contents

1. [Investigation Workflow](#1-investigation-workflow)
2. [Brute Force](#2-brute-force)
3. [Port Scanning](#3-port-scanning)
4. [DoS / DDoS](#4-dos--ddos)
5. [Phishing](#5-phishing)
6. [Suspicious PowerShell Execution](#6-suspicious-powershell-execution)
7. [Lateral Movement](#7-lateral-movement)
8. [IOC Reference](#8-ioc-reference)
9. [Investigation Checklist](#9-investigation-checklist)
10. [SOC Incident Report Template](#10-soc-incident-report-template)

---

## 1. Investigation Workflow

Follow these steps when investigating a security alert.

1. **Identify:** Record the alert, affected host, user, source IP, destination IP, and timestamp.
2. **Validate:** Check whether the activity is expected or suspicious.
3. **Investigate:** Search Splunk logs and inspect network traffic in Wireshark.
4. **Identify IOCs:** Extract IP addresses, domains, file hashes, usernames, process names, and suspicious commands.
5. **Correlate:** Connect related events using timestamps, hosts, users, and process identifiers.
6. **Assess Impact:** Determine whether the activity succeeded and whether other systems were affected.
7. **Respond:** Preserve evidence, escalate, or isolate affected systems according to organizational procedures.
8. **Document:** Record findings, evidence, confidence, impact, and recommended actions.

### Important MITRE ATT&CK Terms

- **Tactic:** Why the adversary performs an action.
- **Technique:** How the adversary attempts to achieve an objective.
- **IOC:** An observable indicator that may help identify malicious activity.
- **False Positive:** An alert that appears suspicious but is caused by legitimate activity.

---

## 2. Brute Force

**MITRE ATT&CK:** T1110 — Brute Force  
**Tactic:** Credential Access  
**Related techniques:** T1110.001 — Password Guessing; T1110.003 — Password Spraying

### Important IOCs

- Repeated failed logins from the same source IP.
- Multiple targeted accounts.
- Windows Event ID 4625 — Failed logon.
- Windows Event ID 4624 — Successful logon.
- Unusual logon types or authentication times.
- A suspicious successful login following repeated failures.

### Splunk — Failed Logins by Source IP

```spl
index=windowslogs EventCode=4625
| stats count as failures
        dc(TargetUserName) as unique_users
        values(TargetUserName) as users
        by IpAddress
| sort - failures
```

**Purpose:** Identify source IPs associated with repeated failed logins and determine how many distinct accounts were targeted.

### Splunk — Sources with Failed and Successful Logins

```spl
index=windowslogs (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4625)) as failures
        count(eval(EventCode=4624)) as successes
        min(_time) as first_seen
        max(_time) as last_seen
        by IpAddress TargetUserName
| where failures >= 5 AND successes > 0
| convert ctime(first_seen) ctime(last_seen)
| sort - failures
```

**Purpose:** Find source IP and account combinations with both failed and successful logons during the selected time range.

**Important:** This query does not prove that success occurred after the failures. Verify the event order before drawing a conclusion.

### Wireshark Filters

Show RDP traffic:

```wireshark
tcp.port == 3389
```

Show SSH traffic:

```wireshark
tcp.port == 22
```

Show SMB traffic:

```wireshark
tcp.port == 445
```

Show initial TCP SYN packets:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Investigation Steps

1. Identify the source IP and targeted account.
2. Count failed logins and inspect the time pattern.
3. Check whether a successful login occurred.
4. Review the logon type, destination host, and authentication details.
5. Correlate the login with process creation and network activity.
6. Determine whether the activity is malicious or legitimate.

**Caution:** TCP connection success does not prove authentication success.

---

## 3. Port Scanning

**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Tactic:** Discovery

### Important IOCs

- One source connecting to many destination ports.
- One source contacting multiple internal hosts.
- Repeated SYN packets without completed TCP handshakes.
- Unusual sequences of connection attempts.
- Repeated TCP RST responses.

### Wireshark — Initial TCP Connections

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Wireshark — TCP Reset Packets

```wireshark
tcp.flags.reset == 1
```

### Wireshark — Traffic to a Specific Host

Replace the example IP with the target address:

```wireshark
ip.dst == 192.168.1.10 && tcp
```

### Splunk — Detect Many Destination Ports

Assumes the fields `src_ip`, `dest_ip`, and `dest_port` exist in the network dataset.

```spl
index=network
| stats count as attempts
        dc(dest_port) as unique_ports
        values(dest_port) as ports
        by src_ip dest_ip
| where unique_ports >= 15
| sort - unique_ports
```

### Splunk — Detect Scanning Across Multiple Hosts

```spl
index=network
| stats dc(dest_ip) as unique_hosts
        dc(dest_port) as unique_ports
        count as connections
        by src_ip
| where unique_hosts >= 10 OR unique_ports >= 15
| sort - connections
```

### Investigation Steps

1. Identify the scanning source.
2. Count unique ports and destination hosts.
3. Check SYN, ACK, and RST patterns.
4. Identify services that responded.
5. Check whether exploitation or authentication attempts followed.
6. Compare activity against approved vulnerability scanners and monitoring tools.

**Caution:** Thresholds are starting points, not universal indicators of malicious activity.

---

## 4. DoS / DDoS

**MITRE ATT&CK:** T1498 — Network Denial of Service  
**Tactic:** Impact  
**Related techniques:** T1498.001 — Direct Network Flood; T1498.002 — Reflection Amplification

### Important IOCs

- Sudden increase in packets or traffic volume.
- Many connections directed at one host or service.
- Unusual concentration of traffic on a particular port.
- Increased service latency or availability errors.
- Large numbers of sources contacting the same target.
- High packet rates or incomplete connection attempts.

### Wireshark — Traffic to the Target

```wireshark
ip.dst == 192.168.1.10
```

### Wireshark — TCP SYN Packets

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Wireshark — UDP Traffic

```wireshark
udp
```

### Splunk — Event Volume Over Time

```spl
index=network
| timechart span=1m count as events
```

### Splunk — Top Source and Destination Pairs

```spl
index=network
| stats count as events
        dc(dest_port) as ports
        by src_ip dest_ip
| sort - events
| head 20
```

### Splunk — Traffic Volume by Port

```spl
index=network
| timechart span=1m count by dest_port limit=10
```

### Splunk — Total Bytes Over Time

Use this query if the dataset contains a suitable numeric `bytes` field.

```spl
index=network
| timechart span=1m sum(bytes) as total_bytes
```

### Investigation Steps

1. Establish the normal traffic baseline.
2. Identify when the traffic spike began.
3. Determine the most affected destination and service.
4. Compare packet rate, byte volume, and connection counts.
5. Check server health and service availability.
6. Determine whether the traffic originates from one source or multiple sources.
7. Escalate to the network or incident-response team as required.

**Caution:** Event counts are not necessarily equivalent to packet counts or network bandwidth.

---

## 5. Phishing

**MITRE ATT&CK:** T1566 — Phishing  
**Tactic:** Initial Access  
**Related techniques:**
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service

### Important IOCs

- Suspicious sender or lookalike domain.
- Unexpected URL or redirect chain.
- Suspicious attachment and SHA-256 hash.
- DNS queries to an unusual domain.
- Proxy connections to suspicious destinations.
- File downloads followed by process execution.
- Authentication activity following a suspicious link.

### Wireshark — DNS Queries

```wireshark
dns
```

### Wireshark — Specific DNS Domain

```wireshark
dns.qry.name == "suspicious-example.com"
```

### Wireshark — HTTP Requests

```wireshark
http.request
```

### Wireshark — HTTP GET Requests

```wireshark
http.request.method == "GET"
```

### Splunk — Search Proxy Logs for a Domain

Assumes proxy fields named `src_ip`, `url`, `status`, and `user`.

```spl
index=proxy "suspicious-example.com"
| table _time src_ip url status user
| sort _time
```

### Splunk — Summarize Web Activity

```spl
index=proxy
| stats count
        values(url) as urls
        values(status) as status_codes
        by src_ip
| sort - count
```

### Splunk — Search DNS Logs

Assumes DNS fields named `src_ip`, `query`, and `answer`.

```spl
index=dns "suspicious-example.com"
| stats count
        values(answer) as resolved_ips
        by src_ip query
```

### Investigation Steps

1. Inspect the email sender, headers, links, and attachments.
2. Search DNS and proxy logs for the domain.
3. Determine whether the user accessed the link.
4. Check for downloads or suspicious redirects.
5. Examine endpoint telemetry for file execution.
6. Correlate events by host, user, and time.
7. Determine whether credentials were entered or data was exposed.

**Caution:** HTTPS traffic usually does not expose the complete URL path or encrypted content in a normal packet capture.

---

## 6. Suspicious PowerShell Execution

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Tactic:** Execution

### Important IOCs

- Unexpected execution of `powershell.exe` or `pwsh.exe`.
- Suspicious parent process.
- Unusual encoded or hidden command-line arguments.
- Commands that download remote content.
- Unexpected outbound network connections.
- Suspicious child processes or newly created files.

### Splunk — Windows Process Creation (Event ID 4688)

```spl
index=windowslogs EventCode=4688
("powershell.exe" OR "pwsh.exe")
| table _time host user New_Process_Name
        Creator_Process_Name Process_Command_Line
| sort - _time
```

### Splunk — Sysmon Process Creation (Event ID 1)

```spl
index=sysmon EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time host User Image ParentImage CommandLine
| sort - _time
```

### Splunk — Sysmon Network Connections (Event ID 3)

```spl
index=sysmon EventCode=3
| stats count
        by Computer Image DestinationIp DestinationPort
| sort - count
```

### Wireshark — DNS, HTTP, and TLS Server Names

```wireshark
dns || http.request || tls.handshake.extensions_server_name
```

### Investigation Steps

1. Identify the user and process that launched PowerShell.
2. Inspect the parent process and full command line.
3. Check for encoded arguments, remote URLs, or unusual execution patterns.
4. Review Sysmon network events for related connections.
5. Correlate activity using the process GUID where available.
6. Check for file creation, persistence, or additional process execution.
7. Document the evidence and assess the impact.

**Caution:** PowerShell is a legitimate administrative tool. Suspicious arguments alone do not prove malicious execution.

---

## 7. Lateral Movement

**MITRE ATT&CK:** Lateral Movement  
**Related techniques:**
- T1021.001 — Remote Desktop Protocol
- T1021.002 — SMB/Windows Admin Shares
- T1021.006 — Windows Remote Management

### Important IOCs

- Unusual RDP or SMB connections between internal hosts.
- One workstation contacting many administrative services.
- Privileged account use from an unfamiliar host.
- Unexpected network logons.
- Remote access followed by process creation or service installation.
- Authentication patterns inconsistent with normal administrative activity.

### Wireshark — Common Remote Services

```wireshark
tcp.port == 3389 || tcp.port == 445 || tcp.port == 5985 || tcp.port == 5986
```

### Splunk — Identify Sources Connecting to Many Hosts

```spl
index=network
(dest_port=3389 OR dest_port=445 OR dest_port=5985 OR dest_port=5986)
| stats count
        dc(dest_ip) as unique_targets
        values(dest_ip) as targets
        by src_ip dest_port
| sort - unique_targets
```

### Splunk — Review Windows Authentication Events

```spl
index=windowslogs (EventCode=4624 OR EventCode=4625)
| table _time host EventCode TargetUserName
        IpAddress LogonType
| sort - _time
```

### Investigation Steps

1. Identify the source and destination hosts.
2. Determine which remote service was used.
3. Inspect the account and logon type.
4. Compare the activity with known administrative behavior.
5. Review process creation and service-related events on the target.
6. Determine whether additional hosts or privileged accounts were affected.
7. Escalate confirmed or high-confidence suspicious activity.

**Caution:** RDP, SMB, and WinRM are legitimate services. Their presence alone is not evidence of an attack.

---

## 8. IOC Reference

| IOC | Investigation Value |
|---|---|
| Source IP | Identifies the apparent network source |
| Destination IP | Identifies the contacted system |
| Domain | Helps trace DNS and web activity |
| SHA-256 | Identifies a specific file version |
| Username | Connects authentication and endpoint events |
| Process name | Helps identify suspicious execution |
| Command line | Reveals execution arguments and behavior |
| Destination port | Helps identify the service involved |
| Timestamp | Enables correlation across log sources |
| Process GUID | Connects related Sysmon process and network events |

**IOC handling rules:**

- Validate indicators against trusted threat intelligence and internal context.
- Preserve the original timestamps and source evidence.
- Record whether an indicator is confirmed, suspected, or unverified.
- Avoid treating a single IP, domain, or event as conclusive proof.
- Correlate multiple independent observations before making a final determination.

---

## 9. Investigation Checklist

- [ ] Identify the alert and affected host.
- [ ] Record the timestamp, source, destination, and account.
- [ ] Preserve relevant logs and PCAP evidence.
- [ ] Map the activity to MITRE ATT&CK.
- [ ] Run the relevant Splunk searches.
- [ ] Inspect the related traffic in Wireshark.
- [ ] Extract and validate relevant IOCs.
- [ ] Correlate events across available data sources.
- [ ] Check whether the activity succeeded and determine the impact.
- [ ] Evaluate false-positive explanations.
- [ ] Escalate or respond according to organizational procedures.
- [ ] Write and update the incident report.

---

## 10. SOC Incident Report Template

### Incident Information

- **Incident ID:** [ID]
- **Title:** [Incident title]
- **Severity:** [Critical / High / Medium / Low]
- **Status:** [Open / Investigating / Contained / Closed]
- **Analyst:** [Name or identifier]
- **First Seen:** [Timestamp and timezone]
- **Last Seen:** [Timestamp and timezone]
- **Affected Hosts:** [Hostnames]
- **Affected Accounts:** [Usernames]

### Executive Summary

[Describe what happened, the affected systems, the potential impact, and the current status in plain language.]

### Technical Findings

- **Suspected Attack:** [Attack name]
- **MITRE ATT&CK Tactic:** [Tactic]
- **Technique ID:** [Technique ID]
- **Source IP:** [IP address]
- **Destination IP:** [IP address]
- **Relevant Event IDs:** [Event IDs]
- **Key Evidence:** [Log events, PCAP observations, process details]
- **IOCs:** [Validated indicators]

### Investigation Timeline

| Timestamp | Event | Evidence |
|---|---|---|
| [Time] | [Observed activity] | [Log or packet reference] |
| [Time] | [Related activity] | [Log or packet reference] |
| [Time] | [Response action] | [Action record] |

### Impact Assessment

[Describe confirmed impact, suspected impact, affected assets, and remaining uncertainty.]

### Response Actions

- [Action taken]
- [Evidence preserved]
- [Containment or escalation status]

### Recommendations

- [Immediate mitigation]
- [Detection improvements]
- [Preventive control]
- [Follow-up investigation]

### Conclusion

[State whether the activity was confirmed malicious, suspicious but unconfirmed, or legitimate, and explain the evidence supporting the conclusion.]

---

## Notes and References

- Adapt index names and field names to your Splunk environment.
- Validate thresholds against normal network and authentication behavior.
- Confirm that the required Windows and Sysmon logging is enabled.
- Use authorized lab data or approved incident-response evidence.

**Official references:**

- MITRE ATT&CK: https://attack.mitre.org/
- Wireshark Display Filter Reference: https://www.wireshark.org/docs/dfref/
- Splunk Search Reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
