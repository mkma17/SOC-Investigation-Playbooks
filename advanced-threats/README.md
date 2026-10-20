# Advanced Threats — SOC Detection Reference

## 1. ClickFix and Social Engineering

- **MITRE ATT&CK:** T1204.004 — Malicious Copy and Paste
- **Related tactic:** Execution
- **Detection sources:** EDR, Sysmon, Windows Security Logs, Proxy Logs
- **Primary signals:** Browser-to-shell process chains, suspicious PowerShell commands, unexpected downloads.

**Splunk starting point:**

```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(powershell|pwsh|cmd)\.exe$")
| table _time Computer User ParentImage Image CommandLine
| sort - _time
```

**Investigate:** Determine whether the parent process, command line, user action, and subsequent network connections form a suspicious execution chain.

## 2. Active Directory — DCSync

- **MITRE ATT&CK:** T1003.006
- **Tactic:** Credential Access
- **Detection source:** Domain Controller Security Logs
- **Primary event:** Event ID 4662, when the relevant auditing is enabled.

**Splunk starting point:**

```spl
index=windowslogs EventCode=4662
| where match(lower(Properties),
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c")
| table _time host SubjectUserName ObjectName Properties
| sort - _time
```

**Investigate:** Verify the replication rights, requesting account, target object, source host, and whether the activity was authorized.

## 3. Active Directory — Shadow Credentials

- **MITRE ATT&CK:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication is a separate technique; validate the precise Shadow Credentials mapping against the current ATT&CK knowledge base before final classification.
- **Detection source:** Active Directory Directory Service Changes
- **Potential event:** Event ID 5136, if the relevant auditing is configured.

**Splunk starting point:**

```spl
index=windowslogs EventCode=5136
"msDS-KeyCredentialLink"
| table _time host SubjectUserName ObjectDN AttributeLDAPDisplayName
        AttributeValue OperationType
| sort - _time
```

**Investigate:** Confirm the affected account, who modified the attribute, the change time, and whether the change was approved.

**Caution:** Confirm that the field names and attribute value are actually extracted in your environment. An attribute change alone does not prove malicious activity.

## 4. Cloud Identity Compromise

- **MITRE ATT&CK:** T1078 — Valid Accounts
- **Detection sources:** Identity-provider audit logs, SaaS audit logs, cloud activity logs
- **Primary signals:** Unusual sign-in context, suspicious application consent, unexpected privilege changes, unusual file access.

**Splunk starting point:**

```spl
index=cloud_audit
| stats count
        dc(source_ip) as unique_ips
        values(action) as actions
        by user
| where unique_ips >= 3
| sort - unique_ips
```

**Investigate:** Correlate sign-in events with MFA, application consent, role changes, mailbox changes, and file downloads.

**Caution:** Multiple IP addresses can be normal because of VPNs, mobile networks, and cloud services.

## 5. Possible Data Exfiltration

- **MITRE ATT&CK:** T1041 — Exfiltration Over C2 Channel, when applicable
- **Detection sources:** Network flow logs, proxy logs, cloud audit logs, DLP
- **Primary signals:** Unusual outbound volume, large-scale file downloads, unusual destination services.

**Splunk starting point:**

```spl
index=network direction=outbound
| stats sum(bytes) as total_bytes
        count as events
        by src_ip dest_ip
| sort - total_bytes
```

**Investigate:** Compare the volume against normal behavior, identify the user and application, and verify whether the transferred data was sensitive.

**Caution:** High outbound traffic is not automatically data theft.

## 6. Edge Device Exploitation

- **MITRE ATT&CK:** T1190, where applicable
- **Detection sources:** Firewall, WAF, appliance audit logs, IDS, EDR
- **Primary signals:** Suspicious management requests, unexpected configuration changes, new outbound connections, and unusual process execution.

**Investigation workflow:**

1. Identify the exposed device and software version.
2. Check applicable vendor advisories and vulnerability exposure.
3. Review device and gateway logs around the suspected exploitation time.
4. Search for unexpected accounts, files, processes, and outbound connections.
5. Determine whether the device was used to reach internal systems.
6. Preserve logs and escalate according to the incident-response procedure.

## 7. Software Supply Chain Compromise

- **MITRE ATT&CK:** T1195 — Supply Chain Compromise
- **Detection sources:** CI/CD audit logs, package registries, EDR, source control
- **Primary signals:** Unexpected dependency changes, unusual build activity, unauthorized pipeline changes, and suspicious build-runner network activity.

**Investigation workflow:**

1. Identify the affected package, build, or release.
2. Compare dependency versions and hashes against trusted records.
3. Inspect changes to source code, build definitions, and secrets access.
4. Correlate the build with process execution and network events.
5. Determine which downstream systems consumed the affected artifact.
6. Document the affected versions and containment actions.

---

## Operational Notes

- These searches are starting points, not production-ready detections.
- Validate every field against the actual source schema.
- Set thresholds using a known-good baseline.
- Confirm logging and audit policies before assuming that missing events indicate no activity.
- Correlate multiple signals before assigning a malicious verdict.
- Map each confirmed behavior to the appropriate current MITRE ATT&CK technique.
