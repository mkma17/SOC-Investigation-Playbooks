# UC-001 — Password Spraying Detection

## 1. Use Case Information

- **Category:** Identity Security
- **Priority:** High
- **MITRE ATT&CK:** T1110.003 — Password Spraying
- **Tactic:** Credential Access
- **Data Sources:** Windows Security Logs, Domain Controller Logs, Identity Provider Logs
- **Primary Event:** Windows Security Event ID 4625
- **Related Event:** Windows Security Event ID 4624

## 2. Detection Objective

Identify a source that generates failed authentication attempts against multiple accounts within a limited period, potentially followed by a successful login.

## 3. Important IOCs

- Source IP address
- Number of distinct targeted accounts
- Failed authentication count
- Authentication failure reason
- Successful login after the suspicious activity
- Unusual logon type or target host

## 4. Splunk — Detect Password Spraying Candidates

```spl
index=windowslogs EventCode=4625
| bin _time span=10m
| stats count as failures
        dc(TargetUserName) as unique_users
        values(TargetUserName) as targeted_users
        by _time IpAddress
| where unique_users >= 5 AND failures >= 10
| sort - unique_users
```

### Query Explanation

- `EventCode=4625`: Select failed Windows logons.
- `bin _time span=10m`: Group events into 10-minute intervals.
- `count`: Count failed logons.
- `dc(TargetUserName)`: Count distinct targeted accounts.
- `by _time IpAddress`: Group activity by time window and source.
- `where`: Identify candidates using initial thresholds.

**Tuning:** The thresholds are illustrative. Adjust them to the organization's normal authentication patterns.

## 5. Splunk — Investigate Related Successful Logons

```spl
index=windowslogs (EventCode=4624 OR EventCode=4625)
| table _time host EventCode TargetUserName IpAddress LogonType
| sort _time
```

Use the suspicious source IP and targeted accounts from the first query to narrow this search.

Verify that any successful login occurred after the suspicious failures. Do not assume that events returned by an aggregate query are chronologically ordered.

## 6. Wireshark

For RDP-related traffic:

```wireshark
tcp.port == 3389
```

For SSH-related traffic:

```wireshark
tcp.port == 22
```

Network traffic may reveal connection patterns, but authentication results should be confirmed using the appropriate identity or host logs.

## 7. False Positives

- Vulnerability scanners
- Misconfigured applications
- Password changes not reflected in stored credentials
- Legitimate users repeatedly entering incorrect passwords
- Shared NAT addresses representing multiple users

## 8. Response

1. Validate the source and targeted accounts.
2. Check for successful authentication after the failures.
3. Review MFA and identity-provider logs.
4. Escalate suspected account compromise.
5. Follow approved procedures for account protection and session revocation.
6. Document the evidence and scope.

## 9. Success Criteria

The use case identifies suspicious authentication patterns and provides enough evidence for an analyst to determine whether the activity is malicious, legitimate, or inconclusive.
