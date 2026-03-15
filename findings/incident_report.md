# Incident Report

## Executive Summary

Analysis of sample Apache access logs and Linux authentication logs identified multiple indicators of suspicious activity, including:

- repeated SSH login failures from external IP addresses
- a successful login following repeated failures against the same account
- web requests consistent with path probing and SQL injection-style behavior
- suspicious input resembling cross-site scripting (XSS)

## Key Findings

### 1. Suspected Brute Force Activity
The IP address `45.83.64.22` generated multiple failed SSH login attempts against user accounts and was later associated with a successful login for the account `dante`.

This sequence is suspicious because it may indicate credential guessing followed by account access.

### 2. Additional SSH Password Guessing
The IP address `203.0.113.200` generated repeated failed login attempts for the invalid user `test`, consistent with low-volume brute-force or username enumeration activity.

### 3. Web Application Probing
The IP address `185.220.101.5` requested several sensitive or commonly abused paths:

- `/wp-login.php`
- `/phpmyadmin`
- `/.env`

This pattern is consistent with opportunistic probing for exposed services or credentials.

### 4. Suspicious Injection-Like Request
The IP address `103.44.21.9` requested a URL containing `UNION SELECT`, which is commonly associated with SQL injection attempts.

### 5. Suspicious Script Injection Pattern
The IP address `192.0.2.123` submitted a request containing `<script>alert(1)</script>`, which resembles a basic reflected XSS test payload.

## Impact Assessment

Based on the available sample data, the highest-priority event is the SSH activity from `45.83.64.22` because the successful authentication occurred after repeated failed attempts.

## Recommended Response Actions

1. Investigate the account `dante` for unauthorized access
2. Reset credentials and review MFA coverage if applicable
3. Block or monitor the identified IP addresses
4. Review web server and application logs for follow-on activity
5. Search for related activity across endpoint, identity, and firewall telemetry
6. Tune detections for brute-force behavior and suspicious web requests

## MITRE ATT&CK Mapping

- T1110 - Brute Force
- T1078 - Valid Accounts
- T1190 - Exploit Public-Facing Application
