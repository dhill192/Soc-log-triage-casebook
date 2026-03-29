# SOC Log Triage Casebook

A Node.js cybersecurity portfolio project focused on reviewing, classifying, and organizing suspicious log events in a Tier 1 SOC-style workflow.

## Overview

This project simulates the first-pass triage process a SOC analyst might perform when reviewing authentication and web-related log activity.

The goal is to examine raw log entries, identify suspicious patterns, separate likely benign activity from events that may require escalation, and organize the results into a clearer investigation workflow.

## What This Project Does

The project is designed to:

- review raw Apache access logs and authentication logs
- parse useful fields from each event
- identify suspicious request patterns and authentication abuse
- classify findings for easier review
- support a basic triage-and-escalation workflow

## Analyst Workflow Simulated

This project reflects a simple Tier 1 SOC process:

1. Review raw log entries
2. Extract relevant details
3. Identify unusual or repeated behavior
4. Classify findings by type and severity
5. Prepare results for further review or escalation

## Example Detections

This repo includes logic for identifying:

- suspicious web requests
- repeated failed login attempts
- brute-force candidates
- successful logins after repeated failures
- suspicious IPs appearing across multiple findings

## Output

The script writes results to:

- `output/analysis.json`

The output includes:

- suspicious web events
- brute-force candidates
- successful logins
- suspicious success-after-failure events
- a consolidated IOC list of suspicious IPs

## Skills Demonstrated

- Security event triage
- Log review and classification
- Basic detection logic for web and authentication activity
- Organizing findings for investigation
- JavaScript and Node.js scripting for security workflows

## Tech Stack

- Node.js
- JavaScript
- Log parsing
- Rule-based analysis
- JSON output generation

## Why I Built It

I built this project to practice the kind of first-pass thinking expected in an entry-level SOC role: reading logs carefully, identifying suspicious behavior, and turning raw events into findings that are easier to review and escalate.

## Current Limitations

This is a portfolio project built around sample data and rule-based logic. It is not a production detection engine and does not replace SIEM correlation, alert enrichment, or deeper incident investigation.

## Possible Next Steps

- severity tuning
- better event grouping
- expanded log-source support
- CSV export
- simple enrichment or scoring

## Note

This project is part of my cybersecurity portfolio as I prepare for a Tier 1 SOC Analyst role.
