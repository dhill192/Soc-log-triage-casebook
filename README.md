# SOC Log Triage Casebook

A Node.js cybersecurity portfolio project focused on reviewing, classifying, and organizing suspicious log events in a Tier 1 SOC-style workflow.

## Overview

This project simulates the first-pass triage process a SOC analyst might perform when reviewing authentication or system-related log activity.

Instead of treating every event the same, the goal is to examine raw log entries, identify suspicious patterns, separate likely benign activity from events that may require escalation, and organize the results into a clearer investigation workflow.

## What This Project Does

The project is designed to:

- review raw log entries from sample data
- parse useful fields from each event
- identify patterns associated with suspicious behavior
- classify findings for easier review
- support a basic triage-and-escalation workflow

## Analyst Workflow Simulated

This project reflects a simple Tier 1 SOC process:

1. Review raw log entries
2. Extract relevant details
3. Identify unusual or repeated behavior
4. Classify findings by type or severity
5. Prepare results for further review or escalation

## Example Use Cases

This repo is intended to reflect tasks such as:

- failed login review
- repeated authentication attempts
- suspicious source behavior
- initial alert validation
- separating likely noise from events worth deeper investigation

## Skills Demonstrated

- Security event triage
- Log review and classification
- Recognizing suspicious patterns in authentication or system logs
- Organizing findings clearly for investigation
- JavaScript and Node.js scripting for security workflows

## Tech Stack

- Node.js
- JavaScript
- Log parsing
- Rule-based analysis

## Why I Built It

I built this project to practice the kind of first-pass thinking expected in an entry-level SOC role: reading logs carefully, identifying suspicious behavior, and turning raw events into findings that are easier to review and escalate.

## Current Limitations

This is a portfolio project built around sample data and rule-based logic. It is not a production detection engine and does not replace SIEM correlation, alert enrichment, or deeper incident investigation.

## Possible Next Steps

- severity tagging
- CSV or JSON export improvements
- better event grouping
- simple alert scoring
- expanded log-source support

## Note

This project is part of my cybersecurity portfolio as I prepare for a Tier 1 SOC Analyst role.
