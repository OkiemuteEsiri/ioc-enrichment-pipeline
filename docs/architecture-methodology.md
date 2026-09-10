# Architecture and Methodology

## Purpose

This lab demonstrates a defensive, provider-neutral IOC enrichment workflow using only local synthetic intelligence. It does not query reputation services, block infrastructure, scan targets, or assert that an indicator is malicious solely because it appears in a feed.

## Pipeline

`raw indicator -> schema validation -> normalization -> deduplication -> local intelligence correlation -> contextual scoring -> priority -> analyst review`

Supported indicator types are IPv4, domain and SHA-256. Normalization produces stable correlation keys and prevents case-format duplicates from inflating workload. Malformed values fail closed.

## Scoring

The bounded 0–100 score combines source confidence, number of independent intelligence matches, malicious-vote count, indicator age and prevalence. Low prevalence increases investigative priority because rare infrastructure/artifacts can be more useful for triage. Scores map to P0-P3 queues; they are prioritization aids, not automated verdicts.

## ATT&CK context

Synthetic fixtures demonstrate contextual mappings including T1071.001 (Web Protocols), T1566.002 (Spearphishing Link) and T1204.002 (Malicious File). ATT&CK mappings describe plausible analyst context only and are not evidence that the technique occurred.

## Analyst validation

Before escalation, validate telemetry provenance, timestamp scope, asset/user context, indicator freshness, legitimate business use, prevalence and corroborating evidence. Suppression should be documented and time-bounded rather than deleting the underlying observation.

## Remediation / response

A confirmed malicious indicator can inform containment, blocking, hunting and incident scoping through approved organizational processes. Revalidation should confirm the indicator no longer appears where it should be blocked and that compensating controls remain effective. This public lab intentionally contains no live blocking or response automation.

## Limitations

Synthetic/local intelligence cannot reproduce provider latency, feed quality, API quotas, false-positive dynamics or production-scale correlation. The project therefore demonstrates engineering and decision logic rather than claiming operational threat-intelligence coverage.
