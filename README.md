# IOC Enrichment Pipeline

A defensive Threat Intelligence, Detection Engineering and Incident Response portfolio project that demonstrates how heterogeneous indicators can be normalized, correlated with intelligence context and prioritized for analyst review without turning reputation data into an automatic compromise verdict.

## Problem statement

SOC and incident-response teams routinely receive IP addresses, domains and file hashes from endpoint, email, network and intelligence sources. Raw IOC volume creates duplicate work and weak prioritization when indicators are treated equally. This project models a repeatable enrichment pipeline that validates indicator syntax, normalizes identity, deduplicates observations, correlates local intelligence context and produces an explainable P0-P3 queue.

## Architecture

```text
Synthetic IOC sources
       |
       v
Validation + normalization
       |
       v
Deduplication / stable identity
       |
       v
Local intelligence correlation
       |
       v
Explainable 0-100 scoring
       |
       v
P0-P3 analyst queue
       |
       v
Triage -> response -> revalidation
```

## Implemented capabilities

- IPv4, domain and SHA-256 validation
- canonical domain/hash normalization
- deterministic deduplication
- source-confidence preservation
- intelligence-match and malicious-vote context
- age and prevalence context
- bounded explainable risk scoring
- deterministic finding identifiers
- P0-P3 prioritization
- MITRE ATT&CK contextual mappings
- realistic synthetic fixtures
- unit tests for validation, normalization, deduplication and scoring

## Repository structure

```text
src/pipeline.py                    core models, validation, correlation and scoring
data/synthetic_intelligence.json   synthetic IOC + intelligence fixtures
tests/test_pipeline.py             unit tests
docs/architecture-methodology.md   engineering and analyst methodology
README.md                           recruiter-facing project overview
```

## Scoring design

The score combines source confidence, independent intelligence matches, malicious-vote count, age and prevalence. Each contribution is capped and the final score is bounded at 100. P0/P1 results are intended to move to analyst review faster; the score is not a malware verdict and is not evidence of compromise.

## MITRE ATT&CK context

Synthetic examples include T1071.001 (Web Protocols), T1566.002 (Spearphishing Link) and T1204.002 (Malicious File). Mappings provide investigation context only. Detection of an IOC does not prove the mapped technique occurred.

## Testing

The unit suite covers malformed indicators, confidence bounds, canonical normalization, duplicate collapse, contextual score ordering, score bounds, stable finding IDs and ATT&CK-technique deduplication.

Run locally with:

```bash
python -m unittest discover -s tests -v
```

## Remediation and validation workflow

1. Validate IOC provenance and freshness.
2. Correlate with endpoint/network/email context.
3. Determine whether legitimate business activity explains the observation.
4. Escalate confirmed/high-confidence cases through approved IR processes.
5. Apply blocking or containment only through authorized production controls.
6. Re-query approved telemetry to validate that exposure/activity has stopped.
7. Record false positives and time-bounded suppressions without deleting evidence.

## Skills demonstrated

Threat-intelligence engineering, IOC normalization, defensive data modeling, correlation logic, explainable risk scoring, SOC prioritization, incident-response decision support, ATT&CK contextualization, Python unit testing and security documentation.

## Limitations

This repository deliberately uses synthetic local intelligence. It does not call commercial reputation APIs, perform live DNS/network lookups, block indicators, scan systems, ingest confidential telemetry, or claim production-scale detection coverage.

## Roadmap

- provider adapter interfaces with mocked fixtures
- STIX/TAXII-compatible serialization
- indicator expiration/decay model
- analyst disposition lifecycle
- batch CLI and Markdown/JSON reporting
- CI security-quality gate

## Safety

All data is synthetic. No credentials, customer/employer data, production targets, malware, exploit payloads, credential theft, live blocking or offensive infrastructure are included.
