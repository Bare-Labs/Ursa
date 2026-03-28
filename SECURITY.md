# Security Policy

Ursa is offensive-security software. Treat governance, approval, audit, and access-control behavior as first-class security requirements.

## Reporting

Report vulnerabilities privately with:

- affected subsystem
- operator or target impact
- reproduction steps
- expected versus actual approval, auth, or audit behavior

## Baseline Expectations

- High-risk workflows must stay approval-gated and auditable.
- Secrets, tokens, payload credentials, and real operator data must never be committed.
- Deployment and public-surface changes must update `README.md` and `BLINK.md`.
