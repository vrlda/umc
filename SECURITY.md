# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest maintained release line | Yes |
| Older release lines | No |

Security fixes land on `main` first and may be backported to maintained release
lines when practical.

OpenMesh treats privacy, traffic-analysis resistance, operator safety, and
censorship resistance as core security concerns.

## Reporting a vulnerability

Please do not report vulnerabilities in public issues, discussions, commits,
or pull requests.

Preferred path:

1. Use GitHub Private Vulnerability Reporting on the repository's Security tab.

Fallback path if private reporting is not yet enabled:

1. Contact the maintainers through a private channel listed in the repository
   profile or project website.
2. Share only the minimum details needed to reproduce and triage the issue.

Include the following when possible:

- affected area or component
- impact and attack scenario
- reproduction steps or proof of concept
- any logs or traces with secrets and personal data removed
- whether the issue could affect privacy, traffic analysis resistance,
  operator safety, or censorship resistance

## What to expect

- Initial acknowledgment target: within 72 hours
- Initial triage target: within 7 days
- Coordinated disclosure preferred after a fix or mitigation is available

## Scope examples

Examples of issues we especially want reported privately:

- deanonymization or traffic-correlation weaknesses
- transport fingerprinting or active-probe bypasses
- key handling or identity compromise
- relay, exit, or policy bypass issues
- logging, data retention, or metadata leaks
- mobile or desktop privilege misuse
