# Security operations drills

`scripts/security-operations-drill.sh` runs the ten required v0.1 security
process exercises from `spec/security-operations.md` without using production
credentials, publishing to a real channel, or changing release trust state.
It writes a machine-readable `drill-report.json` plus redacted evidence files;
each artifact is SHA-256 hashed by the report.

Run locally with:

```sh
bash scripts/security-operations-drill.sh security-operations-drill
```

The harness exercises:

1. Vulnerability report intake and tracking ID assignment.
2. Private-list embargo coordination with the project owner.
3. Advisory publication schema and timeline validation.
4. Release-signature revocation, including tamper rejection.
5. Single-operator emergency signing-key rotation using an ephemeral test key.
6. Locked dependency metadata, SBOM, and reachability assessment records.
7. Cryptographic deprecation/migration policy and vector presence.
8. Emergency protocol, crypto-profile, and carrier disablement tests.
9. Public-relay containment and surviving/invalidated state recording.
10. Postmortem root-cause, owner, regression, and follow-up tracking.

The generated evidence is suitable for CI retention. It deliberately does not
claim that a real security contact or advisory channel has been published;
those remain operator setup actions. No council or multi-person ceremony is
required for the solo-maintainer v0.1 release policy.
