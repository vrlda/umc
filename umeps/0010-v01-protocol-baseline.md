# UMEP-0010: UMP/1 v0.1 Protocol Baseline

- **Status:** Draft
- **Category:** Standards Track
- **Requires:** UMEP-0001

## Summary

This UMEP records identifier and encoding decisions made while the v0.1
specification suite and implementation were developed. It is a review index,
not a production-stability claim.

The baseline currently records:

- 16-byte request identifiers;
- 62-bit random circuit identifiers;
- the provisional `RELAY_STATUS` type `0x82`;
- carrier identifiers `ump.tcp/1`, `ump.udp/1`, `ump.lan-discovery/1`, and
  `ump.tls-stream/1`;
- domain labels `UMP-BUNDLE-ID-v1`, `UMP-INVITE-AUTH-v1`, `UMP-ROTATION-v1`,
  `UMP-REVOCATION-v1`, and `UMP-BOOTSTRAP-v1`;
- the provisional InitialSalt and header-protection constructions documented
  by the wire and handshake specifications.

## Wire-format impact

`RELAY_STATUS` (`0x82`) must be added to the normative wire-format registry
before the interoperation freeze. The current implementation and fixtures
must be treated as provisional until that registry update and independent
vectors are reviewed.

## Compatibility

All entries remain provisional until the interoperation freeze. This UMEP does
not promote the TLS carrier, plugin boundary, handshake composition, or any
privacy profile to a stable production guarantee.

## Review record

Protocol changes that alter these identifiers, labels, packet classes, or
cryptographic constructions require a follow-up UMEP or an amendment reviewed
under [`umeps/0001-process.md`](0001-process.md). Release owners should link
the accepted amendment from the rendered release manifest.
