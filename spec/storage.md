# Universal Mesh Core Persistence and Storage Specification

**Status:** Draft
**Version:** 0.1
**Document:** Storage, Persistence, and Recovery
**Project:** Universal Mesh Core, UMC
**Protocol:** Universal Mesh Protocol, UMP

---

# 1. Purpose

This document defines how UMC persists node state, how it protects secrets at rest, and how it recovers from crashes, corruption, and rollback.

It specifies:

* Storage architecture
* Storage abstraction
* State categories by sensitivity
* Database engine configuration
* Schema organization
* Schema versioning and migrations
* Keystore format
* Content-addressed object store
* Bundle object layout
* Crash consistency
* Write budgets
* Route-cache persistence
* Peer-store lifecycle
* Garbage collection
* Corruption detection and recovery
* Backups
* Restore behavior
* Restart behavior
* Storage quotas

Storage is a UMC implementation concern. It is not part of UMP interoperability. Independent implementations may persist state any way they choose as long as protocol behavior remains correct.

This document does not define:

* UMP wire format
* Cryptographic algorithms
* Application storage
* Log and telemetry retention beyond storage interaction
* Database internals of alternative backends

---

# 2. Requirements language

The terms `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, `MAY`, and `OPTIONAL` have their usual normative meanings.

All quantities use binary byte units:

```text
KiB = 1,024 bytes
MiB = 1,024 KiB
GiB = 1,024 MiB
```

---

# 3. Storage architecture

UMC uses a three-part storage architecture:

```text
SQLite database
    metadata and small records

Content-addressed object store
    large opaque bundle payloads

Protected keystore
    secret key material
```

## 3.1 SQLite

The default metadata backend is SQLite in:

```text
WAL mode
foreign keys enabled
explicit schema migrations
bounded transactions
```

## 3.2 Object store

Large opaque payloads are stored under content hashes:

```text
data/
└── objects/
    ├── ab/
    │   └── abcdef...
    └── f1/
        └── f12345...
```

SQLite records ownership, expiration, reference count, and policy for each object.

## 3.3 Keystore

Secret keys are not stored as ordinary plaintext SQLite fields.

The keystore uses:

1. Operating-system key storage where available.
2. Otherwise, an encrypted keystore protected by a user-provided secret or local machine credential.
3. A separate format and migration path from ordinary metadata.

## 3.4 Alternative backends

SQLite is the default implementation, not a protocol requirement.

Alternative backends MUST preserve the storage contract defined by the abstraction and the lifecycle rules in this document.

---

# 4. Terminology

## 4.1 Metadata record

A small structured record in the database.

## 4.2 Object

A large opaque payload stored by content address.

## 4.3 Object reference

A database record that owns a logical reference to an object.

## 4.4 Schema version

The version of the database schema, controlling migration compatibility.

## 4.5 Keystore

The protected store for secret key material.

## 4.6 Generation

A restore or backup generation binding to prevent rollback confusion.

---

# 5. Storage abstraction

The core SHOULD define a storage abstraction equivalent to:

```rust
trait Store {
    async fn get(&self, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn put(&self, namespace: &str, key: &[u8], value: &[u8]) -> Result<()>;
    async fn delete(&self, namespace: &str, key: &[u8]) -> Result<()>;
    async fn scan(&self, namespace: &str) -> Result<Box<dyn Iterator<Item = Entry>>>;
}
```

The abstraction MUST:

* Support namespaces for state categories
* Guarantee atomicity per operation
* Guarantee durability per operation according to the caller's durability class
* Propagate structured errors
* Support bounded scans
* Keep protocol-pure code independent of the concrete backend

---

# 6. State categories

Persistent state is divided by sensitivity.

## 6.1 Secret state

Includes:

```text
Identity signing private keys
Static handshake private keys
Ticket keys
Retry keys
Invitation secrets
Recovery keys
Local API credentials
```

Secret state MUST be encrypted at rest where the platform supports secure protection.

## 6.2 Trusted state

Includes:

```text
Known endpoint bindings
Delegation certificates
Revocations
Trust-on-first-use records
Peer introductions
Trust state records
Block list entries
```

Trusted state MUST be integrity-protected and validated on read.

## 6.3 Operational state

Includes:

```text
Peer hints
Route cache
Link history
Bundle metadata
Resumption tickets
Carrier metrics
Persisted abuse counters
```

Operational state MAY be rebuilt or expired without identity loss.

## 6.4 Disposable state

Includes:

```text
Temporary diagnostics
Cached route failures
Expired packet history
Short-term replay filters
```

Disposable state MAY be deleted without identity loss.

---

# 7. Database engine configuration

The default SQLite backend MUST use:

```text
journal_mode = WAL
synchronous = FULL for critical transactions, NORMAL where policy permits
foreign_keys = ON
busy_timeout = bounded
```

The backend MUST:

* Support one concurrent writer
* Support concurrent readers during writes
* Bound transaction size and duration
* Use prepared statements
* Reject unauthenticated network input that triggers immediate durable writes per packet
* Batch compatible operational writes within durability requirements

---

# 8. Schema organization

The database contains records for:

```text
Schema version
Node configuration
Endpoint metadata
Identity bindings
Trust records
TOFU records
Introductions
Revocations
Delegation certificates
Block list entries
Peer hints
Peer-store lifecycle state
Route cache
Failure history
Resumption-ticket metadata
Bundle metadata
Object references
Carrier configuration
Local API permissions and grant records
Persisted quotas and abuse counters
Audit records
```

## 8.1 Table grouping

Tables SHOULD be grouped by state category:

```text
secret_*      (key metadata, never key material)
trust_*       (bindings, TOFU, introductions, revocations, blocks)
peer_*        (hints, lifecycle)
route_*       (cache, failure history)
bundle_*      (metadata, object references)
config_*      (node and carrier configuration)
api_*         (permissions, grants, audit)
```

## 8.2 Foreign keys

Records that reference objects, endpoints, or each other MUST use foreign keys with defined cascade or restrict behavior.

Deleting an endpoint MUST report or handle:

```text
Dependent listeners
Sessions metadata
Trust records
Bundles owned or addressed to it
```

---

# 9. Schema versioning and migrations

## 9.1 Schema version

The database MUST store an explicit schema version.

The schema version:

* Controls persisted-state compatibility
* Appears in the release manifest
* MUST be validated at startup
* MUST be part of backup and restore validation

## 9.2 Migration rules

Migrations MUST:

* Be explicit, ordered, and idempotent
* Run inside bounded transactions
* Support upgrade and downgrade plans where applicable
* Validate the starting schema version
* Refuse to run against an unknown or newer version
* Produce a structured error on failure
* Preserve secret state independently of metadata migrations

A migration MUST NOT:

* Run automatically without a validated backup path where destructive
* Reuse nonce, packet-number, or cryptographic state
* Weaken trust or revocation records

## 9.3 Migration safety

Before a migration, the node SHOULD:

* Check available storage reserve
* Stage a compact backup when the migration is destructive
* Verify object-store consistency after object-layout migrations

---

# 10. Keystore format

## 10.1 Placement

Secret key material MUST NOT be stored as plaintext SQLite fields.

The keystore MUST be:

* A separate format from ordinary metadata
* Protected by OS key storage where available
* Otherwise encrypted with a strong user-provided secret or local machine credential
* Derived with a memory-hard KDF when password-derived

## 10.2 Contents

The keystore holds:

```text
Identity signing private keys
Static handshake private keys
Ticket encryption keys
Retry keys
Invitation secrets
Recovery keys
Local API bearer-token records
```

## 10.3 Keystore records

Each keystore record contains:

```text
Record version
Key identifier
Key class
Key material (encrypted)
Key metadata (non-secret)
Integrity tag
```

## 10.4 Integrity

The keystore MUST:

* Validate its integrity before use
* Fail closed on corruption
* Never allow metadata database corruption to alter key material
* Support rotation of the keystore protection secret
* Zeroize plaintext key material in memory where supported

## 10.5 Keystore migration

A keystore format change MUST have:

* Its own migration path
* Its own versioning
* A documented failure mode

Keystore migration MUST NOT depend on database schema migration order.

---

# 11. Content-addressed object store

## 11.1 Object identity

An object's identity is its content hash:

```text
ObjectID = BLAKE2s-256(object_bytes)
```

## 11.2 Layout

Objects are stored under a two-level hash directory:

```text
data/objects/<first 2 hex>/<full ObjectID hex>
```

The layout MUST:

* Bound directory fan-out
* Support atomic write via temporary file and rename
* Validate the stored hash on read
* Reject mismatched or truncated files

## 11.3 Object references

SQLite records ownership of each object:

```text
ObjectID
Owner scope
Reference count
Expiration
Policy flags
Creation time
Last access time
```

A logical reference MUST NOT be created before the object write commits.

## 11.4 Deduplication

Content addressing deduplicates identical payloads.

Physical bytes are charged once.

Logical references are charged to each owner quota.

---

# 12. Bundle object layout

## 12.1 Bundle metadata

Bundle metadata in SQLite includes:

```text
Bundle ID
ObjectID
Owner endpoint
Sender scope
Destination hint
Size
Priority
Creation time
Expiration time
Replication count
Custody state
Delivery state
Reference count
Policy flags
```

## 12.2 Bundle payload

The bundle payload is one content-addressed object.

Bundle limits from `resource-limits.md`:

```text
Maximum bundle: 16 MiB
Maximum lifetime: 7 days
Default lifetime: 24 hours
Maximum replication count: 8
```

## 12.3 Write path

A bundle write MUST:

1. Validate size and quota before allocation.
2. Write the object to a temporary file.
3. Validate the written bytes and hash.
4. Rename the object into place.
5. Commit the bundle metadata transaction.
6. Report success only after commit.

A failed write MUST NOT leave a committed metadata reference.

## 12.4 Read path

A bundle read MUST:

* Look up the metadata record
* Verify the object exists and its hash matches
* Return a structured error when the object is missing or corrupt

---

# 13. Crash consistency

## 13.1 Principles

UMC MUST:

* Use transactions for all metadata changes
* Use WAL or equivalent crash-safe journaling
* Order object writes before metadata commits
* Never persist live session cryptographic state
* Never persist packet numbers, traffic keys, or replay windows

## 13.2 Session state

Live session state is ephemeral.

After restart, the node MUST NOT reconstruct a live session from persisted state.

The node MAY persist:

```text
Resumption-ticket metadata
Diagnostic counters
Application state owned by applications
```

## 13.3 Shutdown

On shutdown, the node SHOULD:

* Stop accepting new writes
* Flush critical state
* Persist bundle metadata
* Close the database cleanly
* Erase ephemeral secrets
* Exit within a bounded time

## 13.4 Crash detection

At startup, the node MUST detect:

* Unclean shutdown
* Failed migration
* Incomplete object writes
* Keystore integrity failure
* Schema-version mismatch

Recovery actions MUST be explicit and structured.

---

# 14. Write budgets

Default database write budgets from `resource-limits.md`:

```text
Concurrent write transactions: 1
Queued write operations: 10,000
Queued write bytes: 64 MiB
Single ordinary transaction: 16 MiB
Single migration transaction: explicit migration limit
Transaction wall deadline: 5 seconds for ordinary writes
```

The backend MUST:

* Batch compatible operational writes
* Preserve trust, revocation, and accepted bundle metadata over disposable writes under pressure
* Drop disposable metrics and route updates first when queues fill
* Never allow unbounded write queues

---

# 15. Route-cache persistence

## 15.1 Persisted records

The node MAY persist route-cache metadata.

Persisted route records MUST separate:

```text
Private routing hints
Public bootstrap data
Trust records
Failure history
```

## 15.2 Restart behavior

After restart, every persisted route MUST begin as `CANDIDATE`.

The node MUST revalidate:

* Live next-hop state
* Authorization state
* Carrier availability
* Protocol-version compatibility

## 15.3 Expiry and decay

Persisted failure penalties SHOULD decay.

A stale failure MUST NOT block rediscovery forever.

The node MUST purge routes affected by:

* Revocation
* Blocked peers
* Removed carriers
* Incompatible protocol versions

## 15.4 Privacy

Private routing records MUST be:

* Partitioned by local identity and policy
* Encrypted at rest where platform support exists
* Expired with their request and reverse-path state
* Deleted after trust revocation or peer removal

Metrics and backups MUST NOT recreate a permanent global topology log by default.

---

# 16. Peer-store lifecycle

## 16.1 Peer records

Peer records include:

```text
Peer classes (PINNED, ACTIVE, TRUSTED, INTRODUCED, SUCCESSFUL, OBSERVED, STALE)
Carrier hints
Introduction sources
Last successful contact
Last failure
Expiration
Sharing policy
Trust state reference
Capabilities
```

## 16.2 Lifecycle

A peer record:

* Is created from an authenticated observation, hint, or introduction
* Expires when its evidence expires
* Is revalidated before use
* Is evicted by the peer-store bounds from `resource-limits.md`
* MUST NOT be interpreted as identity trust

## 16.3 Eviction

Eviction removes expired and stale records before active, pinned, or trusted records.

Trust does not bypass the global peer-record hard limit.

## 16.4 Persistence

Peer records MAY persist across restart.

After restart:

* Trust state is restored from trust records
* Operational peer hints begin as candidates
* Sharing policy is preserved

---

# 17. Bundle metadata lifecycle

Bundle records follow the bundle policy from `resource-limits.md`:

```text
Bundle storage: profile quota
Bundles per sender: 1,000
Storage per Observed sender: 16 MiB
Storage per Introduced sender: 128 MiB
Storage per Trusted sender: 512 MiB
```

## 17.1 Admission

Before accepting a bundle, the node MUST validate:

* Declared size against configured limits
* Remaining storage quota
* Sender scope and trust
* Priority and expiration
* Replication count

A `BUNDLE` frame MUST NOT force immediate allocation of the declared payload size without validating configured limits.

## 17.2 Expiration

A bundle expires at the earliest of:

* Its expiration time
* Policy invalidation
* Owner or sender revocation

Expired bundle metadata and objects are eligible for garbage collection.

## 17.3 Custody

The node MUST preserve custody commitments according to the bundle profile, or refuse custody before acceptance.

---

# 18. Garbage collection

## 18.1 Object collection

The node MUST collect objects with:

* Zero reference count
* Expired metadata
* Invalid or orphaned references

Garbage collection MUST:

* Batch deletions
* Budget CPU and database work
* Verify references before deletion
* Handle concurrent readers

## 18.2 Bundle eviction order

Bundle eviction order:

1. Expired bundles.
2. Invalid or orphaned objects.
3. Delivered bundles past receipt-retention policy.
4. Unauthenticated or Observed-sender bundles.
5. Lowest priority.
6. Highest replication count.
7. Largest remaining storage cost.
8. Oldest eligible bundle.

## 18.3 Startup collection

The node SHOULD run bounded garbage collection at startup after validation.

---

# 19. Corruption detection and recovery

## 19.1 Detection

The node MUST detect:

* Schema-version mismatch
* Truncated or corrupted records
* Invalid lengths and types
* Hash mismatches for content-addressed objects
* Missing object references
* Conflicting references
* Keystore integrity failure

## 19.2 Validation on read

The node MUST validate on read:

* Record versions
* Field lengths
* Cryptographic records (signatures, hashes, tags)
* Reference integrity

## 19.3 Failure behavior

Corruption handling MUST:

* Fail closed for secret or trusted state
* Never reuse keys, nonces, or packet numbers from corrupted state
* Never resume live sessions from corrupted state
* Report structured errors with recovery guidance
* Preserve auditable evidence of the failure

## 19.4 Recovery

Recovery options:

* Rebuild disposable and operational state
* Restore from a validated backup
* Re-import identity from protected export
* Reset trust state under explicit authorization

A corrupted database MUST NOT be silently repaired in a way that weakens trust or cryptographic guarantees.

---

# 20. Backups

## 20.1 Backup contents

A UMC-created backup SHOULD include:

```text
Metadata database (validated)
Object store (validated hashes)
Keystore export (encrypted)
Schema version
Generation identifier
Creation time
```

## 20.2 Generation binding

A backup MUST be bound to:

```text
Node identity
Storage generation
Creation time
Backup format version
Integrity manifest
```

## 20.3 Backup protection

Backups:

* MUST protect secret material with keystore encryption
* MUST NOT be loadable without restore authorization
* SHOULD be encrypted as a unit where platform support exists
* MUST include trust state for continuity

## 20.4 Quota

Backups created by UMC count against the persistent operational storage quota.

---

# 21. Restore behavior

## 21.1 Restore workflow

A restore MUST:

1. Parse the backup as hostile input.
2. Validate format version, generation, and integrity manifest.
3. Verify hashes of database and objects.
4. Stage into an isolated location.
5. Validate schema and references.
6. Require explicit authorization.
7. Swap state only after validation succeeds.

## 21.2 Rejections

A restore MUST reject:

* Unknown backup format
* Wrong node identity
* Invalid signatures or hashes
* Missing objects
* Path traversal or unsafe file names
* Schema-version mismatch
* Rollback beyond accepted generation policy

## 21.3 Post-restore actions

After restore, the node SHOULD:

* Rotate ticket and Retry keys
* Invalidate replay-sensitive operational state
* Recalculate storage quotas from validated state
* Warn when trust or revocation state may be stale
* Record an audit event

## 21.4 Restore and rollback

A restore of an older snapshot MAY resurrect stale trust, invitations, or bindings.

The node MUST:

* Detect sequence regression where platform counters permit
* Warn the operator
* Refuse restoration of live session state

---

# 22. Restart behavior

After restart, the node MUST:

1. Validate the keystore.
2. Validate the database schema.
3. Run pending migrations.
4. Validate trust and revocation records.
5. Restore trust state.
6. Revalidate persisted routes as `CANDIDATE`.
7. Recalculate storage quotas.
8. Run bounded garbage collection.
9. Resume operation without restored live sessions.

The node MUST NOT:

* Resume live sessions
* Restore replay windows
* Restore packet numbers
* Trust persisted routing state without revalidation

---

# 23. Storage quotas

## 23.1 Persistent operational storage

Profile defaults from `resource-limits.md`:

```text
constrained: 512 MiB
standard:    4 GiB
relay:       16 GiB
```

## 23.2 Reserved capacity

Secret and trust records receive reserved space.

The standard profile reserves:

```text
64 MiB of free database and filesystem budget for critical transactions
```

Bundle or diagnostic growth MUST NOT prevent a critical trust or schema transaction.

When the reserve is unavailable, the node:

* Enters `EMERGENCY` pressure
* Rejects new persistent work
* Reports storage failure

## 23.3 Quota accounting

Storage quotas MUST account:

```text
Peer and route database
Trust and revocation records
Resumption tickets
Diagnostics
Bundle metadata
Content-addressed objects
Temporary migrations
Backups created by UMC
```

Quotas are recalculated from validated database and object state after restart.

---

# 24. Persisted counters

## 24.1 Abuse counters

Token buckets and abuse counters MAY persist across restart when policy needs resistance to restart evasion.

Persisted accounting MUST:

* Have bounded cardinality
* Include expiry
* Validate schema and values
* Avoid wall-clock extension after rollback
* Exclude packet-level and live-session reservations

## 24.2 Live reservations

Memory, handle, queue, and operation reservations reset after restart.

Live reservations MUST NOT be persisted.

---

# 25. Control API surface

Storage-related Control API operations:

```text
NodeAdmin.GetStatus
NodeAdmin.GetResourceUsage
DiagnosticsService.RunDoctor
IdentityService.ImportIdentity
```

Backup and restore API placement remains an open decision.

The daemon MUST redact:

* Keystore paths where sensitive
* Key identifiers
* Backup secrets

---

# 26. Security considerations

## 26.1 Corruption and key reuse

Corruption MUST NOT cause nonce, packet-number, or key reuse.

The keystore and metadata database are independent failure domains.

## 26.2 Rollback

Offline rollback may resurrect stale trust.

Sequence checks, generation binding, and post-restore key rotation limit damage.

## 26.3 Malicious import

Imports and restores are hostile input.

Every file and archive MUST pass size, path, signature, hash, and ownership validation before staged application.

## 26.4 Object store attacks

Attacker-controlled files must not become objects.

Hash validation on every read prevents substitution.

## 26.5 Disk exhaustion

Quotas and the critical reserve prevent trust transactions from failing due to bundle or log growth.

Filesystem exhaustion outside UMC may still remove the reserve.

## 26.6 Logging

Storage logs MUST NOT contain:

* Key material
* Plaintext bundle payloads
* Full private peer tables
* Full resumption tickets
* Backup secrets

---

# 27. Required tests

A compliant implementation MUST test:

1. Schema version validation and migration order.
2. Migration failure and rollback.
3. Keystore integrity failure and fail-closed behavior.
4. Object hash validation on read.
5. Bundle write ordering (object before metadata).
6. Failed bundle write leaving no committed reference.
7. Crash during transaction, object write, and migration.
8. WAL recovery after unclean shutdown.
9. Concurrent readers during writes.
10. Write-queue saturation preserving trust records.
11. Route-cache revalidation after restart.
12. Peer-store eviction order and bounds.
13. Bundle eviction order.
14. Garbage collection with concurrent readers.
15. Orphan object detection.
16. Backup creation and validation.
17. Hostile restore rejection.
18. Restore with missing objects.
19. Post-restore key rotation.
20. Rollback detection and stale-state warning.
21. Quota recalculation after restart.
22. Reserved capacity protection under bundle fill.
23. Disposable state deletion without identity loss.
24. Persisted abuse counters with bounded cardinality.
25. Fuzzing of database recovery and import logic.

Property tests SHOULD verify:

```text
Every committed metadata reference has a valid object.
No object is deleted while referenced.
Object writes commit before their metadata.
Restore never resumes live session state.
Trust and revocation records survive restart.
Corruption never leads to key or nonce reuse.
Storage usage never exceeds configured quotas.
```

---

# 28. Minimal v0.1 compliance

A compliant UMC v0.1 implementation MUST support:

* SQLite metadata database in WAL mode
* Explicit schema version
* Ordered idempotent migrations
* Protected keystore separated from metadata
* Content-addressed bundle objects
* Bundle metadata lifecycle
* Bounded transactions
* Crash consistency without live-session restoration
* Route-cache revalidation
* Trust-state persistence
* Storage quotas and reserved capacity
* Garbage collection
* Backup creation with integrity manifest
* Staged, validated restore
* Corruption detection and fail-closed behavior

An implementation MAY defer:

* Automated rollback detection on all platforms
* Encrypted whole-backup units
* Alternative storage backends
* Diagnostic persistence

---

# 29. Open design decisions

The project must resolve these items before stable v0.1:

1. Exact SQLite schema and table layout.
2. Exact keystore file format and KDF parameters.
3. Backup format and archive layout.
4. Backup and restore API placement in the Control API.
5. Migration downgrade policy.
6. Rollback-detection anchor per platform.
7. Whether diagnostics persist in the database or filesystem.
8. Audit-record retention and storage.
9. Object-store fsync policy.
10. Whether bundle objects are encrypted at rest.
11. Exact reserved-capacity values per profile.
12. Whether route cache persists by default.
13. Peer-store persistence granularity.
14. Content-addressed object store directory layout versioning.
15. Whether config is stored in the database or separate files.
16. Keystore unlock workflow and re-lock behavior.
17. Backup scheduling and rotation policy.
18. Restore authorization flow.
19. Crash-recovery self-check scope.
20. Storage schema compatibility windows per release.

---

# 30. Recommended implementation order

Implement storage in this order:

1. Storage trait and namespaces.
2. SQLite connection and WAL configuration.
3. Schema versioning.
4. Migration runner.
5. Keystore with OS integration.
6. Metadata records for trust and identity.
7. Config persistence.
8. Peer-store records.
9. Route-cache records.
10. Content-addressed object store.
11. Bundle metadata lifecycle.
12. Write budgets and batching.
13. Crash consistency and recovery.
14. Garbage collection.
15. Quotas and reserved capacity.
16. Corruption detection.
17. Backups.
18. Staged restore.
19. Post-restore key rotation.
20. Fuzzing and failure-injection tests.

---

# 31. Core rule

UMC persists secrets, trust, operational hints, and disposable state in separate, appropriately protected stores with one explicit schema version and ordered migrations.

Object writes commit before their metadata. Live sessions never persist. Corruption fails closed and never reuses cryptographic state. Backups bind to generations, restores stage and validate before applying, and every restart revalidates what persisted state may safely become usable again.
