# Plugin Security Model

Status: bounded v0.1 closeout — capability enforcement and generation-scoped
supervision are enforced at the `PluginContext`/registry boundary. Applies to
`crates/umc-plugin`.

## Trust model

The v0.1 implementation profile does not advertise or load external carrier
processes. The registry accepts only trusted, compiled-in `Plugin` hooks; this
is an explicit scope decision, not a claim of sandboxing. Capability
enforcement is defense in depth: a plugin granted no capabilities still runs
in the daemon's address space, so loading native plugin code remains a trust
decision.

The daemon-side `PluginSupervisor` is transport-independent and is the stable
contract for a future subprocess loader. It gives each launch a fresh
generation, rejects work before quota growth, invalidates permits, handles, and
shared-memory reservations on failure, applies bounded restart backoff, and
disables a plugin after the configured restart burst. The current registry
uses the same lifecycle transitions for init and shutdown failures.

## Capabilities (closed set)

| Capability | Manifest string | Grants |
|---|---|---|
| NetworkListen | `network.listen` | Bind/listen on a network address |
| NetworkDial | `network.dial` | Open outbound connections |
| StorageRead | `storage.read` | Read daemon storage |
| StorageWrite | `storage.write` | Write daemon storage |
| IdentityUse | `identity.use` | Act on behalf of a node identity |
| AppRegister | `app.register` | Register an app for stream dispatch |
| ControlEvents | `control.events` | Subscribe to control-plane events |
| BundleAdmit | `bundle.admit` | Admit bundle transactions |
| ConfigRead | `config.read` | Read daemon config |
| ConfigWrite | `config.write` | Write daemon config |

The set is fixed. New daemon surfaces exposed to plugins must add a
capability first.

## Enforcement

Deny by default: `CapsContext` wraps the daemon context with the manifest's
grant and rejects every call the grant does not cover with
`PluginError::PermissionDenied` before the inner context is touched.
Manifests are validated at load time — unknown permission strings are
rejected, so a typo never silently widens or narrows a grant. The manifest is
advisory (what the plugin declares); the loader is the trust anchor (what it
actually grants), and only the loader's grant is enforced.

## Supervisor limits

The default supervisor limits mirror `carrier-plugin-api.md` §26: 1 MiB
messages, a 10-second startup deadline, a 15-second heartbeat timeout, 1,024
outstanding requests, 65,536 handles, 64 MiB shared-memory packet bytes, 100
log events per second with a 1,000-event burst, 10,000 property events per
second, and a three-failure restart burst with a five-minute backoff cap. Every
reservation is generation-scoped and cleared on stop, crash, protocol failure,
or restart.

## Threats

| Threat | Status |
|---|---|
| Arbitrary code execution | Accepted and bounded by scope — native in-process hooks are trusted; external process loading is not advertised in v0.1 |
| Resource exhaustion | Mitigated for the bounded contract — request, message, handle, shared-memory, log, property-event, and restart quotas are enforced |
| Data exfiltration | Mitigated by least privilege — read caps granted per plugin, never by default |
| Control-plane abuse | Mitigated — control caps (`control.events`) are read-only; no control write surface exists |
| Manifest forgery | Accepted — manifests are unsigned; signed manifests are future work |
| Unknown-permission typos | Mitigated — strict validation at load time |

## Deferred extension

An external subprocess loader, private IPC handshake, OS sandbox profiles, and
independent carrier-plugin review remain a future extension. They must use the
same manifest capability set and `PluginSupervisor` generation/quota contract
before being advertised. No v0.1 production claim depends on those controls.
