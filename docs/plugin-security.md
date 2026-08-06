# Plugin Security Model

Status: Phase 11 closeout — capability-based permission model enforced at the
`PluginContext` boundary. Applies to `crates/umc-plugin`.

## Trust model

Plugins are third-party code compiled into the daemon binary and driven
in-process by the registry. Capability enforcement is a robustness and
defense-in-depth layer, **not a sandbox**: a plugin granted no capabilities
still runs in the daemon's address space. **Accepted risk:** malicious native
plugin code is not contained — it can read process memory, call arbitrary
syscalls, and compromise the daemon. The real isolation boundary is the future
WASM/subprocess loading path; this capability model carries over to it
unchanged. Loading plugins is a trust decision: only load plugins you trust.

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

## Threats

| Threat | Status |
|---|---|
| Arbitrary code execution | Accepted risk — in-process plugins are native code; future process isolation |
| Resource exhaustion | Accepted — no per-plugin CPU/memory budgets yet |
| Data exfiltration | Mitigated by least privilege — read caps granted per plugin, never by default |
| Control-plane abuse | Mitigated — control caps (`control.events`) are read-only; no control write surface exists |
| Manifest forgery | Accepted — manifests are unsigned; signed manifests are future work |
| Unknown-permission typos | Mitigated — strict validation at load time |

## Future

Signed manifests, per-plugin resource budgets, and a WASM/subprocess loader
that becomes the true isolation boundary. The capability model defined here
is the stable contract for that path.
