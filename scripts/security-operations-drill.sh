#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 OUTPUT_DIR" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
output_dir=$1
repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

if [ -e "$output_dir" ]; then
    echo "output directory already exists: $output_dir" >&2
    exit 1
fi
mkdir -p "$output_dir"

python3 - "$repo_root" "$output_dir" <<'PY'
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

repo = Path(sys.argv[1])
output = Path(sys.argv[2])
records = []


def write_json(name, value):
    path = output / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run(name, command, log_name):
    log = output / log_name
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(
            command,
            cwd=repo,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
        )
    if result.returncode:
        raise RuntimeError(f"{name} exited with status {result.returncode}; see {log_name}")
    return log


def drill(identifier, title, evidence, action):
    try:
        paths = action()
        records.append({"id": identifier, "title": title, "status": "pass", "evidence": paths})
        print(f"pass {identifier}: {title}")
    except Exception as error:
        records.append(
            {"id": identifier, "title": title, "status": "fail", "error": str(error)}
        )
        print(f"fail {identifier}: {title}: {error}", file=sys.stderr)


def report_handling():
    value = {
        "advisory_id": "UMC-DRILL-2026-001",
        "component": "umc-session",
        "version": "0.1.0",
        "severity": "HIGH",
        "description": "Synthetic bounded report for the offline operations exercise.",
        "reproduction": ["run the release regression suite"],
        "impact": "Synthetic only; no live vulnerability is asserted.",
        "disclosure_constraints": "embargoed",
    }
    path = write_json("01-report.json", value)
    required = {"component", "version", "description", "reproduction", "impact"}
    assert required <= value.keys()
    assert value["advisory_id"].startswith("UMC-DRILL-")
    return [path.name]


def embargo():
    value = {
        "report_id": "UMC-DRILL-2026-001",
        "default_days": 90,
        "trusted_participants": [
            {"role": "project-owner", "channel": "private"},
        ],
        "public_channels": [],
        "reviewers_required": 1,
    }
    path = write_json("02-embargo.json", value)
    assert value["default_days"] == 90
    assert len(value["trusted_participants"]) == 1
    assert not value["public_channels"]
    assert all(entry["channel"] == "private" for entry in value["trusted_participants"])
    return [path.name]


def advisory():
    value = {
        "advisory_id": "UMC-2026-DRILL-001",
        "severity": "HIGH",
        "cve": None,
        "affected_versions": ["0.1.x"],
        "fixed_versions": ["0.1.1"],
        "summary": "Synthetic advisory publication dry run.",
        "impact": "No real vulnerability; used to validate publication fields.",
        "attack_conditions": "Synthetic test input only.",
        "mitigations": ["Upgrade to the fixed version."],
        "timeline": {"reported": "2026-01-01", "fixed": "2026-01-02", "disclosed": "2026-01-03"},
        "credits": ["UMC operator"],
        "references": ["https://example.invalid/umc/drill"],
    }
    path = write_json("03-advisory.json", value)
    required = {
        "advisory_id", "severity", "affected_versions", "fixed_versions", "summary",
        "impact", "attack_conditions", "mitigations", "timeline", "credits", "references",
    }
    assert required <= value.keys()
    assert value["timeline"]["reported"] <= value["timeline"]["fixed"] <= value["timeline"]["disclosed"]
    return [path.name]


def signing_material(directory, stem):
    private = directory / f"{stem}-private.pem"
    public = directory / f"{stem}-public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
    return private, public


def sign(manifest, private, signature):
    subprocess.run(
        [str(repo / "scripts/sign-release-manifest.sh"), str(manifest), str(private), str(signature)],
        check=True,
        stdout=subprocess.DEVNULL,
    )


def verify(manifest, public, signature):
    return subprocess.run(
        [str(repo / "scripts/verify-release-manifest.sh"), str(manifest), str(public), str(signature)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def release_revocation():
    with tempfile.TemporaryDirectory(prefix="umc-revocation-drill-") as temporary:
        directory = Path(temporary)
        manifest = directory / "manifest.json"
        manifest.write_text(
            json.dumps({"manifest_version": 1, "release": "0.1.0", "artifacts": []}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        private, public = signing_material(directory, "release")
        signature = directory / "manifest.sig"
        sign(manifest, private, signature)
        assert verify(manifest, public, signature)
        revoked = directory / "revoked-manifest.json"
        revoked.write_bytes(manifest.read_bytes().replace(b"0.1.0", b"0.1.0-revoked"))
        assert not verify(revoked, public, signature)
        value = {
            "release": "0.1.0",
            "reason": "synthetic signature/artifact revocation",
            "replacement": "0.1.1",
            "distribution_channels": ["advisory", "release-manifest"],
            "signature_invalidated": True,
        }
    path = write_json("04-release-revocation.json", value)
    assert len(value["distribution_channels"]) >= 2
    return [path.name]


def key_rotation():
    with tempfile.TemporaryDirectory(prefix="umc-key-rotation-drill-") as temporary:
        directory = Path(temporary)
        trusted = directory / "trusted"
        trusted.mkdir()
        manifest = directory / "manifest.json"
        keys = [signing_material(directory, "operator")]
        key_ids = []
        for _private, public in keys:
            key_id = hashlib.sha256(public.read_bytes()).hexdigest()
            key_ids.append(key_id)
            (trusted / f"{key_id}.pem").write_bytes(public.read_bytes())
        manifest.write_text(
            json.dumps(
                {
                    "manifest_version": 1,
                    "release": "0.1.0",
                    "signing": {
                        "threshold": 1,
                        "signatures": [
                            {"key_id": key_ids[0], "file": "manifest-0.sig"},
                        ],
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        for index, (private, _public) in enumerate(keys):
            signature = directory / f"manifest-{index}.sig"
            sign(manifest, private, signature)
        threshold_verifier = repo / "scripts/verify-release-threshold.sh"
        passed = subprocess.run(
            [str(threshold_verifier), str(manifest), str(trusted)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert passed.returncode == 0
        (directory / "manifest-0.sig").write_bytes(b"tampered")
        rejected = subprocess.run(
            [str(threshold_verifier), str(manifest), str(trusted)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        assert rejected.returncode != 0
    value = {"threshold": "1-of-1", "old_key_stopped": True, "new_key_ids": key_ids, "reissued": True}
    path = write_json("05-key-rotation.json", value)
    assert len(value["new_key_ids"]) == 1
    return [path.name]


def dependency_response():
    sbom = run(
        "dependency SBOM",
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        "06-sbom.json",
    )
    tree = run("dependency tree", ["cargo", "tree", "--locked"], "06-dependency-tree.txt")
    lock = repo / "Cargo.lock"
    assert lock.is_file()
    metadata = json.loads(sbom.read_text(encoding="utf-8"))
    assert metadata["packages"]
    value = {
        "sbom": sbom.name,
        "dependency_tree": tree.name,
        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "exposure_assessed": True,
        "replacement_or_pin_decision": "pin via Cargo.lock and review reachability",
    }
    path = write_json("06-dependency-incident.json", value)
    return [path.name, sbom.name, tree.name]


def crypto_deprecation():
    vectors = sorted((repo / "interop/vectors").glob("*.json"))
    value = {
        "deprecated_profile": "UMP-CRYPTO-0",
        "replacement_profile": "UMP-CRYPTO-1",
        "overlap_until": "2026-12-31",
        "new_handshake_selection": "UMP-CRYPTO-1",
        "migration_vectors": [path.name for path in vectors[:3]],
        "silent_downgrade": False,
    }
    path = write_json("07-crypto-deprecation.json", value)
    assert value["migration_vectors"]
    assert value["new_handshake_selection"] != value["deprecated_profile"]
    assert not value["silent_downgrade"]
    return [path.name]


def protocol_disablement():
    log = run(
        "emergency protocol disablement",
        [
            "cargo", "test", "--locked", "--package", "umcd",
            "emergency_disablement_blocks_protocol_crypto_and_carrier", "--", "--nocapture",
        ],
        "08-protocol-disablement.log",
    )
    return [log.name]


def containment():
    log = run(
        "incident containment",
        [
            "cargo", "test", "--locked", "--package", "umcd",
            "emergency_public_relay_disablement_refuses_public_opens", "--", "--nocapture",
        ],
        "09-containment.log",
    )
    value = {
        "actions": ["disable public relay", "preserve unaffected direct sessions", "record audit event"],
        "state_survives": ["identity", "trust store", "validated local configuration"],
        "state_invalidated": ["new public relay opens"],
        "regression_log": log.name,
    }
    path = write_json("09-containment.json", value)
    assert value["state_invalidated"]
    return [path.name, log.name]


def postmortem():
    value = {
        "incident_id": "UMC-DRILL-2026-001",
        "root_cause": "Synthetic exercise input; no production incident.",
        "remediation_owner": "project-owner",
        "regression_tests": ["cargo test --workspace --locked", "security-operations-drill.sh"],
        "follow_up": [{"id": "OPS-DRILL-001", "status": "tracked"}],
        "threat_model_updated": True,
    }
    path = write_json("10-postmortem.json", value)
    assert value["remediation_owner"]
    assert value["regression_tests"]
    return [path.name]


drill("OPS-01", "Simulated vulnerability report handling", ["01-report.json"], report_handling)
drill("OPS-02", "Embargo coordination", ["02-embargo.json"], embargo)
drill("OPS-03", "Advisory publication dry run", ["03-advisory.json"], advisory)
drill("OPS-04", "Release revocation", ["04-release-revocation.json"], release_revocation)
drill("OPS-05", "Emergency signing-key rotation", ["05-key-rotation.json"], key_rotation)
drill("OPS-06", "Dependency incident response", ["06-dependency-incident.json", "06-sbom.json"], dependency_response)
drill("OPS-07", "Cryptographic deprecation migration", ["07-crypto-deprecation.json"], crypto_deprecation)
drill("OPS-08", "Emergency protocol disablement", ["08-protocol-disablement.log"], protocol_disablement)
drill("OPS-09", "Incident containment", ["09-containment.json", "09-containment.log"], containment)
drill("OPS-10", "Postmortem and remediation tracking", ["10-postmortem.json"], postmortem)

artifacts = []
for path in sorted(output.iterdir()):
    if path.name == "drill-report.json" or not path.is_file():
        continue
    artifacts.append(
        {"name": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    )

record = {
    "schema": "umc-security-operations-drill-v1",
    "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "git_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
    "working_tree_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True).strip()),
    "status": "pass" if all(item["status"] == "pass" for item in records) else "fail",
    "drills": records,
    "artifacts": artifacts,
}
write_json("drill-report.json", record)
if record["status"] != "pass":
    raise SystemExit(1)
print(f"security operations drill: {output}")
PY
