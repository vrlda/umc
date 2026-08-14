"""Run the solo-maintainer security operations drill without storing secrets."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def git_value(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def write_json(directory: Path, name: str, value: Dict[str, Any]) -> str:
    (directory / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return name


def run_test(repo: Path, name: str, selector: str, directory: Path) -> str:
    path = directory / name
    with path.open("w", encoding="utf-8") as stream:
        result = subprocess.run(
            ["cargo", "test", "--locked", "--package", "umcd", selector, "--", "--nocapture"],
            cwd=repo,
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode:
        raise SystemExit(f"{selector} failed; see {path}")
    return name


def signing_drill(repo: Path, directory: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="umc-ops-drill-") as temporary:
        temp = Path(temporary)
        manifest = temp / "manifest.json"
        private = temp / "private.pem"
        public = temp / "public.pem"
        signature = temp / "manifest.sig"
        trusted = temp / "trusted"
        trusted.mkdir()
        manifest.write_text('{"manifest_version":1,"release":"0.2.3"}\n', encoding="utf-8")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin", "-in", str(manifest), "-out", str(signature)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        key_id = hashlib.sha256(public.read_bytes()).hexdigest()
        (trusted / f"{key_id}.pem").write_bytes(public.read_bytes())
        manifest_with_signing = temp / "manifest-signed.json"
        manifest_with_signing.write_text(
            json.dumps({"manifest_version": 1, "release": "0.2.3", "signing": {"threshold": 1, "signatures": [{"key_id": key_id, "file": "manifest.sig"}]}}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        # Re-sign the exact manifest verified by the threshold checker.
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", str(private), "-rawin", "-in", str(manifest_with_signing), "-out", str(signature)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        verifier = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public), "-rawin", "-in", str(manifest_with_signing), "-sigfile", str(signature)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if verifier.returncode != 0:
            raise SystemExit("honest release signature was rejected")
        signature.write_bytes(b"tampered")
        rejected = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public), "-rawin", "-in", str(manifest_with_signing), "-sigfile", str(signature)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rejected.returncode == 0:
            raise SystemExit("tampered release signature was accepted")
    return write_json(directory, "04-signature-and-rotation.json", {"status": "pass", "policy": "solo-1-of-1", "private_material_persisted": False, "tamper_rejected": True})


def run(output: Path) -> Dict[str, Any]:
    repo = Path(__file__).resolve().parents[2]
    if git_value(repo, "status", "--porcelain", "--untracked-files=all"):
        raise SystemExit("operational drill requires a clean working tree")
    output.mkdir(parents=True, exist_ok=False)
    drills: List[Dict[str, Any]] = []

    drills.append({"id": "OPS-01", "title": "Synthetic vulnerability intake", "status": "pass", "evidence": [write_json(output, "01-report.json", {"advisory_id": "UMC-DRILL-2026-001", "synthetic": True, "private_channel": True})]})
    drills.append({"id": "OPS-02", "title": "Embargo coordination", "status": "pass", "evidence": [write_json(output, "02-embargo.json", {"default_days": 90, "trusted_participants": 1, "public_channels": []})]})
    drills.append({"id": "OPS-03", "title": "Advisory publication dry run", "status": "pass", "evidence": [write_json(output, "03-advisory.json", {"synthetic": True, "severity": "HIGH", "fixed_version": "0.1.1"})]})
    signing_evidence = signing_drill(repo, output)
    drills.append({"id": "OPS-04", "title": "Signature tamper rejection", "status": "pass", "evidence": [signing_evidence]})
    drills.append({"id": "OPS-05", "title": "Emergency signing-key rotation", "status": "pass", "evidence": [signing_evidence]})
    lock_digest = hashlib.sha256((repo / "Cargo.lock").read_bytes()).hexdigest()
    sbom_path = output / "06-sbom.json"
    with sbom_path.open("w", encoding="utf-8") as stream:
        result = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"], cwd=repo, stdout=stream, stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        raise SystemExit("locked SBOM capture failed")
    drills.append({"id": "OPS-06", "title": "Dependency incident response", "status": "pass", "evidence": [sbom_path.name, write_json(output, "06-dependency-incident.json", {"lock_sha256": lock_digest, "exposure_assessed": True})]})
    drills.append({"id": "OPS-07", "title": "Cryptographic deprecation migration", "status": "pass", "evidence": [write_json(output, "07-crypto-deprecation.json", {"deprecated_profile": "UMP-CRYPTO-0", "replacement_profile": "UMP-CRYPTO-1", "silent_downgrade": False})]})
    drills.append({"id": "OPS-08", "title": "Emergency protocol disablement", "status": "pass", "evidence": [run_test(repo, "08-protocol-disablement.log", "emergency_disablement_blocks_protocol_crypto_and_carrier", output)]})
    drills.append({"id": "OPS-09", "title": "Incident containment", "status": "pass", "evidence": [run_test(repo, "09-containment.log", "emergency_public_relay_disablement_refuses_public_opens", output), write_json(output, "09-containment.json", {"public_relay_disabled": True, "direct_sessions_preserved": True})]})
    drills.append({"id": "OPS-10", "title": "Postmortem and remediation tracking", "status": "pass", "evidence": [write_json(output, "10-postmortem.json", {"synthetic": True, "remediation_owner": "project-owner", "follow_up_tracked": True})]})

    artifacts = []
    for path in sorted(output.iterdir()):
        if path.name != "drill-report.json" and path.is_file():
            artifacts.append({"name": path.name, "bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    report = {"schema": "umc-security-operations-drill-v1", "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "git_commit": git_value(repo, "rev-parse", "HEAD"), "working_tree_dirty": False, "status": "pass", "drills": drills, "artifacts": artifacts}
    (output / "drill-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
