import unittest
from pathlib import Path

from verify_vectors import verify_vectors


class IndependentVectorTests(unittest.TestCase):
    def test_published_vectors(self) -> None:
        verify_vectors()

    def test_ci_exposes_a_published_independent_vector_gate(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("independent-vectors:", workflow)
        self.assertIn("python -m unittest discover -s interop/python", workflow)

    def test_ci_exposes_live_carrier_interoperability_gate(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("carrier-interoperability:", workflow)
        self.assertIn("live_runner.py --carrier tcp", workflow)
        self.assertIn("live_runner.py --carrier udp", workflow)
        self.assertIn("live_runner.py --carrier tls", workflow)

    def test_ci_exposes_security_evidence_gate(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("security-evidence:", workflow)
        self.assertIn("security_gate.py", workflow)
        self.assertIn("security-evidence", workflow)

    def test_ci_exposes_fuzz_evidence_gate(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("fuzz-evidence:", workflow)
        self.assertIn("fuzz_gate.py", workflow)
        self.assertIn("fuzz-report.json", workflow)

    def test_ci_exposes_protocol_coverage_gate(self) -> None:
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("protocol-coverage:", workflow)
        self.assertIn("cargo llvm-cov", workflow)
        self.assertIn("lcov.info", workflow)
        self.assertIn("protocol-coverage", workflow)

    def test_security_reporting_link_matches_published_repository(self) -> None:
        policy = (Path(__file__).resolve().parents[2] / "SECURITY.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "https://github.com/vrlda/umc/security/advisories/new", policy
        )
        self.assertNotIn("github.com/varpn/openmesh", policy)


if __name__ == "__main__":
    unittest.main()
