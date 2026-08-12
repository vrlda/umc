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


if __name__ == "__main__":
    unittest.main()
