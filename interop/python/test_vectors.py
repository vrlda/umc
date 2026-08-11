import unittest

from verify_vectors import verify_vectors


class IndependentVectorTests(unittest.TestCase):
    def test_published_vectors(self) -> None:
        verify_vectors()


if __name__ == "__main__":
    unittest.main()
