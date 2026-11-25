import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SUPABASE_URL", "https://example.invalid")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-only-not-a-real-key")
os.environ.setdefault("RESOLVER_SECRET", "test-local-resolver-secret")

from main import resolve_address, verify_secret, _elf_cache


class LowMemoryResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.elf = str(Path(cls.directory.name) / "fixture.elf")
        fixture = Path(__file__).with_name("known_fault.c")
        subprocess.run(["gcc", "-g", "-O0", "-fno-inline", "-no-pie",
                        str(fixture), "-o", cls.elf], check=True)
        symbols = subprocess.check_output(["nm", "-n", cls.elf], text=True)
        cls.address = int(next(line.split()[0] for line in symbols.splitlines()
                               if line.endswith(" synthetic_known_fault")), 16)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_ground_truth_function_and_file(self):
        data = resolve_address(self.elf, self.address)
        self.assertEqual(data["function"], "synthetic_known_fault")
        self.assertEqual(data["file"], "known_fault.c")
        self.assertIsInstance(data["line"], int)

    def test_outside_elf_returns_unknown(self):
        data = resolve_address(self.elf, 0x12345678)
        self.assertIsNone(data["function"])
        self.assertIsNone(data["line"])

    def test_address_bounds_rejected(self):
        for addr in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                resolve_address(self.elf, addr)

    def test_server_auth_fail_closed(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            verify_secret("incorrect")
        self.assertTrue(verify_secret("test-local-resolver-secret"))


if __name__ == "__main__":
    unittest.main()
