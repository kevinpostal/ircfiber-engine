#!/usr/bin/env python3
"""Engine image build-context contracts. Real Docker target builds remain required."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = {
    "ircfiber-engine-entrypoint.sh": "ce481b4c450c712aa0a2b37c628ecaece37b5ab78551c0e02a6bed5cda218570",
    "ircfiber-engine-healthcheck.sh": "ff9bfdf142abb9a9c81998974621628a355db5becefb67c918fbc03a32789726",
}


class RuntimePackagingTest(unittest.TestCase):
    def test_every_context_copy_input_exists(self):
        checked = 0
        for number, line in enumerate((ROOT / "Containerfile.engine").read_text().splitlines(), 1):
            if not line.lstrip().startswith("COPY "):
                continue
            words = shlex.split(line, comments=True)
            if any(word.startswith("--from=") for word in words):
                continue
            operands = [word for word in words[1:] if not word.startswith("--")]
            self.assertGreaterEqual(len(operands), 2, f"malformed COPY at line {number}")
            for source in operands[:-1]:
                with self.subTest(line=number, source=source):
                    self.assertTrue((ROOT / source).exists(),
                                    f"runtime build COPY input is absent: {source}")
                    checked += 1
        self.assertGreater(checked, 10, "the test must inspect the real multi-stage build context")

    def test_runtime_scripts_are_exact_deployed_engine_artifacts(self):
        containerfile = (ROOT / "Containerfile.engine").read_text()
        for name, digest in SCRIPTS.items():
            with self.subTest(script=name):
                source = ROOT / "scripts" / "runtime" / name
                self.assertTrue(source.is_file(), "runtime scripts belong to the engine, not an Ansible fork")
                self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest,
                                 "relocation must not change deployed 7c8f6e3 script behavior")
                self.assertTrue(os.access(source, os.X_OK), "runtime script must retain executable mode")
                self.assertIn(f"COPY scripts/runtime/{name} /usr/local/bin/{name}", containerfile)
                subprocess.run(["sh", "-n", str(source)], check=True)
        self.assertNotIn("COPY deploy/", containerfile)
        self.assertFalse((ROOT / "deploy" / "roles").exists(), "do not resurrect the removed deployment role fork")

    def test_engine_build_freshness_tracks_canonical_runtime_sources(self):
        makefile = (ROOT / "Makefile.engine").read_text()
        self.assertNotIn("find engine/source common/source deploy/roles/engine/files", makefile)
        self.assertEqual(makefile.count("find engine/source common/source scripts/runtime"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
