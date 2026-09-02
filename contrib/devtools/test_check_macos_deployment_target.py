#!/usr/bin/env python3

import unittest
from pathlib import Path
from unittest import mock

import check_macos_deployment_target as target_check


class DeploymentTargetTest(unittest.TestCase):
    def test_parses_archive_members_and_legacy_binary(self):
        sample = """\
Archive : /tmp/verifier.a
/tmp/verifier.a(first.o):
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 24
 platform 1
    minos 11.0
      sdk 15.0
/tmp/verifier.a(second.o):
Load command 1
      cmd LC_VERSION_MIN_MACOSX
  cmdsize 16
  version 10.15
      sdk 13.3
"""
        self.assertEqual(
            target_check.parse_otool_deployment_targets(sample),
            [
                ("/tmp/verifier.a(first.o)", "11.0"),
                ("/tmp/verifier.a(second.o)", "10.15"),
            ],
        )
        self.assertEqual(
            target_check.parse_otool_macho_labels(sample),
            ["/tmp/verifier.a(first.o)", "/tmp/verifier.a(second.o)"],
        )

    def test_normalizes_trailing_zero_components_only(self):
        self.assertEqual(
            target_check.normalized_version("11.0"),
            target_check.normalized_version("11.0.0"),
        )
        self.assertNotEqual(
            target_check.normalized_version("11.1"),
            target_check.normalized_version("11.0"),
        )
        with self.assertRaises(ValueError):
            target_check.normalized_version("11.x")

    def test_parses_and_classifies_dynamic_dependencies(self):
        sample = """\
/tmp/elementsd:
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1356.0.0)
\t/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0, current version 1.0.0)
\t/opt/homebrew/opt/libevent/lib/libevent-2.1.7.dylib (compatibility version 8.0.0, current version 8.1.0)
"""
        dependencies = target_check.parse_otool_dependencies(sample)
        self.assertEqual(len(dependencies), 3)
        self.assertTrue(target_check.is_system_dependency(dependencies[0][1]))
        self.assertTrue(target_check.is_system_dependency(dependencies[1][1]))
        self.assertFalse(target_check.is_system_dependency(dependencies[2][1]))

    def test_archive_members_without_load_dylibs_are_allowed(self):
        sample = """\
Archive : /tmp/verifier.a
/tmp/verifier.a(first.o):
/tmp/verifier.a(second.o):
"""
        self.assertEqual(target_check.parse_otool_dependencies(sample), [])

    @mock.patch("check_macos_deployment_target.subprocess.run")
    def test_inspect_rejects_member_without_target_command(self, run):
        run.return_value = mock.Mock(
            returncode=0,
            stdout="Archive : /tmp/verifier.a\n/tmp/verifier.a(no-target.o):\n",
            stderr="",
        )
        with self.assertRaisesRegex(RuntimeError, "no macOS deployment-target"):
            target_check.inspect(Path("/tmp/verifier.a"))

    @mock.patch("check_macos_deployment_target.subprocess.run")
    def test_dependency_inspection_propagates_otool_failure(self, run):
        run.return_value = mock.Mock(returncode=1, stdout="", stderr="bad binary")
        with self.assertRaisesRegex(RuntimeError, "bad binary"):
            target_check.inspect_dependencies(Path("/tmp/elementsd"))


if __name__ == "__main__":
    unittest.main()
