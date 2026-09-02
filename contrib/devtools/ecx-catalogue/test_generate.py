#!/usr/bin/env python3
"""Mutation tests for the checked-in catalogue verifier (no network or node)."""
import copy
import csv
import hashlib
import io
import unittest
from unittest.mock import patch

import generate


class CatalogueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with (generate.HERE / "jet-identities.tsv").open() as stream:
            cls.raw = list(csv.DictReader(stream, delimiter="\t"))

    def load(self, rows):
        content = io.StringIO()
        writer = csv.DictWriter(content, fieldnames=generate.FIELDS, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)
        with patch("pathlib.Path.open", return_value=io.StringIO(content.getvalue())):
            return generate.load_rows()

    def test_exact_rows(self):
        self.assertEqual(24, len(self.load(self.raw)))

    def test_compression_independent_standard_vectors(self):
        # Compare the custom compression primitive to hashlib, not to itself.
        for payload in (b"", b"abc", bytes(range(55))):
            padding = b"\x80" + bytes(55 - len(payload)) + (8 * len(payload)).to_bytes(8, "big")
            self.assertEqual(generate.compress(generate.INITIAL, payload + padding),
                             hashlib.sha256(payload).digest())

    def test_every_consensus_field_mutation_rejected(self):
        for index in range(24):
            for field in generate.FIELDS:
                with self.subTest(index=index, field=field):
                    rows = copy.deepcopy(self.raw)
                    value = rows[index][field]
                    rows[index][field] = ("1" if value[0] != "1" else "0") + value[1:]
                    with self.assertRaises(ValueError):
                        self.load(rows)

    def test_missing_extra_and_reordered_rows_rejected(self):
        for rows in (self.raw[:-1], self.raw + [self.raw[0]], list(reversed(self.raw))):
            with self.assertRaises(ValueError):
                self.load(rows)

    def test_specification_cannot_be_substituted_for_jet(self):
        for index in range(24):
            rows = copy.deepcopy(self.raw)
            rows[index]["cmr"] = rows[index]["specification_cmr"]
            with self.assertRaises(ValueError):
                self.load(rows)

    def test_natural_encoding_boundaries(self):
        self.assertEqual(generate.natural(1), "0")
        self.assertEqual(generate.natural(5), "110001")
        for invalid in (0, -1, 2147483648):
            with self.assertRaises(ValueError):
                generate.natural(invalid)

    def test_rendered_files_are_exact(self):
        for path, expected in generate.render(generate.load_rows()).items():
            with self.subTest(path=path.name):
                self.assertEqual(path.read_bytes(), expected.encode("ascii"))

    def test_registry_does_not_attest_measurements_or_activation(self):
        import json
        registry = json.loads(generate.render(generate.load_rows())[generate.HERE / "registry.json"])
        self.assertFalse(registry["activation_authorized"])
        self.assertFalse(registry["production_benchmark_reviewed"])
        self.assertEqual(registry["cost_basis"]["kind"], "user-selected-policy")
        self.assertEqual(sum(j["cost_milliweight"] == 1000 for j in registry["jets"]), 19)
        self.assertEqual(sum(j["cost_milliweight"] == 1000000000 for j in registry["jets"]), 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
