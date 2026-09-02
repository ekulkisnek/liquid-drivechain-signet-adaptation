#!/usr/bin/env python3
"""Check/emit the additive ECX catalogue; never authorize live activation.

The typed Haskell derivation is independently checked here using the exact
Simplicity SHA-256 midstate constructions. This is build/test tooling, not a
cryptographic verifier. No benchmark measurements or review attestations are
manufactured by this generator. See README.md for the independent live gates.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
UPSTREAM = "e3b670103101108faa238df012676ff5d8b77cf9"
CONTEXT_COST = 1_000
PROOF_COST = 1_000_000_000
# Catalogue ordering is consensus data, not alphabetical presentation order.
INTERFACES = (
    ("prior_active_exchange_state_root_required", "1", "h"),
    ("prior_active_forced_inbox_root_required", "1", "h"),
    ("prior_active_deposit_inbox_root_required", "1", "h"),
    ("prior_active_forced_processed_cursor_required", "1", "l"),
    ("prior_active_deposit_processed_cursor_required", "1", "l"),
    ("current_bmm_parent_block_hash_required", "1", "h"),
    ("current_bmm_parent_height_required", "1", "l"),
    ("current_bmm_parent_mtp_required", "1", "l"),
    ("bond_v2_configuration_hash_required", "1", "h"),
    ("bond_v2_asset_id_required", "1", "h"),
    ("bond_v2_deployment_commitment_required", "1", "h"),
    ("bond_v2_transition_cmr_required", "1", "h"),
    ("verify_sp1_groth16_sha256", "*hh", "2"),
    ("verify_sp1_groth16_v3_public_values_v4_sha256", "*hh", "2"),
    ("verify_sp1_groth16_v4_public_values_v5_sha256", "*hh", "2"),
    ("prior_active_bond_inbox_root_required", "1", "h"),
    ("prior_active_bond_inbox_count_required", "1", "l"),
    ("current_sidechain_height_required", "1", "l"),
    ("bond_v2_insurance_reserve_input_required", "i", "1"),
    ("bond_v2_collateral_vault_input_required", "i", "1"),
    ("bond_v2_incremental_activation_cmr_required", "1", "h"),
    ("incremental_successor_transition_cmr_required", "1", "h"),
    ("verify_sp1_groth16_v5_incremental_activation_sha256", "*hh", "2"),
    ("verify_sp1_groth16_v6_incremental_successor_sha256", "*hh", "2"),
)
TYPE_INDEX = {"1": "ty_u", "2": "ty_b", "i": "ty_w32",
              "l": "ty_w64", "h": "ty_w256", "*hh": "ty_w512"}
TYPE_BITS = {"1": 0, "2": 1, "i": 32, "l": 64, "h": 256, "*hh": 512}
FIELDS = ["index", "name", "haskell_bits", "encoding_bits", "cost_milliweight",
          "cmr", "imr", "amr", "source_tmr", "target_tmr",
          "specification_cmr", "specification_imr"]
INITIAL = bytes.fromhex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")
K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def ror(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def compress(midstate: bytes, block: bytes) -> bytes:
    require(len(midstate) == 32 and len(block) == 64, "invalid compression size")
    state = struct.unpack(">8I", midstate)
    words = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = words[i - 15], words[i - 2]
        s0 = ror(x, 7) ^ ror(x, 18) ^ (x >> 3)
        s1 = ror(y, 17) ^ ror(y, 19) ^ (y >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & 0xffffffff)
    a, b, c, d, e, f, g, h = state
    for k, w in zip(K, words):
        t1 = (h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + k + w) & 0xffffffff
        t2 = ((ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & 0xffffffff
        a, b, c, d, e, f, g, h = (t1 + t2) & 0xffffffff, a, b, c, (d + t1) & 0xffffffff, e, f, g
    return struct.pack(">8I", *((x + y) & 0xffffffff for x, y in zip(state, (a, b, c, d, e, f, g, h))))


def tag(*parts: str) -> bytes:
    digest = hashlib.sha256("\x1f".join(("Simplicity",) + parts).encode("ascii")).digest()
    return compress(INITIAL, digest + digest)


def type_roots() -> dict[str, bytes]:
    unit = tag("Type", "unit")
    word = compress(tag("Type", "sum"), unit + unit)
    roots = {"1": unit, "2": word}
    for bits in (2, 4, 8, 16, 32, 64, 128, 256, 512):
        word = compress(tag("Type", "prod"), word + word)
        for name, size in TYPE_BITS.items():
            if size == bits:
                roots[name] = word
    return roots


def identity(root: bytes, source: bytes, target: bytes) -> bytes:
    return compress(compress(tag("Identity"), bytes(32) + root), source + target)


def natural(value: int) -> str:
    require(1 <= value <= 2147483647, "natural out of range")
    if value == 1:
        return "0"
    bits = bin(value)[3:]
    return "1" + natural(len(bits)) + bits


def load_rows(path: Path = HERE / "jet-identities.tsv") -> list[dict]:
    with path.open(encoding="ascii", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        require(reader.fieldnames == FIELDS, "unexpected TSV columns")
        rows = list(reader)
    require(len(rows) == len(INTERFACES), "exactly 24 interfaces required")
    roots = type_roots()
    for index, (row, (name, source, target)) in enumerate(zip(rows, INTERFACES), 1):
        require(row["index"] == str(index) and row["name"] == name, f"wrong interface at {index}")
        cost = PROOF_COST if source == "*hh" else CONTEXT_COST
        require(row["cost_milliweight"] == str(cost), f"{name}: policy cost mismatch")
        bits = "11" + natural(5) + natural(index)
        require(row["haskell_bits"] == bits and row["encoding_bits"] == bits[1:], f"{name}: encoding mismatch")
        spec = tag("Primitive", "Elements", name)
        spec_imr = identity(spec, roots[source], roots[target])
        cmr = compress(tag("Jet"), cost.to_bytes(32, "big") + spec_imr)
        computed = {"specification_cmr": spec, "specification_imr": spec_imr,
                    "source_tmr": roots[source], "target_tmr": roots[target],
                    "cmr": cmr, "amr": cmr, "imr": identity(cmr, roots[source], roots[target])}
        for field, value in computed.items():
            require(row[field] == value.hex(), f"{name}: {field} mismatch")
        require(spec != cmr, f"{name}: specification fingerprint substituted for jet CMR")
        row.update(index=index - 1, decoder_path=[5, index], source_type_name=source,
                   target_type_name=target, cost_milliweight=cost,
                   source_type_index=TYPE_INDEX[source], target_type_index=TYPE_INDEX[target],
                   enum_name="ECX_" + name.upper(), c_jet_symbol="simplicity_" + name)
    for field in ("name", "cmr", "imr", "encoding_bits"):
        require(len({row[field] for row in rows}) == 24, f"duplicate {field}")
    require(not any(a["encoding_bits"].startswith(b["encoding_bits"])
                    for a in rows for b in rows if a is not b), "non-prefix-free encodings")
    return rows


def raw_symbol(name: str) -> str:
    # Upstream's C name renderer inserts underscores before numeric runs.
    # The existing Elements runtime uses the canonical registry spelling.
    return re.sub(r"([a-z])([0-9])", r"\1_\2", name)


def check_upstream(rows: list[dict], directory: Path) -> None:
    nodes = (directory / "primitiveJetNode.inc").read_text()
    decoder = (directory / "decodeElementsJets.inc").read_text()
    rust = (directory / "elements.rs").read_text()
    source_section = rust.split("fn source_ty(", 1)[1].split("fn target_ty(", 1)[0]
    target_section = rust.split("fn target_ty(", 1)[1].split("fn encode", 1)[0]
    for row in rows:
        name, raw = row["name"], raw_symbol(row["name"])
        matches = re.findall(r"\[" + raw.upper() + r"\] =\s*\{(.*?)\n\}", nodes, re.S)
        require(len(matches) == 1, f"{name}: missing/duplicate upstream C node")
        node = matches[0]
        words = re.findall(r"0x([0-9a-f]{8})u", node)
        require("".join(words) == row["cmr"], f"{name}: upstream C CMR mismatch")
        for field, value in (("jet", "simplicity_" + raw), ("sourceIx", row["source_type_index"]),
                             ("targetIx", row["target_type_index"]), ("cost", row["cost_milliweight"])):
            require(re.search(r"\." + field + r" = " + str(value) + r"(?:\s|\n|,)", node) is not None,
                    f"{name}: upstream C {field} mismatch")
        require(f"case {row['index'] + 1}: *result = {raw.upper()};" in decoder,
                f"{name}: upstream C decoder mismatch")
        found = re.findall(r"Elements::" + name + r" => \[(.*?)\]", rust, re.S)
        require(len(found) == 1 and "".join(re.findall(r"0x([0-9a-f]{2})", found[0])) == row["cmr"],
                f"{name}: upstream Rust CMR mismatch")
        for section, expected in ((source_section, row["source_type_name"]), (target_section, row["target_type_name"])):
            require(f'Elements::{name} => b"{expected}",' in section, f"{name}: upstream Rust type mismatch")
        bits = row["encoding_bits"]
        require(f"Elements::{name} => ({int(bits, 2)}, {len(bits)})," in rust, f"{name}: upstream Rust encoding mismatch")
        require(f"Elements::{name} => Cost::from_milliweight({row['cost_milliweight']})," in rust,
                f"{name}: upstream Rust cost mismatch")


def c_hash(value: str) -> str:
    return "{{" + ", ".join("0x" + value[i:i + 8] + "u" for i in range(0, 64, 8)) + "}}"


def render(rows: list[dict]) -> dict[Path, str]:
    banner = "/* Generated by contrib/devtools/ecx-catalogue/generate.py; do not edit.\n * Fixed POLICY costs; not measured results or live activation authorization. */\n"
    target = REPO / "src/simplicity/elements"
    outputs = {
        target / "ecxPrimitiveEnumJet.inc": banner + "".join(row["enum_name"] + ",\n" for row in rows),
        target / "ecxPrimitiveEnumTy.inc": banner + "/* All 24 interfaces use existing native types, including ty_w512. */\n",
        target / "ecxPrimitiveInitTy.inc": banner + "/* No additional unification variables are necessary. */\n",
        target / "ecxElementsJets.h.inc": banner + "".join(
            f"bool {row['c_jet_symbol']}(frameItem* dst, frameItem src, const txEnv* env);\n" for row in rows),
        target / "ecxPrimitiveJetNode.inc": banner + "".join(
            f",[{row['enum_name']}] =\n{{ .tag = JET\n, .jet = {row['c_jet_symbol']}\n"
            f", .cmr = {c_hash(row['cmr'])}\n, .sourceIx = {row['source_type_index']}\n"
            f", .targetIx = {row['target_type_index']}\n, .cost = {row['cost_milliweight']} /* milliweight */\n}}\n"
            for row in rows),
        target / "ecxDecodeElementsJets.inc": banner +
            "case 5:\n  code = simplicity_decodeUptoMaxInt(stream);\n"
            "  if (code < 0) return (simplicity_err)code;\n  switch (code) {\n" +
            "".join(f"    case {row['index'] + 1}: *result = {row['enum_name']}; return SIMPLICITY_NO_ERROR;\n" for row in rows) +
            "  }\n  break;\n",
        HERE / "catalogue_vectors.inc": banner + "".join(
            f"{{\"{row['name']}\", \"{row['encoding_bits']}\", {row['c_jet_symbol']},\n"
            f" {row['cost_milliweight']}, {TYPE_BITS[row['source_type_name']]}, {TYPE_BITS[row['target_type_name']]},\n"
            f" {c_hash(row['cmr'])}, {c_hash(row['imr'])}, {c_hash(row['amr'])},\n"
            f" {c_hash(row['source_tmr'])}, {c_hash(row['target_tmr'])}}},\n" for row in rows),
    }
    inputs = ("generate.py", "DeriveEcxCatalogue.hs", "EcxPrimitiveCandidate.hs", "apply_overlay.py",
              "catalogue.project", "catalogue.project.freeze", "reproduce.sh",
              "jet-identities.tsv", "evidence/sp1-smoke-cost-candidate-20260827.json",
              "evidence/current-bmm-wsl-diagnostic-20260828.json")
    registry = {
        "schema": "ECX_FIXED_POLICY_CATALOGUE_V1",
        "status": "fixed-bindings-opt-in-not-live-activation",
        "upstream_generator": {"repository": "https://github.com/BlockstreamResearch/simplicity",
                               "commit": UPSTREAM, "compiler": "ghc-9.6.7"},
        "activation_authorized": False,
        "production_benchmark_reviewed": False,
        "cost_basis": {"kind": "user-selected-policy", "context_milliweight": CONTEXT_COST,
                       "proof_milliweight": PROOF_COST,
                       "note": "Historical WSL diagnostics are separate evidence, not measurements of these policy values or of all 24 current jets."},
        "input_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in inputs},
        "decoder_policy": {"haskell_prefix": "11", "c_and_rust_prefix": "1", "elements_branch": 5,
                           "native_catalogue_unchanged": True, "first_path_index": 1},
        "jets": rows,
    }
    outputs[HERE / "registry.json"] = json.dumps(registry, indent=2) + "\n"
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate only the listed catalogue outputs")
    parser.add_argument("--upstream-generated", type=Path, help="also check outputs of pinned Haskell C/Rust generators")
    args = parser.parse_args()
    try:
        rows = load_rows()
        if args.upstream_generated:
            check_upstream(rows, args.upstream_generated)
        outputs = render(rows)
        # Validate every input before any generated output is changed.
        for path, content in outputs.items():
            if args.write:
                path.write_text(content, encoding="ascii")
            else:
                require(path.read_bytes() == content.encode("ascii"), f"stale generated file: {path.relative_to(REPO)}")
        print("PASS: 24 independently recomputed typed identities, policy costs, encodings, and exact generated files")
        if args.upstream_generated:
            print("PASS: pinned upstream C and Rust generator outputs agree for all 24 jets")
        print("Live activation and paid proving remain separately gated.")
        return 0
    except (ValueError, OSError, KeyError, IndexError) as exc:
        print(f"FAIL: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
