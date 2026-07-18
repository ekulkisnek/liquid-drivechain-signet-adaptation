#!/usr/bin/env python3
"""
Production bridge CLI for Liquid ID5 Drivechain peg operations.

This tool deliberately refuses to invent side credits or withdrawal bundles.
It owns the production-safe boundary between:
  - CUSF/BIP300 enforcer gRPC calls, and
  - the Elements/Liquid side node or side wallet that must consume/produce
    real peg artifacts.

Deposit flow:
  1. CreateDepositTransaction on WalletService for sidechain ID 5.
  2. Record the returned mainchain txid as pending.
  3. Reconcile against ValidatorService.GetTwoWayPegData.
  4. Pass the exact confirmed block, outpoint, value, and address to elementsd.
     elementsd independently queries GetTwoWayPegData and rejects any mismatch.

Withdrawal flow:
  1. Accept a real withdrawal bundle hex from the sidechain wallet/node.
  2. BroadcastWithdrawalBundle on WalletService.
  3. Record and reconcile against ValidatorService.GetBlockInfo events.

The state file is a single valid JSON object. Older JSONL/mixed state files are
loaded best-effort and rewritten into the structured format.
"""

from __future__ import annotations

if __name__ == "__main__":
    import sys as _quarantine_sys
    _quarantine_sys.stderr.write(
        "ERROR: quarantined legacy slot-5/regtest launcher. This fork supports only "
        "Elements Drivechain (-chain=elements), BIP300 slot 24. See the repository README.md.\n"
    )
    raise SystemExit(64)

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SIDECHAIN_ID = 24
DEFAULT_STATE_FILE = (
    Path(__file__).resolve().parents[1] / "tests" / "liquid-id5-peg-state.json"
)
LEGACY_STATE_FILE = (
    Path(__file__).resolve().parents[1] / "tests" / "liquid-side-state.json"
)
DEFAULT_ELEMENTS_CLI = Path(__file__).resolve().parents[2] / "src" / "elements-cli"
DEFAULT_ELEMENTS_DATADIR = Path("/tmp/liquid-id5-regtest")
DEFAULT_ELEMENTS_RPCPORT = "18443"


class BridgeError(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(cmd: list[str], *, timeout: int = 30, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        raise BridgeError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{detail}")
    return proc.stdout


def parse_jsonish(raw: str) -> Any:
    raw = raw.strip()
    if not raw:
        return {}
    return json.loads(raw)


def default_state(sidechain_id: int) -> dict[str, Any]:
    return {
        "schema": "liquid-id5-peg-state-v1",
        "sidechain_id": sidechain_id,
        "updated_at": now_iso(),
        "deposits": [],
        "withdrawals": [],
        "events": [],
    }


def load_state(path: Path, sidechain_id: int) -> dict[str, Any]:
    if not path.exists():
        return default_state(sidechain_id)
    text = path.read_text()
    try:
        value = json.loads(text)
        if isinstance(value, dict) and value.get("schema") == "liquid-id5-peg-state-v1":
            return value
    except json.JSONDecodeError:
        pass

    state = default_state(sidechain_id)
    recovered: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            recovered.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if recovered:
        state["events"].append(
            {
                "kind": "legacy_state_recovered",
                "count": len(recovered),
                "source": str(path),
                "items": recovered,
                "ts": now_iso(),
            }
        )
    return state


def save_state(path: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = now_iso()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def append_unique(items: list[dict[str, Any]], key: str, item: dict[str, Any]) -> dict[str, Any]:
    value = item.get(key)
    if value:
        for existing in items:
            if existing.get(key) == value:
                existing.update({k: v for k, v in item.items() if v is not None})
                return existing
    items.append(item)
    return item


def grpc_curl(enforcer: str, service_method: str, payload: dict[str, Any] | None = None, timeout: int = 30) -> Any:
    if not shutil_which("buf"):
        raise BridgeError("buf is required for enforcer gRPC calls; install buf or run inside the local-dev buf container")
    cmd = [
        "buf",
        "curl",
        "--timeout",
        f"{timeout}s",
        "--emit-defaults",
        "--protocol",
        "grpc",
        "--http2-prior-knowledge",
    ]
    if payload is not None:
        cmd.extend(["-d", json.dumps(payload, separators=(",", ":"))])
    cmd.append(f"http://{enforcer}/{service_method}")
    return parse_jsonish(run(cmd, timeout=timeout + 5))


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def elements_cli(args: argparse.Namespace, *rpc_args: str, timeout: int = 15) -> Any:
    cli = Path(args.elements_cli)
    if not cli.exists():
        raise BridgeError(f"elements-cli not found at {cli}")
    cmd = [
        str(cli),
        "-regtest",
        f"-datadir={args.elements_datadir}",
        f"-rpcport={args.elements_rpcport}",
        f"-rpccookiefile={Path(args.elements_datadir) / 'regtest' / '.cookie'}",
        *rpc_args,
    ]
    raw = run(cmd, timeout=timeout)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip()


def elements_available(args: argparse.Namespace) -> bool:
    try:
        elements_cli(args, "getblockchaininfo", timeout=5)
        return True
    except Exception:
        return False


def elements_has_method(args: argparse.Namespace, method: str) -> bool:
    try:
        help_text = elements_cli(args, "help", method, timeout=5)
        return "unknown command" not in str(help_text).lower()
    except Exception:
        return False


def sidechain_info(args: argparse.Namespace) -> dict[str, Any] | None:
    info = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.ValidatorService/GetSidechains",
        None,
        timeout=args.timeout,
    )
    for item in info.get("sidechains", []):
        if item.get("sidechainNumber") == args.sidechain_id:
            return item
    return None


def require_sidechain_active(args: argparse.Namespace) -> dict[str, Any]:
    info = sidechain_info(args)
    if not info:
        raise BridgeError(
            f"sidechain {args.sidechain_id} is not listed; run scripts/activate-liquid-id5.sh first"
        )
    if "activationHeight" not in info:
        raise BridgeError(
            f"sidechain {args.sidechain_id} is listed but not active yet; run/mine activation first"
        )
    return info


def create_deposit(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    active_info = require_sidechain_active(args)
    payload = {
        "sidechainId": args.sidechain_id,
        "address": args.address,
        "valueSats": args.value_sats,
        "feeSats": args.fee_sats,
    }
    resp = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.WalletService/CreateDepositTransaction",
        payload,
        timeout=args.timeout,
    )
    txid = (resp.get("txid") or {}).get("hex") or resp.get("txid")
    if not txid:
        raise BridgeError(f"CreateDepositTransaction returned no txid: {resp}")
    item = append_unique(
        state["deposits"],
        "txid",
        {
            "txid": txid,
            "address": args.address,
            "value_sats": args.value_sats,
            "fee_sats": args.fee_sats,
            "status": "created_pending_confirmation",
            "created_at": now_iso(),
            "sidechain_activation": active_info,
            "enforcer_response": resp,
        },
    )
    state["events"].append({"kind": "deposit_created", "txid": txid, "ts": now_iso()})
    return item


def get_tip_hash(args: argparse.Namespace) -> str:
    if args.end_block_hash:
        return args.end_block_hash
    info = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.ValidatorService/GetChainTip",
        None,
        timeout=args.timeout,
    )
    block_hash = (((info.get("blockHeaderInfo") or {}).get("blockHash") or {}).get("hex") or {})
    if isinstance(block_hash, dict):
        value = block_hash.get("value")
    else:
        value = block_hash
    if not value:
        raise BridgeError(f"could not determine mainchain tip hash: {info}")
    return value


def unwrap_proto_value(value: Any) -> Any:
    if isinstance(value, dict):
        if "hex" in value:
            return value["hex"]
        if "value" in value:
            return value["value"]
    return value


def find_deposit_event(peg_data: dict[str, Any], txid: str) -> dict[str, Any] | None:
    wanted_txid = txid.lower()
    for block in peg_data.get("blocks", []):
        header = block.get("blockHeaderInfo") or block.get("block_header_info") or {}
        block_hash = unwrap_proto_value(header.get("blockHash") or header.get("block_hash"))
        block_info = block.get("blockInfo") or block.get("block_info") or {}
        for event in block_info.get("events", []):
            deposit = event.get("deposit")
            if not isinstance(deposit, dict):
                continue
            outpoint = deposit.get("outpoint") or {}
            event_txid = unwrap_proto_value(outpoint.get("txid"))
            if not isinstance(event_txid, str) or event_txid.lower() != wanted_txid:
                continue
            output = deposit.get("output") or {}
            address_hex = unwrap_proto_value(output.get("address"))
            try:
                address = bytes.fromhex(str(address_hex)).decode("utf-8")
                vout = int(unwrap_proto_value(outpoint.get("vout")))
                value_sats = int(
                    unwrap_proto_value(output.get("valueSats") or output.get("value_sats"))
                )
            except (TypeError, ValueError, UnicodeDecodeError):
                raise BridgeError(f"malformed BIP300 deposit event for {txid}: {deposit}")
            if not isinstance(block_hash, str) or len(block_hash) != 64:
                raise BridgeError(f"deposit event for {txid} has no containing block hash")
            return {
                "block_hash": block_hash,
                "txid": event_txid,
                "vout": vout,
                "address": address,
                "value_sats": value_sats,
            }
    return None


def reconcile_deposits(args: argparse.Namespace, state: dict[str, Any]) -> list[dict[str, Any]]:
    end_hash = get_tip_hash(args)
    payload = {
        "sidechainId": args.sidechain_id,
        "endBlockHash": {"hex": end_hash},
    }
    peg_data = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
        payload,
        timeout=args.timeout,
    )
    changed: list[dict[str, Any]] = []
    can_import = elements_available(args) and elements_has_method(args, "importdrivechaindeposit")
    for deposit in state["deposits"]:
        txid = deposit.get("txid")
        event = find_deposit_event(peg_data, txid) if txid else None
        if event is not None:
            if event["address"] != deposit["address"]:
                raise BridgeError(
                    f"deposit {txid} commits to address {event['address']}, "
                    f"not requested address {deposit['address']}"
                )
            if event["value_sats"] != deposit["value_sats"]:
                raise BridgeError(
                    f"deposit {txid} has value {event['value_sats']}, "
                    f"not requested value {deposit['value_sats']}"
                )
            deposit["status"] = "seen_in_two_way_peg_data"
            deposit["seen_in_two_way_peg_data_at"] = now_iso()
            deposit["mainchain_block_hash"] = event["block_hash"]
            deposit["mainchain_vout"] = event["vout"]
        if deposit.get("status") == "seen_in_two_way_peg_data":
            if can_import:
                import_resp = elements_cli(
                    args,
                    "importdrivechaindeposit",
                    txid,
                    str(deposit["mainchain_vout"]),
                    deposit["mainchain_block_hash"],
                    deposit["address"],
                    str(deposit["value_sats"]),
                    timeout=args.timeout,
                )
                deposit["status"] = "side_credit_imported"
                deposit["elements_import_response"] = import_resp
            else:
                deposit["status"] = "pending_side_credit"
                deposit["side_credit_blocker"] = (
                    "Elements RPC importdrivechaindeposit is not available; "
                    "deposit is real on CUSF but cannot be credited without a side import hook"
                )
        changed.append(deposit)
    state["events"].append(
        {
            "kind": "deposits_reconciled",
            "end_block_hash": end_hash,
            "deposit_count": len(state["deposits"]),
            "elements_import_hook_available": can_import,
            "ts": now_iso(),
        }
    )
    return changed


def broadcast_withdrawal(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    active_info = require_sidechain_active(args)
    bundle_hex = args.bundle_hex.strip().lower()
    if bundle_hex.startswith("0x"):
        bundle_hex = bundle_hex[2:]
    if len(bundle_hex) % 2 != 0:
        raise BridgeError("withdrawal bundle hex must have an even length")
    try:
        bundle_bytes = bytes.fromhex(bundle_hex)
    except ValueError as exc:
        raise BridgeError(f"withdrawal bundle is not valid hex: {exc}") from exc
    if not bundle_bytes:
        raise BridgeError("withdrawal bundle cannot be empty")
    payload = {
        "sidechainId": args.sidechain_id,
        "transaction": base64.b64encode(bundle_bytes).decode("ascii"),
    }
    resp = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        payload,
        timeout=args.timeout,
    )
    bundle_id = args.bundle_id or bundle_hex[:64]
    item = append_unique(
        state["withdrawals"],
        "bundle_id",
        {
            "bundle_id": bundle_id,
            "bundle_hex": bundle_hex,
            "status": "broadcast_submitted",
            "submitted_at": now_iso(),
            "sidechain_activation": active_info,
            "enforcer_response": resp,
        },
    )
    state["events"].append({"kind": "withdrawal_broadcast", "bundle_id": bundle_id, "ts": now_iso()})
    return item


def reconcile_withdrawals(args: argparse.Namespace, state: dict[str, Any]) -> list[dict[str, Any]]:
    end_hash = get_tip_hash(args)
    payload = {
        "blockHash": {"hex": end_hash},
        "sidechainId": args.sidechain_id,
    }
    block_info = grpc_curl(
        args.enforcer,
        "cusf.mainchain.v1.ValidatorService/GetBlockInfo",
        payload,
        timeout=args.timeout,
    )
    raw = json.dumps(block_info)
    for withdrawal in state["withdrawals"]:
        bundle_id = withdrawal.get("bundle_id", "")
        bundle_hex = withdrawal.get("bundle_hex", "")
        if (bundle_id and bundle_id.lower() in raw.lower()) or (
            bundle_hex and bundle_hex[:32].lower() in raw.lower()
        ):
            withdrawal["status"] = "seen_in_block_info"
            withdrawal["seen_in_block_info_at"] = now_iso()
        elif withdrawal.get("status") == "broadcast_submitted":
            withdrawal["status"] = "broadcast_pending_event"
    state["events"].append(
        {
            "kind": "withdrawals_reconciled",
            "end_block_hash": end_hash,
            "withdrawal_count": len(state["withdrawals"]),
            "ts": now_iso(),
        }
    )
    return state["withdrawals"]


def status(args: argparse.Namespace, state: dict[str, Any]) -> dict[str, Any]:
    result = {
        "state_file": str(args.state_file),
        "sidechain_id": args.sidechain_id,
        "sidechain": sidechain_info(args),
        "deposit_count": len(state["deposits"]),
        "withdrawal_count": len(state["withdrawals"]),
        "elements_rpc_available": elements_available(args),
        "elements_importdrivechaindeposit_available": False,
    }
    if result["elements_rpc_available"]:
        result["elements_importdrivechaindeposit_available"] = elements_has_method(
            args, "importdrivechaindeposit"
        )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Liquid ID5 production peg bridge")
    parser.add_argument("--enforcer", default="127.0.0.1:50051")
    parser.add_argument("--sidechain-id", type=int, default=DEFAULT_SIDECHAIN_ID)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--elements-cli", default=str(DEFAULT_ELEMENTS_CLI))
    parser.add_argument("--elements-datadir", default=str(DEFAULT_ELEMENTS_DATADIR))
    parser.add_argument("--elements-rpcport", default=DEFAULT_ELEMENTS_RPCPORT)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--end-block-hash", default="")
    sub = parser.add_subparsers(dest="command", required=True)

    deposit = sub.add_parser("deposit", help="create a real CUSF deposit transaction")
    deposit.add_argument("--address", required=True)
    deposit.add_argument("--value-sats", type=int, required=True)
    deposit.add_argument("--fee-sats", type=int, default=2000)

    sub.add_parser("reconcile-deposits", help="reconcile deposits with CUSF peg data")

    withdrawal = sub.add_parser("withdraw", help="broadcast a real side-produced withdrawal bundle")
    withdrawal.add_argument("--bundle-hex", required=True)
    withdrawal.add_argument("--bundle-id", default="")

    sub.add_parser("reconcile-withdrawals", help="reconcile withdrawal events")
    sub.add_parser("status", help="print bridge status")
    sub.add_parser("normalize-state", help="rewrite state as structured JSON")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    state = load_state(args.state_file, args.sidechain_id)

    try:
        if args.command == "deposit":
            result = create_deposit(args, state)
        elif args.command == "reconcile-deposits":
            result = reconcile_deposits(args, state)
        elif args.command == "withdraw":
            result = broadcast_withdrawal(args, state)
        elif args.command == "reconcile-withdrawals":
            result = reconcile_withdrawals(args, state)
        elif args.command == "status":
            result = status(args, state)
        elif args.command == "normalize-state":
            if LEGACY_STATE_FILE.exists() and not args.state_file.exists():
                legacy = load_state(LEGACY_STATE_FILE, args.sidechain_id)
                state["events"].extend(legacy.get("events", []))
            result = {"normalized": True, "state_file": str(args.state_file)}
        else:
            raise BridgeError(f"unknown command {args.command}")
        save_state(args.state_file, state)
        print(json.dumps({"ok": True, "result": result, "state": state}, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        state["events"].append({"kind": "bridge_error", "error": str(exc), "ts": now_iso()})
        save_state(args.state_file, state)
        print(json.dumps({"ok": False, "error": str(exc), "state": state}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
