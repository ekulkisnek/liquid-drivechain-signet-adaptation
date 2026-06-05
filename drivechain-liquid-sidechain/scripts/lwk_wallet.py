#!/usr/bin/env python3
import sys
import os
import json
import argparse
import lwk

DEFAULT_DATADIR = "/tmp/liquid-id5-regtest/lwk_wallet"
ELECTRUM_URL = "tcp://127.0.0.1:60401"
POLICY_ASSET = "0000000000000000000000000000000000000000000000000000000000000000"

def get_network():
    return lwk.Network.regtest(POLICY_ASSET)

def get_mnemonic(datadir):
    os.makedirs(datadir, exist_ok=True)
    mnemonic_path = os.path.join(datadir, "mnemonic.txt")
    if os.path.exists(mnemonic_path):
        with open(mnemonic_path, "r") as f:
            return f.read().strip()
    else:
        # Generate new random 12-word mnemonic
        net = get_network()
        # Random mnemonic
        mnemonic = lwk.Mnemonic.from_random(12)
        mnemonic_str = str(mnemonic)
        with open(mnemonic_path, "w") as f:
            f.write(mnemonic_str)
        return mnemonic_str

def get_wallet(datadir):
    net = get_network()
    mnemonic_str = get_mnemonic(datadir)
    mnemonic = lwk.Mnemonic(mnemonic_str)
    signer = lwk.Signer(mnemonic, net)
    desc = signer.wpkh_slip77_descriptor()
    wallet = lwk.Wollet(net, desc, datadir)
    return wallet, signer

def sync_wallet(wallet):
    client = lwk.ElectrumClient.from_url(ELECTRUM_URL)
    update = client.full_scan(wallet)
    if update:
        wallet.apply_update(update)
    return client

def main():
    parser = argparse.ArgumentParser(description="LWK CLI wallet utility")
    parser.add_argument("--datadir", default=DEFAULT_DATADIR, help="Data directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Initialize and print wallet descriptor")
    subparsers.add_parser("address", help="Get a new receive address")
    subparsers.add_parser("balance", help="Get wallet balances")
    subparsers.add_parser("transactions", help="List wallet transactions")

    send_parser = subparsers.add_parser("send", help="Send L-BTC to address")
    send_parser.add_argument("address", help="Destination address")
    send_parser.add_argument("amount_sats", type=int, help="Amount in satoshis")
    send_parser.add_argument("--fee-rate", type=float, default=1000.0, help="Fee rate in sats/kvb")

    args = parser.parse_args()

    try:
        wallet, signer = get_wallet(args.datadir)

        if args.command == "init":
            print(json.dumps({
                "mnemonic_file": os.path.join(args.datadir, "mnemonic.txt"),
                "descriptor": str(wallet.descriptor()),
                "dwid": wallet.dwid()
            }, indent=2))
            return 0

        # For actual queries/operations, we must sync the wallet
        client = sync_wallet(wallet)

        if args.command == "address":
            addr_res = wallet.address(None)
            print(json.dumps({
                "address": str(addr_res.address()),
                "index": addr_res.index()
            }, indent=2))

        elif args.command == "balance":
            balances = {}
            for asset, amount in wallet.balance().items():
                balances[str(asset)] = amount
            print(json.dumps({
                "balances": balances
            }, indent=2))

        elif args.command == "transactions":
            txs = []
            for tx in wallet.transactions():
                balances = {}
                for asset, amt in tx.balance().items():
                    balances[str(asset)] = amt
                txs.append({
                    "txid": str(tx.txid()),
                    "height": tx.height(),
                    "timestamp": tx.timestamp(),
                    "type": tx.type(),
                    "fee": tx.fee(),
                    "balance": balances
                })
            # Sort by height/timestamp (unconfirmed height=None, put them at the end or start)
            txs.sort(key=lambda t: (t["height"] or 999999999, t["timestamp"] or 0), reverse=True)
            print(json.dumps(txs, indent=2))

        elif args.command == "send":
            dest_addr = lwk.Address(args.address)
            builder = lwk.TxBuilder(get_network())
            builder.add_lbtc_recipient(dest_addr, args.amount_sats)
            builder.fee_rate(args.fee_rate)
            
            pset = builder.finish(wallet)
            signed_pset = signer.sign(pset)
            tx = signed_pset.finalize()
            
            txid = client.broadcast(tx)
            print(json.dumps({
                "success": True,
                "txid": str(txid)
            }, indent=2))

        return 0
    except Exception as e:
        print(json.dumps({
            "success": False,
            "error": str(e)
        }, indent=2), file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
