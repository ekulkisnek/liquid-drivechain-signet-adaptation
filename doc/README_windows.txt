Elements Core
=============

Intro
-----
This package contains the canonical Elements Drivechain node and wallet for
BIP300 slot 24. The production binaries support only `-chain=elements`.
Legacy Liquid, Bitcoin, testnet, Signet, regtest, and custom identities cannot
be selected as the child chain in these binaries.


Setup
-----
Unpack the files into a directory and run elements-qt.exe.

Elements validation requires a local, fully validating parent Signet node on a
loopback RPC address. See the project documentation for configuration details:
  https://github.com/ElementsProject/elements/tree/master/doc
