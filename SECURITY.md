# Security Policy

## Reporting a Vulnerability

For this fork, contact **camo007@duck.com** privately. Do not open a public issue
or pull request containing an undisclosed vulnerability or working exploit.
Blockstream does not maintain this fork or receive its security reports.

Start with a brief, non-sensitive description and request a secure channel for
detailed evidence. No PGP key is currently published for this address; ordinary
email is not an end-to-end encrypted reporting channel.

Include the affected commit and network identity, impact, prerequisites,
reproduction steps using isolated test assets, relevant redacted logs, and any
proposed fix. Never include seed phrases, private keys, RPC cookies, passwords,
TLS private keys, or other users' data. Do not test exploits against live users.

Coordinate disclosure timing with the maintainer. Issues affecting upstream
Elements, Bitcoin, or other dependencies should also be reported through those
projects' own security policies, without assuming that this fork's contact
automatically reaches them.

## Scope and Support

Report issues in consensus, deposits, withdrawals, RPC transport, dependencies,
and release artifacts. State the exact source SHA and binary checksum. A patch
or successful test run is not a claim of an independent audit or production
readiness. Historical slot-5 tools and obsolete network identities are not
supported deployments.
