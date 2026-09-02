# Security report remediation (2026-09-02)

Scope: the report against `295a4ea293`, reviewed against the actual native
`-chain=elements` execution path. These changes are not an independent audit,
a release certification, or authorization to use real funds. No live node,
wallet, parent deployment or preserved historical data was changed for testing.

## Findings and changes

1. **Parent identity and historical signet code.** Preserve the frozen native
   identity, not a newly chosen parent: slot 24, Bitcoin-mainnet ancestry,
   empty signet challenge and checkpoint 995347. Native BMM admission already
   uses `GetDrivechainBmmBlockStatus` and authenticated parent replay in
   `validation.cpp`; it does not use the historical signet proof verifier.
   Added explicit guards rejecting the historical proof bit, commitment, proof
   bytes and persisted signet BMM state on native Elements. Native callers
   cannot obtain historical effective BMM state. Corrected the cookie default
   and operations docs; no genesis, proof-of-work or activation constants changed.
   The report's claimed simultaneous native signet/mainnet validation was not
   reproduced. Changing those constants to match old instructions would create
   a different consensus network, not fix the current deployment.
2. **Plaintext enforcer path.** Removed the HTTP ConnectJSON implementation.
   BMM wallet requests, validator queries and legacy withdrawal submission now
   share the allowlisted mTLS gRPC helper and one configured endpoint. Endpoint
   mismatches, missing credentials, process failures, timeouts, oversized output
   and non-object responses fail closed. Parent/wallet HTTP and a same-host
   proxy's upstream hop remain loopback-only, not encrypted; see
   [the exact trust boundaries](drivechain-rpc-security.md).
3. **Custody environment overrides.** Removed the wallet RPC's environment
   reads for slot, endpoint, fee and optional event verification. The historical
   ECX withdrawal path fixes slot 24, requires authenticated event verification
   and takes its positive bounded fee from explicit configuration. Its transport
   configuration is checked before mutation. Native burn/M6 semantics remain
   unchanged and supported.
4. **Executable trust.** Removed grpcurl discovery and PATH fallback. Require
   an explicitly configured absolute executable, regular and non-symlink, with
   the private-key owner/permission/directory checks and executable permission.
   No shell is invoked. This does not hash-pin the executable or defend against
   compromise of the same user, root, or a writable ancestor directory.
5. **Enforcer endpoint.** Require numeric loopback, including with TLS. Reject
   DNS/LAN endpoints, conflicting deprecated wallet endpoints and the old bearer
   cookie option. Also fixed the proxy helper's former `127.*` hostname loophole
   using strict numeric address/port validation.
6. **OP_TRUE blocks.** Retained the intentional signblock syntax. Native block
   admission separately requires BMM authorization from authenticated parent
   replay. It was not replaced with a federation or a permissive bypass.
7. **Runtime CTIP bootstrap.** Removed the historical runtime genesis-CTIP
   parser, cache and connect/disconnect exceptions. Missing authenticated CTIP
   state fails closed. Native deposits still bootstrap through their frozen
   identity and authenticated parent replay, including the first deposit test.
8. **Release safety.** Pinned workflow actions, made default permissions
   read-only, isolated publication permissions to a dependent job with an
   `elements-release` environment, removed implicit source/tag defaults and
   artifact replacement, and verify the exact draft tag/source before upload.
   The old recipes are explicitly limited to their historical source revision;
   they must not masquerade as a current SP1-enabled release. Linux packaging
   now fails when its unit-test gate fails.
9. **Reporting.** Replaced upstream's reporting policy with this fork's contact,
   `camo007@duck.com`. Request a secure channel before sending sensitive evidence;
   no PGP key or encrypted email channel is claimed.
10. **SP1 documentation.** The jet is implemented, and the native build/startup
    checks the pinned verifier identity. Updated the obsolete document to match
    the C/Rust integration and bounded input limits. No cryptographic-verifier
    or activation changes were needed for this finding.
11. **Certificates.** Reduced generated CA lifetime to 365 days and leaf
    lifetime to 90 days, added IPv6 loopback SAN and refusal to overwrite
    credentials (including dangling symlinks). Documented rotation and expiry
    checks. Existing certificates are not silently replaced.

Additional findings: replaced quarantined slot-5 entry-point bodies with inert
failures on both Python import and execution; generated random per-run tutorial
RPC passwords in exclusive owner-only files; removed `curl --insecure`; added
CodeQL and Actions Dependabot configuration; gave alternate identity headers
distinct guards with a hard mixed-identity error; rejected unauthenticated
native REST explicitly. Historical tutorial network instructions remain
unsupported on the native-only binary.

## Withdrawal availability

These fixes do not disable native withdrawals. Use the documented
`sendtomainchain` burn, inspect the exact claim with
`getdrivechainwithdrawalbundle`, submit with `submitdrivechainwithdrawal`, and
verify actual parent payment. See [the native workflow](drivechain-peg-operations.md).
The historical recovery journal API is not the native withdrawal path.

A burn can be constructed while the enforcer is unavailable. Check the
authenticated submission path before burning; no startup TLS handshake or
guaranteed miner payment is implied. After an uncertain submission, inspect
and resubmit the same claim rather than create another burn.

## Local validation

Validated on macOS arm64 in an isolated out-of-tree build with the pinned native
USDD SP1 verifier linked, tests enabled, and two build workers. No daemon was
started and no transaction was created or broadcast.

Reproducible gates after configuring the build:

```sh
make -j2
make -C src -j2 test/test_bitcoin
src/test/test_bitcoin \
  --run_test=validation_tests,elements_startup_validation_tests,drivechain_withdrawal_tests,pegin_witness_tests,rpc_tests \
  --log_level=error --report_level=detailed
src/test/test_bitcoin --log_level=error --report_level=detailed
python3 <source>/contrib/drivechain-mtls/test_security_helpers.py
```

- Production build and test binary build completed successfully.
- Focused node suite: **87 tests, 30,205 assertions passed**. Includes native
  first deposit, CTIP/replay validation, miner-authorized M6, withdrawal codec
  uniqueness, native/historical BMM separation, RPC cookies and mTLS constraints.
- Operational suite: **7 tests passed**. Actual TLS authentication and stunnel
  forwarding, missing/wrong client identity, wrong hostname/untrusted server,
  certificate expiry/permissions, refusal to overwrite, numeric endpoints,
  tutorial secrets and incompatible identity-header combinations.
- Full node suite: **not green**. One ECX source-vector test aborts with
  `ECX bond-inbox custody verifier is not compiled in`; that optional verifier
  is separate from the linked native USDD SP1 verifier. The remaining 648 tests
  passed (one with warnings). This test and its checks were not disabled or
  weakened to obtain a pass.
- Shell syntax, Python parsing, YAML structure and action-pin checks passed.
  These are not hosted GitHub execution results.

## Outstanding release gates

- Configure/link the separate ECX custody verifier and rerun the full suite,
  or explicitly establish and test a supported native-only build/test scope.
  A missing dependency is not evidence that its cryptographic path works.
- Build/test current verifier-enabled Linux and Windows artifacts and a portable
  macOS artifact. The local Homebrew-linked macOS build emitted deployment-target
  warnings and is not a portable release. Authenticated external gRPC execution
  remains fail-closed on Windows pending a secure equivalent implementation.
- Build current release recipes with exact source/verifier provenance, test
  evidence and immutable artifact checksums. The historical recipes deliberately
  cannot publish the current native revision.
- A repository administrator must configure environment protection/approvers
  for `elements-release`, then verify hosted CI, code scanning and Dependabot
  run successfully. Merely naming an environment does not create approval rules.
- Verify end-to-end native BMM, deposit and M6 payment through the deployed
  enforcer's mTLS service, including reflection/descriptors, fees, restart and
  reorg behavior. Local fixtures and the proxy handshake are not live miner
  inclusion evidence. No new public transaction was needed for these fixes.
- Independently review the consensus/custody changes and verify the intended
  parent checkpoint/activation. Do not infer network identity from an address
  prefix or describe this branch as ready for production funds.
