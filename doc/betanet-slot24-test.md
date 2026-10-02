# Existing-Proposal Slot-24 Test Deployment

This profile is explicitly for operator-authorized testing on Betanet slot24.
It authenticates the existing Elements proposal
`866e33f1e4c854fadea9f9792064708ced3633bc963b000a03d4d4ac2e1a2400`,
activated at parent970715. That proposal describes historical replay-v4 rules;
this child uses current Betanet replay-v5/NOP8 rules. It is NOT the historical
Alpha network, nor a claim that the parent proposal commits the new child code.

The independent child manifest, genesis and asset commit the new rules. Full
parent replay, exact proposal matching, mined BMM authentication, deposit and
withdrawal checks remain required. No runtime slot/proposal bypass was added.

- Genesis: `a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f`
- Native asset: `5836dcc06130dcf6a65b6ac493813fd65559955283e44cc3f07966294eccb2c8`
- P2P magic: `3b5ff18b`
- Data namespace: `elements-betanet-slot24-v1`

Use a fresh data directory and fresh sidechain wallet. Never relabel the old
slot130 or Alpha databases. Existing USDD/futures deployments require new
chain-specific bindings; their old state does not migrate into this genesis.

Validation on October2: all23 independent identity tests and99 focused native
tests/34872 assertions passed. Native startup independently reproduces the
genesis and authenticates parent replay. This is not full release qualification
or proof of mined-block inclusion. No enforcer source changes were made.
