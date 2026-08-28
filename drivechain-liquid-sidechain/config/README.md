# Quarantined configuration

The JSON file in this directory is the retired slot-5 proposal preserved for
historical audit purposes. Do not submit it to an enforcer. It is incompatible
with this fork's sole supported **Elements Drivechain** identity at BIP300 slot
24. Use `elementsd -chain=elements` and the identity documented in the
[canonical repository README](../../README.md).

All scripts that previously consumed this proposal now exit before reading or
submitting it.
