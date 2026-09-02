# Historical V7 identity fixture

`elements-v7-identity.h` and `legacy_v7_identity.py` are byte-preserved from the
2026-07-21 ARM64 Elements source archive. They independently reproduce the V7
genesis `3336884b616fb495e5faedc77be45bf2951b9d7d0887aaafd2f54873a8ddb1d6`
used by the published withdrawal/checkpoint vectors in `doc/`.

These files are test fixtures only. They are not compiled into the node and
must not be used as the live Alpha identity. Keeping the historical serializer
avoids relabelling historical vectors as Alpha or weakening their derivation
checks when the built-in network changes.
