# USDD raw-compressed SP1 verifier jet

Status: normative implementation contract; **not implemented or activated**.

The minimal consensus interface is one Elements environmental jet:

```text
verify_sp1_compressed_sha256 :
    (TWO^256 * TWO^256) |- TWO
```

The two inputs are, in order:

1. the SP1 `HashableKey::hash_bytes` program ID, encoded as eight canonical
   KoalaBear words in big-endian order; and
2. `SHA256(public_values)`, where `public_values` is the exact canonical USDD
   journal encoding supplied separately as typed Simplicity witness data.

The output is true if and only if every condition below succeeds.  Every
absence, malformed encoding, unsupported mode, arithmetic failure, verifier
failure, and unsuccessful guest exit produces false.  The C jet itself must
remain a total function for every bit-pattern input and every bounded annex.

## Environmental input

The jet reads the current input's exact owned Taproot annex directly from the
opaque `elementsTransaction` using the authenticated `txEnv` input index.  The
annex must be present, must include the `0x50` tag, and must not exceed 512 KiB.
It is the byte-for-byte copy already checked to equal `0x50` followed by the
tag-stripped annex body used by the released transaction-hash jets.

A generic Simplicity value containing 512 KiB is neither required nor
appropriate.  Simplicity has fixed algebraic types, so a variable-length annex
would otherwise require an indexed-byte environmental API and a very large
unrolled parser.  That would expand consensus surface without helping the
controller: the verifier alone needs the opaque proof bytes.  Consequently V1
must not add a separate full-annex byte jet.

## Envelope and proof rules

The jet must strictly parse the exact V1 envelope documented in
`src/script/usdd_sp1_annex.h` and reject:

- any namespace, envelope version, statement kind, proof system, digest mode,
  or flag other than the frozen V1 values;
- empty public values or proof bytes;
- public values larger than 16 KiB or a combined annex larger than 512 KiB;
- a zero or noncanonical program ID;
- declared-length mismatch, integer overflow, trailing bytes, or alternate
  encodings;
- a program ID different from the first jet input;
- a SHA-256 digest of the annex public values different from the second input;
- Core, Groth16, PLONK, or any other SP1 proof mode; and
- any raw-compressed SP1 proof that does not verify with a successful guest
  exit under the frozen SP1 6.3.1 recursion/verifier constants.

The proof verifier must not accept a host-provided digest as a substitute for
hashing the public-values bytes actually carried in the annex.  It must not
call RPC, read wall-clock time, use a mutable allowlist, or depend on process
configuration.

## Controller binding

The controller receives a fixed, typed representation of the V1 public journal
through its ordinary Simplicity witness.  It must:

1. strictly validate and canonically serialize that value;
2. compute `SHA256(canonical_public_values)` inside Simplicity;
3. call this jet with the frozen Ethereum guest program ID and that digest;
4. require true; and
5. derive every state, nonce, issuance, recipient, and successor-output check
   from the same typed value.

This makes the annex proof and the transaction constraints inseparable without
making opaque proof bytes available to the rest of the program.

## Generation and cost

The verifier is a new consensus primitive and must pass through the official
Simplicity primitive model, catalogue, serialization, C FFI, C implementation,
cost table, `GenDecodeJet`, and `GenPrimitive --elements` pipeline.  Its type,
decoder index, CMR, cost, SP1 constants, and exact source revision must be
frozen together.

Charge a fixed worst-case cost for the maximum accepted annex, including
strict parsing, SHA-256 of the maximum public-values region, and complete
verification of a worst-case valid raw-compressed proof.  Early rejection may
run faster but must not receive a lower consensus charge.  Peak allocation must
remain below the frozen verifier-memory limit on all supported architectures.

No accepting implementation may be merged until there is:

- a reproducibly built positive raw-compressed proof fixture;
- independent negative fixtures for every parser and verifier boundary;
- model/C differential tests and cross-architecture deterministic results;
- measured worst-case time, memory, proof size, and block-weight results; and
- an independently reviewed SP1-to-consensus implementation.

The current `VERIFIER_UNAVAILABLE` result is therefore intentional.  Adding a
jet that always returns false would freeze a useless consensus identity;
adding one that trusts a host callback would create an invalid mint authority.

## Atomic activation

Activation must atomically freeze the verifier jet and controller CMR, pin the
one Ethereum guest program ID, and replace the host-level fail-closed annex
gate.  Before that activation, every USDD proof remains invalid.  After it,
the controller program—not envelope parsing alone—must require the verifier
jet's true result.  Non-USDD annex behavior must remain unchanged.
