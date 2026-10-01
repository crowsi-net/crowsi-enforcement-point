# Crowsi Enforcement Point

This crate is the fail-closed provider enforcement boundary for Crowsi. It
accepts a PA-issued execution lease, verifies its command, consumes the
authorization at the provider boundary, and returns a signed receipt.

## Wire contract

The only supported wire contract is the closed Crowsi control v2 set:

- `crowsi://control/isolation-command/v2`
- `crowsi://control/pep-execution-lease/v2`
- `crowsi://control/enforcement-receipt/v2`

The three control schemas and structural sample fixtures are released copies
from `crowsi-control-contracts`. They are deliberately local artifacts rather
than a source-tree or Cargo path dependency. Compatibility tests load these
artifacts as an external consumer would. Sample fixture signatures outside the
conformance directory are structural placeholders and are not trust evidence.
The command parser also independently enforces the same bounded canonical
SPIFFE workload identity, so an alternative URI spelling cannot cross the PEP.

`fixtures/conformance/v1/` contains a byte-identical released PA artifact
produced by `reserve_v2` followed by `begin_execution_v2`, plus its public-only
trust manifest. It also contains the exact signed receipt produced by the PEP
and `pep-receipt-trust-manifest-v1.json`. A generation test verifies both
signature and byte-for-byte serialization without a cross-repository
dependency. All conformance private keys exist only in test code.

Commands and receipts use the control-v2 canonical field encoding. The
canonical payload excludes `signed`, is SHA-256 digested, and the PEP's
Ed25519 verifier checks the digest bytes. Receipt signing is delegated through
`ReceiptSigningPort` to an external HSM, TPM, or credential broker, then
verified against a separately pinned public key. The library exposes no
software private-key constructor. Command and receipt roles must use distinct
key identifiers and distinct public key material. A lease is accepted only
when its reservation, embedded command, and command digest agree.

## Provider boundary

Supported adapter kinds share one port:

- host controls;
- host firewall controls;
- cloud-provider controls;
- optional Incus controls.

A valid greater fence is durably consumed before provider resource-version
comparison. A resource-version conflict is therefore a rejected operation that
still advances the fence; neither a retry nor a restart can reuse that fence.
The command JTI and reservation provide replay-safe receipt recovery.

The bundled `MemoryProvider` and `SqliteProvider` are conformance adapters.
They never access a host, firewall, cloud API, or Incus socket and are not
production adapters. A real adapter must implement `EnforcementAdapter` while
preserving exact resource binding, durable monotonic fencing, provider-native
CAS, and idempotency.

Production execution time comes from the PEP process clock; callers cannot
submit an `applied_at` value. Fixed-time execution exists only in debug/test
builds. The trusted time is durably watermarked in the PEP ledger, so host
clock rollback is rejected after process restart. The CLI sample contains its
own isolated deterministic signing keys and never exports them through the
library API.

An `applied` receipt proves what this PEP attempted and recorded. It does not
prove containment. `crowsi-independent-verifier` must read the resulting state
through an independently trusted sensor.

The local conformance sample performs no network access:

```bash
cargo run --offline --quiet -- sample
```

## Verification

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
```
