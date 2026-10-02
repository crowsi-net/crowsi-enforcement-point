# crowsi-enforcement-point

Verify a bounded execution authorization and retain evidence of its consumption.

## What you can do

- Reject expired, mismatched or replayed authorizations.
- Produce a signed execution receipt through the configured interface.

## Current scope

Execution adapters and signing custody must be configured. A receipt alone is not independent proof of an external effect.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Examples and interface details

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

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Schemas](schemas) · [Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
