# Security boundary

This repository contains no provider credentials and ships no production
network mutation adapter. `MemoryProvider` and `SqliteProvider` are local
conformance tools; do not connect them to a real network or treat their output
as independent evidence.

## Fail-closed processing

The PEP must preserve this ordering:

1. reject anything outside the three closed control-v2 schemas;
2. bind the lease reservation and digest to its embedded signed command;
3. verify the pinned PA key, security domain, deployment, and validity window;
4. reserve command JTI and release reservation idempotently;
5. require exact provider, deployment, domain, and resource binding;
6. durably consume a previously unseen greater fence;
7. compare the provider-native expected resource version;
8. attempt the mutation and persist a signed v2 receipt.

The validity check uses PEP-owned trusted time. Production callers cannot
inject the evaluation or receipt timestamp. `ReceiptSigningPort` must terminate
at an HSM, TPM, or credential broker; the returned signature is verified
against the separately configured `TrustedReceiptKey` before it is persisted.
The PA command and PEP receipt roles must not share either a key identifier or
public key material; `EnforcementPoint::new` rejects both forms of reuse.
The ledger watermark detects clock rollback across restart. Production still
requires a signed external time or rollback anchor to detect rollback of the
entire database and host snapshot.

Step 6 intentionally precedes step 7. A valid command with a stale expected
resource version is rejected, but its greater fence remains consumed across
process and machine restarts. Rolling that fence back would let an older
authorization become executable again.

Timeout, unavailable, missing-target, and partial results are non-success
receipts with residual exposure. They require reconciliation and independent
read-back. Receipt signatures authenticate the PEP record; they do not turn a
provider response into proof of containment.

## Production adapter requirements

A production adapter must additionally supply:

- hardware- or workload-bound adapter identity;
- hardware-backed `ReceiptSigningPort` with non-exportable key material;
- least-privilege credentials from a local credential broker;
- provider-native compare-and-swap plus durable monotonic fencing;
- durable idempotency at the actual mutation boundary;
- bounded calls with explicit timeout and unknown-result reconciliation;
- immutable audit export without secrets or raw provider payloads;
- an independently administered sensor and verifier path.

Do not weaken exact URI, audience, domain, deployment, or key binding into
prefix or display-name matching. Do not log signatures' private material,
credentials, customer identifiers, network addresses, or unredacted provider
responses.

Report suspected bypasses privately with a redacted reproduction, affected
contract URI, and observed fence/idempotency state.

## Private vulnerability reporting

Report vulnerabilities through this repository's GitHub private vulnerability reporting form. Do not put credentials, personal or customer data, or production certificate material in public issues or pull requests.
