# Using crowsi-enforcement-point

Verify a bounded execution authorization and retain evidence of its consumption.

## Before you start

Execution adapters and signing custody must be configured. A receipt alone is not independent proof of an external effect.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Reject expired, mismatched or replayed authorizations.
- Produce a signed execution receipt through the configured interface.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
