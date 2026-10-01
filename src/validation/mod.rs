mod command;
mod common;
mod receipt;
mod time;
mod workload;

use crate::{EnforcementReceiptV2, IsolationCommandV2, PepExecutionLeaseV2, Result};

pub(crate) use common::{digest, identifier, opaque};
pub(crate) use time::{in_window, timestamp};

impl IsolationCommandV2 {
    /// Validates the released V2 wire contract and canonical digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unbound, expired-shape, or digest-mismatched commands.
    pub fn validate_contract(&self) -> Result<()> {
        command::validate(self)
    }
}

impl PepExecutionLeaseV2 {
    /// Validates the released V2 lease and its exact command reservation.
    ///
    /// # Errors
    ///
    /// Rejects malformed leases or any reservation, digest, or time mismatch.
    pub fn validate_contract(&self) -> Result<()> {
        command::lease(self)
    }
}

impl EnforcementReceiptV2 {
    /// Validates the released V2 receipt and canonical digest.
    ///
    /// # Errors
    ///
    /// Rejects malformed receipts, incomplete outcomes, or digest mismatch.
    pub fn validate_contract(&self) -> Result<()> {
        receipt::validate(self)
    }
}
