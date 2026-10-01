use crate::{AdapterOutcome, ProviderRequest};

pub trait EnforcementAdapter: Send + Sync {
    fn apply(&self, request: &ProviderRequest) -> AdapterOutcome;
}
