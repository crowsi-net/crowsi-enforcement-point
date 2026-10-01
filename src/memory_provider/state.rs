use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::{AdapterOutcome, PepError, ResourceRecord, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FaultMode {
    #[default]
    None,
    Unavailable,
    TimeoutBeforeApply,
    TimeoutAfterApply,
    PartialApply,
}

#[derive(Default)]
pub(crate) struct ProviderState {
    pub(crate) resources: BTreeMap<String, ResourceRecord>,
    pub(crate) outcomes: BTreeMap<String, (String, AdapterOutcome)>,
    pub(crate) next_fault: FaultMode,
    pub(crate) invocations: u64,
}

pub struct MemoryProvider {
    pub(crate) state: Mutex<ProviderState>,
}

impl Default for MemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryProvider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ProviderState::default()),
        }
    }

    /// Registers one resource in the local conformance adapter.
    ///
    /// # Errors
    ///
    /// Rejects missing bindings or duplicate resource identifiers.
    pub fn register(&self, record: ResourceRecord) -> Result<()> {
        let mut state = self.lock();
        if state.resources.contains_key(&record.resource_uri)
            || record.resource_uri.is_empty()
            || record.security_domain.is_empty()
            || record.deployment_id.is_empty()
            || record.provider.is_empty()
            || record.resource_version.is_empty()
        {
            return Err(PepError::Validation("resource registration".into()));
        }
        state.resources.insert(record.resource_uri.clone(), record);
        Ok(())
    }

    /// Injects a single local conformance failure for the next adapter call.
    pub fn set_next_fault(&self, fault: FaultMode) {
        self.lock().next_fault = fault;
    }

    #[must_use]
    pub fn invocation_count(&self) -> u64 {
        self.lock().invocations
    }

    #[must_use]
    pub fn snapshot(&self, resource_uri: &str) -> Option<ResourceRecord> {
        self.lock().resources.get(resource_uri).cloned()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ProviderState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
