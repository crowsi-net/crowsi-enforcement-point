use rusqlite::{Transaction, TransactionBehavior, params};

use crate::{
    AdapterOutcome, AdapterStatus, ControlAction, EnforcementAdapter, PepError, ProviderRequest,
    ResourceState, Result,
};

use super::SqliteProvider;

impl EnforcementAdapter for SqliteProvider {
    fn apply(&self, request: &ProviderRequest) -> AdapterOutcome {
        self.apply_result(request)
            .unwrap_or_else(super::persist::storage_unknown)
    }
}

impl SqliteProvider {
    fn apply_result(&self, request: &ProviderRequest) -> Result<AdapterOutcome> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((digest, outcome)) =
            super::persist::previous(&transaction, &request.command_jti)?
        {
            return if digest == request.command_digest {
                serde_json::from_str(&outcome).map_err(PepError::from)
            } else {
                Ok(super::rules::rejected("provider-idempotency-conflict"))
            };
        }
        let Some(resource) = super::store::resource(&transaction, &request.resource_uri)? else {
            return super::persist::finish(
                transaction,
                request,
                AdapterOutcome::unknown("provider-unreachable"),
            );
        };
        if let Some(outcome) = super::rules::binding(&resource, request) {
            return super::persist::finish(transaction, request, outcome);
        }
        if super::rules::stale(&resource, request) {
            return super::persist::finish(
                transaction,
                request,
                super::rules::rejected("stale-fence"),
            );
        }
        if consume_fence(&transaction, request)? != 1 {
            return super::persist::finish(
                transaction,
                request,
                AdapterOutcome::unknown("provider-fence-cas-race"),
            );
        }
        if request.expected_resource_version != resource.resource_version {
            let outcome = super::rules::rejected_after_fence(
                "resource-version-conflict",
                &resource,
                request.fence,
            );
            return super::persist::finish(transaction, request, outcome);
        }
        let state = state_for(request.action);
        let version = format!("rv:{}:{}", request.provider, request.fence);
        let changed = mutate(&transaction, request, state, &version)?;
        let outcome = if changed == 1 {
            AdapterOutcome {
                status: AdapterStatus::Applied,
                reason_code: "applied".into(),
                changed_state: true,
                resource_version: Some(version),
                fence: Some(request.fence),
                state: Some(state),
            }
        } else {
            AdapterOutcome::unknown("provider-cas-race")
        };
        super::persist::finish(transaction, request, outcome)
    }
}

fn consume_fence(transaction: &Transaction<'_>, request: &ProviderRequest) -> Result<usize> {
    transaction
        .execute(
            "UPDATE provider_resources SET latest_fence = ?1
             WHERE resource_uri = ?2 AND latest_fence < ?1",
            params![request.fence, request.resource_uri],
        )
        .map_err(PepError::from)
}

fn mutate(
    transaction: &Transaction<'_>,
    request: &ProviderRequest,
    state: ResourceState,
    version: &str,
) -> Result<usize> {
    transaction
        .execute(
            "UPDATE provider_resources SET resource_version = ?1, state = ?2
             WHERE resource_uri = ?3 AND security_domain = ?4 AND deployment_id = ?5
               AND provider = ?6 AND resource_version = ?7 AND latest_fence = ?8",
            params![
                version,
                state.code(),
                request.resource_uri,
                request.security_domain,
                request.deployment_id,
                request.provider,
                request.expected_resource_version,
                request.fence
            ],
        )
        .map_err(PepError::from)
}

const fn state_for(action: ControlAction) -> ResourceState {
    match action {
        ControlAction::Quarantine | ControlAction::RestrictEgress => ResourceState::Isolated,
        ControlAction::RevokeAccess => ResourceState::Revoked,
        ControlAction::Restore => ResourceState::Connected,
    }
}
