use crate::{PepExecutionLeaseV2, ProviderRequest};

pub(super) fn provider(lease: &PepExecutionLeaseV2) -> ProviderRequest {
    let command = &lease.command;
    ProviderRequest {
        command_id: command.command_id.clone(),
        command_jti: command.jti.clone(),
        command_digest: lease.command_digest.clone(),
        release_reservation_id: lease.reservation_id.clone(),
        security_domain: command.security_domain.clone(),
        deployment_id: command.deployment_id.clone(),
        incident_id: command.incident_id.clone(),
        resource_uri: command.target_id.clone(),
        provider: command.provider.clone(),
        action: command.binding.action,
        binding: command.binding.clone(),
        expected_resource_version: command.expected_resource_version.clone(),
        previous_fence: command.previous_fence_epoch,
        fence: command.fence_epoch,
        release_digest: command.release_digest.clone(),
        checkpoint_digest: command.checkpoint_digest.clone(),
    }
}
