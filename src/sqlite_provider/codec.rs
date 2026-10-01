use crate::{ProviderKind, ResourceState};

pub(crate) const fn kind_code(value: ProviderKind) -> &'static str {
    match value {
        ProviderKind::Host => "host",
        ProviderKind::HostFirewall => "host-firewall",
        ProviderKind::CloudProvider => "cloud-provider",
        ProviderKind::Incus => "incus",
    }
}

pub(crate) fn kind(value: &str) -> Option<ProviderKind> {
    match value {
        "host" => Some(ProviderKind::Host),
        "host-firewall" => Some(ProviderKind::HostFirewall),
        "cloud-provider" => Some(ProviderKind::CloudProvider),
        "incus" => Some(ProviderKind::Incus),
        _ => None,
    }
}

pub(crate) fn state(value: &str) -> Option<ResourceState> {
    match value {
        "connected" => Some(ResourceState::Connected),
        "isolated" => Some(ResourceState::Isolated),
        "revoked" => Some(ResourceState::Revoked),
        "indeterminate" => Some(ResourceState::Indeterminate),
        _ => None,
    }
}
