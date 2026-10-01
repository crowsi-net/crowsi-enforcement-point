use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlAction {
    Quarantine,
    RestrictEgress,
    RevokeAccess,
    Restore,
}

impl ControlAction {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::RestrictEgress => "restrict-egress",
            Self::RevokeAccess => "revoke-access",
            Self::Restore => "restore",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlChannel {
    HatterInteractive,
    EmergencyConsole,
    ServiceAutomation,
}

impl ControlChannel {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::HatterInteractive => "hatter-interactive",
            Self::EmergencyConsole => "emergency-console",
            Self::ServiceAutomation => "service-automation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBindingV1 {
    pub audience: String,
    pub resource: String,
    pub action: ControlAction,
    pub purpose: String,
    pub channel: ControlChannel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDigestV1 {
    pub algorithm: SignatureAlgorithm,
    pub key_id: String,
    pub digest: String,
    pub signature: String,
}
