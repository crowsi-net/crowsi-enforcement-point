use serde::{Deserialize, Serialize};

use super::IsolationCommandV2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PepExecutionLeaseV2 {
    pub schema: String,
    pub reservation_id: String,
    pub command: IsolationCommandV2,
    pub command_digest: String,
    pub reserved_at: String,
}
