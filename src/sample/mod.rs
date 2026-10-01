mod fixture;
mod signing;

use std::error::Error;

use crowsi_enforcement_point::{EnforcementReceiptV2, FaultMode, PepExecutionLeaseV2};
use serde::Serialize;

#[derive(Serialize)]
struct Sample {
    schema: &'static str,
    external_actions: bool,
    scenarios: Vec<Scenario>,
}

#[derive(Serialize)]
struct Scenario {
    name: &'static str,
    lease: PepExecutionLeaseV2,
    receipt: EnforcementReceiptV2,
}

pub(crate) fn run() -> Result<(), Box<dyn Error>> {
    let report = Sample {
        schema: "crowsi.pep-v2-conformance-sample",
        external_actions: false,
        scenarios: vec![
            execute("applied", 1, FaultMode::None)?,
            execute("failed", 2, FaultMode::Unavailable)?,
            execute("partial", 3, FaultMode::PartialApply)?,
        ],
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn execute(name: &'static str, serial: u64, fault: FaultMode) -> Result<Scenario, Box<dyn Error>> {
    let setup = fixture::Setup::new(fault)?;
    let lease = setup.lease(serial)?;
    let receipt = setup.point.execute(&lease)?;
    Ok(Scenario {
        name,
        lease,
        receipt,
    })
}
