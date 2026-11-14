//! The code signature of running processes: the Security framework calls `procline_core::verify` needs, for one process each.

use std::time::{Duration, Instant};

use procline_core::verify::{self, Lookup, Requirement, SigningCalls, SigningInfo};
use procline_core::{CdHash, Certificate, CodeSigning};
use security_framework::os::macos::code_signing::{SecCode, SecRequirement};

use crate::sys::security::{self, Guest};

/// Every requirement of `Requirement::ALL`, compiled once per collection. A requirement that failed to compile keeps the status of its compilation, which its checks return.
struct Requirements(Vec<(Requirement, Result<SecRequirement, i32>)>);

impl Requirements {
    fn compile() -> Self {
        Self(
            Requirement::ALL
                .into_iter()
                .map(|requirement| (requirement, security::requirement(requirement.text())))
                .collect(),
        )
    }

    fn get(&self, requirement: Requirement) -> Result<&SecRequirement, i32> {
        self.0
            .iter()
            .find(|(r, _)| *r == requirement)
            .map_or(Err(-1), |(_, compiled)| compiled.as_ref().map_err(|s| *s))
    }
}

/// The calls for one process.
struct Calls<'a> {
    guest: Guest,
    requirements: &'a Requirements,
}

impl SigningCalls for Calls<'_> {
    type Code = SecCode;

    fn open(&self, lookup: Lookup) -> Result<SecCode, i32> {
        security::guest(self.guest, lookup == Lookup::RunningCode)
    }

    fn check(&self, code: &SecCode, requirement: Option<Requirement>) -> i32 {
        match requirement {
            None => security::check(code, None),
            Some(requirement) => match self.requirements.get(requirement) {
                Ok(compiled) => security::check(code, Some(compiled)),
                Err(status) => status,
            },
        }
    }

    fn info(&self, code: &SecCode) -> Result<SigningInfo, i32> {
        let info = security::signing_information(code)?;
        Ok(SigningInfo {
            identifier: info.identifier(),
            cdhash: info
                .unique()
                .and_then(|bytes| <[u8; 20]>::try_from(bytes.as_slice()).ok())
                .map(CdHash),
            team_id: info.team_identifier(),
            certificates: info
                .certificates()
                .into_iter()
                .map(|(summary, der)| Certificate { summary, der })
                .collect(),
            flags: info.flags(),
            status: info.status(),
            entitlements: info.entitlements(),
            entitlements_blob: info.has_entitlements_blob(),
            bundle_id: info.plist_string("CFBundleIdentifier"),
        })
    }
}

/// Verifies the processes in order, with the requirements compiled once. With a `budget`, the processes not yet verified when it runs out (measured from the start of this call) are `NotChecked`.
pub(crate) fn verify_chain(guests: &[Guest], budget: Option<Duration>) -> Vec<CodeSigning> {
    let started = Instant::now();
    let requirements = Requirements::compile();
    let calls: Vec<Calls<'_>> = guests
        .iter()
        .map(|&guest| Calls {
            guest,
            requirements: &requirements,
        })
        .collect();
    verify::verify_chain(&calls, budget, || started.elapsed())
}
