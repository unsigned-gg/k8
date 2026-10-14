// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Byzantine fault-tolerant ($3f + 1$) jury quorum and execution receipt primitives.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Jury verdict outcome for an autonomous agent workload execution.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub enum VerdictOutcome {
    /// Workload output passed all deterministic and critic checks.
    Approve,
    /// Workload output violated an invariant or failed verification.
    Reject,
    /// Arbiter abstained due to inconclusive telemetry.
    Abstain,
}

/// Signed vote cast by an independent jury arbiter for a specific workload round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JuryVote {
    /// Workload run identifier.
    pub workload_id: String,
    /// Monotonic consensus round number.
    pub round: u64,
    /// Unique arbiter identifier.
    pub arbiter_id: String,
    /// Verdict outcome selected by the arbiter.
    pub outcome: VerdictOutcome,
    /// Deterministic hex digest of the evaluated workload artifact.
    pub artifact_digest: String,
    /// Virtual monotonic timestamp in milliseconds when the vote was recorded.
    pub timestamp_ms: u64,
}

/// Equivocation evidence recorded when an arbiter signs conflicting votes in the same round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EquivocationFault {
    /// Faulty arbiter identifier.
    pub arbiter_id: String,
    /// Consensus round in which equivocation occurred.
    pub round: u64,
    /// First observed vote outcome.
    pub first_outcome: VerdictOutcome,
    /// First observed artifact digest.
    pub first_digest: String,
    /// Conflicting vote outcome.
    pub second_outcome: VerdictOutcome,
    /// Conflicting artifact digest.
    pub second_digest: String,
}

/// Errors returned by the BFT [`JuryQuorum`] state machine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JuryError {
    /// Vote workload ID or round does not match the quorum session.
    #[error("vote target ({workload_id}, round {round}) does not match session ({expected_workload}, round {expected_round})")]
    SessionMismatch {
        /// Workload ID on the incoming vote.
        workload_id: String,
        /// Round on the incoming vote.
        round: u64,
        /// Expected workload ID.
        expected_workload: String,
        /// Expected round.
        expected_round: u64,
    },

    /// Arbiter is not a registered member of the jury roster.
    #[error("arbiter '{0}' is not in the authorized jury roster")]
    UnauthorizedArbiter(String),

    /// Arbiter was quarantined after an equivocation fault.
    #[error("arbiter '{0}' is quarantined for equivocation: {1:?}")]
    EquivocationDetected(String, EquivocationFault),
}

/// Sealed execution receipt emitted when a $2f + 1$ supermajority converges on a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceipt {
    /// Workload run identifier.
    pub workload_id: String,
    /// Consensus round number.
    pub round: u64,
    /// Agreed verdict outcome.
    pub outcome: VerdictOutcome,
    /// Agreed artifact digest.
    pub artifact_digest: String,
    /// Sorted list of arbiters whose votes formed the quorum certificate.
    pub signers: Vec<String>,
    /// Virtual monotonic timestamp in milliseconds when quorum was reached.
    pub finalized_at_ms: u64,
    /// Deterministic FNV-1a 64-bit hex commitment over the canonical receipt fields.
    pub receipt_commitment: String,
}

impl ExecutionReceipt {
    /// Compute a deterministic 64-bit FNV-1a hex commitment over the receipt fields.
    #[must_use]
    pub fn compute_commitment(
        workload_id: &str,
        round: u64,
        outcome: VerdictOutcome,
        artifact_digest: &str,
        signers: &[String],
    ) -> String {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let mut feed = |bytes: &[u8]| {
            for &b in bytes {
                hash ^= u64::from(b);
                hash = hash.wrapping_mul(0x0100_0000_01b3);
            }
        };
        feed(workload_id.as_bytes());
        feed(&[0xff]);
        feed(&round.to_be_bytes());
        feed(&[match outcome {
            VerdictOutcome::Approve => 1,
            VerdictOutcome::Reject => 2,
            VerdictOutcome::Abstain => 3,
        }]);
        feed(artifact_digest.as_bytes());
        for s in signers {
            feed(&[0xfe]);
            feed(s.as_bytes());
        }
        format!("{hash:016x}")
    }
}

/// Deterministic $3f + 1$ Byzantine fault-tolerant jury quorum state machine.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JuryQuorum {
    workload_id: String,
    round: u64,
    max_faulty: usize,
    roster: BTreeSet<String>,
    votes: BTreeMap<String, JuryVote>,
    quarantined: BTreeMap<String, EquivocationFault>,
}

impl JuryQuorum {
    /// Create a new BFT jury session tolerating `max_faulty` ($f$) Byzantine arbiters.
    ///
    /// Requires at least $3f + 1$ unique arbiters in `roster`.
    pub fn new(
        workload_id: impl Into<String>,
        round: u64,
        max_faulty: usize,
        roster: BTreeSet<String>,
    ) -> Option<Self> {
        let min_roster = max_faulty.checked_mul(3)?.checked_add(1)?;
        if roster.len() < min_roster {
            return None;
        }
        Some(Self {
            workload_id: workload_id.into(),
            round,
            max_faulty,
            roster,
            votes: BTreeMap::new(),
            quarantined: BTreeMap::new(),
        })
    }

    /// Minimum matching votes required to reach a BFT quorum ($2f + 1$).
    #[must_use]
    pub const fn quorum_threshold(&self) -> usize {
        self.max_faulty * 2 + 1
    }

    /// Return the map of quarantined arbiters and their equivocation evidence.
    #[must_use]
    pub const fn quarantined(&self) -> &BTreeMap<String, EquivocationFault> {
        &self.quarantined
    }

    /// Return the currently recorded valid votes.
    #[must_use]
    pub const fn votes(&self) -> &BTreeMap<String, JuryVote> {
        &self.votes
    }

    /// Record a [`JuryVote`] and return `Ok(Some(ExecutionReceipt))` if quorum is reached.
    pub fn record_vote(&mut self, vote: JuryVote) -> Result<Option<ExecutionReceipt>, JuryError> {
        if vote.workload_id != self.workload_id || vote.round != self.round {
            return Err(JuryError::SessionMismatch {
                workload_id: vote.workload_id,
                round: vote.round,
                expected_workload: self.workload_id.clone(),
                expected_round: self.round,
            });
        }
        if !self.roster.contains(&vote.arbiter_id) {
            return Err(JuryError::UnauthorizedArbiter(vote.arbiter_id));
        }
        if let Some(fault) = self.quarantined.get(&vote.arbiter_id) {
            return Err(JuryError::EquivocationDetected(
                vote.arbiter_id,
                fault.clone(),
            ));
        }

        if let Some(existing) = self.votes.get(&vote.arbiter_id) {
            if existing.outcome != vote.outcome || existing.artifact_digest != vote.artifact_digest
            {
                let fault = EquivocationFault {
                    arbiter_id: vote.arbiter_id.clone(),
                    round: self.round,
                    first_outcome: existing.outcome,
                    first_digest: existing.artifact_digest.clone(),
                    second_outcome: vote.outcome,
                    second_digest: vote.artifact_digest,
                };
                self.votes.remove(&vote.arbiter_id);
                self.quarantined
                    .insert(vote.arbiter_id.clone(), fault.clone());
                return Err(JuryError::EquivocationDetected(vote.arbiter_id, fault));
            }
            // Idempotent duplicate of the exact same vote.
            return Ok(self.try_finalize(vote.timestamp_ms));
        }

        let ts = vote.timestamp_ms;
        self.votes.insert(vote.arbiter_id.clone(), vote);
        Ok(self.try_finalize(ts))
    }

    fn try_finalize(&self, finalized_at_ms: u64) -> Option<ExecutionReceipt> {
        let threshold = self.quorum_threshold();
        let mut tallies: BTreeMap<(VerdictOutcome, &str), Vec<String>> = BTreeMap::new();
        for v in self.votes.values() {
            tallies
                .entry((v.outcome, v.artifact_digest.as_str()))
                .or_default()
                .push(v.arbiter_id.clone());
        }

        for ((outcome, digest), mut signers) in tallies {
            if signers.len() >= threshold {
                signers.sort();
                let commitment = ExecutionReceipt::compute_commitment(
                    &self.workload_id,
                    self.round,
                    outcome,
                    digest,
                    &signers,
                );
                return Some(ExecutionReceipt {
                    workload_id: self.workload_id.clone(),
                    round: self.round,
                    outcome,
                    artifact_digest: digest.to_string(),
                    signers,
                    finalized_at_ms,
                    receipt_commitment: commitment,
                });
            }
        }
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_roster() -> BTreeSet<String> {
        ["arb-1", "arb-2", "arb-3", "arb-4"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[test]
    fn test_bft_quorum_reaches_receipt_at_2f_plus_1() {
        let mut quorum =
            JuryQuorum::new("agent-run-1", 1, 1, sample_roster()).expect("4 >= 3*1 + 1");
        assert_eq!(quorum.quorum_threshold(), 3);

        for (idx, arb) in ["arb-1", "arb-2", "arb-3"].iter().enumerate() {
            let vote = JuryVote {
                workload_id: "agent-run-1".to_string(),
                round: 1,
                arbiter_id: (*arb).to_string(),
                outcome: VerdictOutcome::Approve,
                artifact_digest: "sha256:abcd".to_string(),
                timestamp_ms: 1_000 + (idx as u64) * 10,
            };
            let res = quorum.record_vote(vote).expect("valid vote");
            if idx < 2 {
                assert!(res.is_none());
            } else {
                let receipt = res.expect("quorum reached on 3rd vote");
                assert_eq!(receipt.outcome, VerdictOutcome::Approve);
                assert_eq!(receipt.signers.len(), 3);
            }
        }
    }

    #[test]
    fn test_equivocation_quarantines_arbiter() {
        let mut quorum =
            JuryQuorum::new("agent-run-2", 1, 1, sample_roster()).expect("valid roster");
        let v1 = JuryVote {
            workload_id: "agent-run-2".to_string(),
            round: 1,
            arbiter_id: "arb-1".to_string(),
            outcome: VerdictOutcome::Approve,
            artifact_digest: "sha256:1111".to_string(),
            timestamp_ms: 100,
        };
        let v2 = JuryVote {
            outcome: VerdictOutcome::Reject,
            timestamp_ms: 105,
            ..v1.clone()
        };

        assert!(quorum.record_vote(v1).is_ok());
        let err = quorum
            .record_vote(v2)
            .expect_err("must detect equivocation");
        assert!(matches!(err, JuryError::EquivocationDetected(_, _)));
        assert!(quorum.quarantined().contains_key("arb-1"));
        assert!(!quorum.votes().contains_key("arb-1"));
    }
}
