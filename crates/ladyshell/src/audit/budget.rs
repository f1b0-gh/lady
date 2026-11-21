//! Invocation accounting. A reservation is consumed before launching an agent.
use super::{
    invalid,
    model::{Budget, Role},
};
use crate::error::Result;
use std::time::{Duration, Instant};

pub struct InvocationBudget {
    limit: Budget,
    started: Instant,
    counts: [u32; 4],
    verifications: u32,
}

impl InvocationBudget {
    pub fn new(limit: Budget) -> Result<Self> {
        if limit.invocations < 7 || limit.seconds == 0 {
            return Err(invalid(
                "Audit distribué : sept invocations et une durée positive requises",
            ));
        }
        Ok(Self {
            limit,
            started: Instant::now(),
            counts: [0; 4],
            verifications: 1,
        })
    }
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
    pub fn used(&self) -> u32 {
        self.counts.iter().sum()
    }
    pub fn time_remaining(&self) -> Duration {
        Duration::from_secs(self.limit.seconds).saturating_sub(self.started.elapsed())
    }
    pub fn claim(&mut self, role: Role) -> Result<String> {
        if self.time_remaining().is_zero() {
            return Err(invalid("Durée d’audit épuisée"));
        }
        let remaining = self.limit.invocations.saturating_sub(self.used());
        if remaining == 0 {
            return Err(invalid("Budget d’invocations épuisé"));
        }
        let index = match role {
            Role::Recon => 0,
            Role::Hunter => 1,
            Role::Verifier => 2,
            Role::Critic => 3,
        };
        let mut next = self.counts;
        next[index] += 1;
        let reserved = match role {
            // When new candidates make full verification impossible, consume
            // the remaining verifier slots but preserve the final critique.
            Role::Verifier if self.counts[2] < self.verifications => {
                self.required(next) - u64::from(self.verifications.saturating_sub(next[2]))
            }
            Role::Critic if self.counts[3] == 0 => {
                self.required(next) - u64::from(self.verifications.saturating_sub(next[2]))
            }
            _ => self.required(next),
        };
        if u64::from(remaining - 1) < reserved {
            return Err(invalid(
                "Budget réservé à la reconnaissance, à la critique et à la vérification",
            ));
        }
        self.counts = next;
        Ok(format!("invocation-{}", self.used()))
    }
    pub fn require_verifications(&mut self, total: u32) -> Result<()> {
        if total < self.verifications {
            return Err(invalid("Réserve de vérification décroissante"));
        }
        self.verifications = total;
        Ok(())
    }
    pub fn can_finish(&self) -> bool {
        !self.time_remaining().is_zero()
            && self.required(self.counts) <= u64::from(self.limit.invocations - self.used())
    }
    fn required(&self, counts: [u32; 4]) -> u64 {
        [4, 1, self.verifications, 1]
            .iter()
            .zip(counts)
            .map(|(required, used)| u64::from(required.saturating_sub(used)))
            .sum()
    }
}
