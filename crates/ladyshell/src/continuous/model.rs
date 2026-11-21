//! Exact, bounded lifecycle decisions without filesystem or backend effects.
use super::invalid;
use crate::error::{ensure, Result};
use serde::{Deserialize, Serialize};

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Ready,
    Checkpointing,
    Checkpointed,
    Refreshing,
    Refreshed,
    ReplacementRequired,
    Replacing,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub schema_version: u32,
    pub task: String,
    pub sandbox_id: String,
    pub owner: String,
    pub runtime: String,
    pub environment: String,
    pub epoch: u64,
    pub incarnation_epoch: u64,
    pub tree: String,
    pub phase: Phase,
    pub checkpoint_attempt: Option<String>,
    pub checkpoint_tree: Option<String>,
    pub offer: Option<RefreshOffer>,
    pub acknowledgement: Option<Acknowledgement>,
}
impl Session {
    pub fn new(
        task: String,
        sandbox_id: String,
        owner: String,
        runtime: String,
        environment: String,
        tree: String,
    ) -> Result<Self> {
        let state = Self {
            schema_version: 1,
            task,
            sandbox_id,
            owner,
            runtime,
            environment,
            epoch: 0,
            incarnation_epoch: 0,
            tree,
            phase: Phase::Ready,
            checkpoint_attempt: None,
            checkpoint_tree: None,
            offer: None,
            acknowledgement: None,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "Unsupported continuous session version"
        );
        ensure!(
            [&self.task, &self.sandbox_id, &self.owner, &self.runtime]
                .into_iter()
                .all(|v| token(v)),
            "Invalid continuous session identity"
        );
        ensure!(
            digest(&self.environment) && digest(&self.tree),
            "Invalid continuous session digest"
        );
        ensure!(
            self.incarnation_epoch <= self.epoch,
            "Invalid incarnation epoch"
        );
        ensure!(
            self.checkpoint_attempt.as_deref().is_none_or(token)
                && self.checkpoint_tree.as_deref().is_none_or(digest),
            "Invalid checkpoint binding"
        );
        if let Some(offer) = &self.offer {
            offer.validate()?;
        }
        Ok(())
    }
    pub fn admit(&self, sandbox: &str, runtime: &str) -> Result<()> {
        self.validate()?;
        ensure!(
            self.phase == Phase::Ready,
            "Continuous handoff is pending; execution is refused"
        );
        ensure!(
            self.sandbox_id == sandbox && self.runtime == runtime,
            "Sandbox incarnation or runtime generation changed"
        );
        Ok(())
    }
    pub fn begin_checkpoint(&mut self, attempt: &str, epoch: u64) -> Result<()> {
        self.validate()?;
        ensure!(
            token(attempt) && epoch == self.epoch,
            "Invalid checkpoint attempt or stale epoch"
        );
        if self.phase == Phase::Checkpointing && self.checkpoint_attempt.as_deref() == Some(attempt)
        {
            return Ok(());
        }
        ensure!(
            self.phase == Phase::Ready && self.checkpoint_attempt.as_deref() != Some(attempt),
            "Checkpoint attempt is unavailable; inspect retained state"
        );
        self.phase = Phase::Checkpointing;
        self.checkpoint_attempt = Some(attempt.into());
        self.checkpoint_tree = None;
        self.offer = None;
        self.acknowledgement = None;
        Ok(())
    }
    pub fn finish_checkpoint(&mut self, attempt: &str, runtime: &str, tree: String) -> Result<()> {
        self.validate()?;
        ensure!(
            self.phase == Phase::Checkpointing
                && self.checkpoint_attempt.as_deref() == Some(attempt),
            "Checkpoint acknowledgement belongs to another attempt"
        );
        ensure!(
            token(runtime) && runtime != self.runtime && digest(&tree),
            "Checkpoint requires a new verified runtime generation and exact export"
        );
        self.runtime = runtime.into();
        self.checkpoint_tree = Some(tree);
        self.phase = Phase::Checkpointed;
        Ok(())
    }
    pub fn begin_refresh(&mut self, offer: &RefreshOffer) -> Result<()> {
        self.validate()?;
        offer.validate()?;
        ensure!(
            offer.task == self.task
                && offer.sandbox_id == self.sandbox_id
                && offer.owner == self.owner
                && offer.environment == self.environment
                && offer.expected_epoch == self.epoch
                && offer.incarnation_epoch == self.incarnation_epoch
                && self.checkpoint_tree.as_ref() == Some(&offer.previous_tree),
            "Refresh offer differs from checkpoint binding"
        );
        if self.phase == Phase::Refreshing && self.offer.as_ref() == Some(offer) {
            return Ok(());
        }
        ensure!(
            self.phase == Phase::Checkpointed,
            "Refresh requires a completed checkpoint"
        );
        self.offer = Some(offer.clone());
        self.phase = Phase::Refreshing;
        Ok(())
    }
    pub fn acknowledge(&mut self, offer: &RefreshOffer, ack: &Acknowledgement) -> Result<()> {
        self.validate()?;
        offer.validate()?;
        ensure!(
            self.phase == Phase::Refreshing && self.offer.as_ref() == Some(offer),
            "No matching refresh is pending"
        );
        ensure!(
            *ack == Acknowledgement::for_offer(offer, &self.runtime),
            "Refresh acknowledgement differs from selected revision"
        );
        self.acknowledgement = Some(ack.clone());
        self.phase = Phase::Refreshed;
        Ok(())
    }
    pub fn resume(&mut self, ack: &Acknowledgement) -> Result<()> {
        self.validate()?;
        ensure!(
            self.phase == Phase::Refreshed && self.acknowledgement.as_ref() == Some(ack),
            "Resume requires the exact applied acknowledgement"
        );
        self.epoch = ack.epoch;
        self.tree = ack.tree.clone();
        self.phase = Phase::Ready;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshOffer {
    pub schema_version: u32,
    pub task: String,
    pub sandbox_id: String,
    pub owner: String,
    pub environment: String,
    pub expected_epoch: u64,
    pub incarnation_epoch: u64,
    pub epoch: u64,
    pub attempt: String,
    pub previous_tree: String,
    pub tree: String,
    pub context: String,
}
impl RefreshOffer {
    pub fn new(state: &Session, attempt: &str, tree: String, context: String) -> Result<Self> {
        state.validate()?;
        ensure!(
            state.phase == Phase::Checkpointed,
            "Refresh selection requires a checkpoint"
        );
        let offer = Self {
            schema_version: 1,
            task: state.task.clone(),
            sandbox_id: state.sandbox_id.clone(),
            owner: state.owner.clone(),
            environment: state.environment.clone(),
            expected_epoch: state.epoch,
            incarnation_epoch: state.incarnation_epoch,
            epoch: state
                .epoch
                .checked_add(1)
                .ok_or_else(|| super::invalid("Continuous epoch exhausted"))?,
            attempt: attempt.into(),
            previous_tree: state
                .checkpoint_tree
                .clone()
                .ok_or_else(|| super::invalid("Checkpoint tree missing"))?,
            tree,
            context,
        };
        offer.validate()?;
        Ok(offer)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "Unsupported refresh version");
        ensure!(
            [&self.task, &self.sandbox_id, &self.owner, &self.attempt]
                .into_iter()
                .all(|v| token(v)),
            "Invalid refresh identity"
        );
        ensure!(
            [
                &self.environment,
                &self.previous_tree,
                &self.tree,
                &self.context
            ]
            .into_iter()
            .all(|v| digest(v)),
            "Invalid refresh digest"
        );
        ensure!(
            self.expected_epoch.checked_add(1) == Some(self.epoch),
            "Refresh epoch must advance exactly once"
        );
        ensure!(
            self.incarnation_epoch <= self.expected_epoch,
            "Invalid refresh incarnation epoch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub schema_version: u32,
    pub task: String,
    pub sandbox_id: String,
    pub owner: String,
    pub runtime: String,
    pub environment: String,
    pub epoch: u64,
    pub attempt: String,
    pub tree: String,
    pub context: String,
}
impl Acknowledgement {
    pub fn for_offer(offer: &RefreshOffer, runtime: &str) -> Self {
        Self {
            schema_version: 1,
            task: offer.task.clone(),
            sandbox_id: offer.sandbox_id.clone(),
            owner: offer.owner.clone(),
            runtime: runtime.into(),
            environment: offer.environment.clone(),
            epoch: offer.epoch,
            attempt: offer.attempt.clone(),
            tree: offer.tree.clone(),
            context: offer.context.clone(),
        }
    }
}
