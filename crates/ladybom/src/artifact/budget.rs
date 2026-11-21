use super::{invalid, Gap};
use crate::error::Result;

pub(super) const MAX_REFERENCES: usize = 200_000;
const MAX_GAPS: usize = 200_000;
const MAX_GAP_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(super) struct Budget {
    references: usize,
    gaps: usize,
    gap_bytes: usize,
}
impl Budget {
    pub(super) fn reference(&mut self) -> Result<()> {
        if self.references >= MAX_REFERENCES {
            return Err(invalid("Cumulative Nix reference budget exceeded"));
        }
        self.references += 1;
        Ok(())
    }
    pub(super) fn push_gap(&mut self, gaps: &mut Vec<Gap>, gap: Gap) -> Result<()> {
        let bytes = gap
            .code
            .len()
            .saturating_add(gap.path.len())
            .saturating_add(gap.message.len());
        if self.gaps >= MAX_GAPS || bytes > MAX_GAP_BYTES.saturating_sub(self.gap_bytes) {
            return Err(invalid("Cumulative artifact diagnostic budget exceeded"));
        }
        self.gaps += 1;
        self.gap_bytes += bytes;
        gaps.push(gap);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_cumulative_references_and_diagnostics_before_insertion() {
        let mut budget = Budget {
            references: MAX_REFERENCES,
            ..Budget::default()
        };
        assert!(budget.reference().is_err());
        let mut gaps = Vec::new();
        let gap = || Gap {
            code: "code".into(),
            path: "path".into(),
            message: "message".into(),
        };
        budget.gaps = MAX_GAPS;
        assert!(budget.push_gap(&mut gaps, gap()).is_err());
        assert!(gaps.is_empty());
        budget.gaps = 0;
        budget.gap_bytes = MAX_GAP_BYTES - 1;
        assert!(budget.push_gap(&mut gaps, gap()).is_err());
        assert!(gaps.is_empty());
    }
}
