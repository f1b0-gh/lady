use super::{model::VerifiedRun, verify};
pub fn render(run: &VerifiedRun) -> String {
    let summary = verify::summary(run);
    format!("# Ladyshell audit report\n\nRun `{}` — partial coverage.\n\nStatus: {}.\n\n| Declared finding | Count |\n|---|---:|\n| Confirmed | {} |\n| Needs validation | {} |\n| Rejected | {} |\n\n{} coverage units.\n\nVerification checks documents, relationships and hashes. It does not certify the authenticity of observations or the existence of vulnerabilities.\n\nOpen obligations:\n\n```json\n{}\n```\n",
        run.metadata.run_id, summary["run_status"], summary["counts"]["confirmed"], summary["counts"]["needs_validation"], summary["counts"]["rejected"], run.coverage.len(), summary["open_obligations"])
}
