use super::{model::VerifiedRun, verify};
pub fn render(run: &VerifiedRun) -> String {
    let summary = verify::summary(run);
    format!("# Rapport d’audit Ladyshell\n\nRun `{}` — couverture partielle.\n\nStatut : {}.\n\n| Résultat déclaré | Nombre |\n|---|---:|\n| Confirmé | {} |\n| À valider | {} |\n| Rejeté | {} |\n\n{} unités de couverture.\n\nLa vérification contrôle documents, relations et empreintes. Elle ne certifie ni l’authenticité des observations ni la réalité des vulnérabilités.\n\nObligations ouvertes :\n\n```json\n{}\n```\n",
        run.metadata.run_id, summary["run_status"], summary["counts"]["confirmed"], summary["counts"]["needs_validation"], summary["counts"]["rejected"], run.coverage.len(), summary["open_obligations"])
}
