//! Audit requests retained under their historical module path, without CLI parsing.
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AuditArgs {
    pub command: AuditCommand,
}
#[derive(Clone, Debug)]
pub enum AuditCommand {
    /// Préparer le périmètre et diagnostiquer les capacités manquantes.
    Plan {
        state: PathBuf,
        profile: Option<super::model::Profile>,
    },
    /// Demander l’exécution ; refus si les garanties ne sont pas disponibles.
    Run {
        state: PathBuf,
        profile: Option<super::model::Profile>,
    },
    /// Vérifier hors ligne un run natif et ses preuves.
    Verify { path: PathBuf },
    /// Reprendre le nettoyage d’un run interrompu sans rejouer la cible.
    Recover { path: PathBuf },
    /// Comparer deux runs sans transférer leurs confirmations.
    Compare { old: PathBuf, new: PathBuf },
    /// Publier un export vérifié dans un nouveau dossier.
    Export { path: PathBuf, destination: PathBuf },
    /// Valider un document ; ne confirme pas une vulnérabilité.
    Validate { mode: DocumentMode, path: PathBuf },
}
#[derive(Clone, Copy, Debug)]
pub enum DocumentMode {
    Findings,
    Coverage,
}
impl From<DocumentMode> for crate::audit::validator::Mode {
    fn from(mode: DocumentMode) -> Self {
        match mode {
            DocumentMode::Findings => Self::Findings,
            DocumentMode::Coverage => Self::Coverage,
        }
    }
}
