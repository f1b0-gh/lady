mod audit_support;
use audit_support::*;
use std::{error::Error, fs, process::Command};
#[test]
fn exports_only_verified_bytes_and_does_not_overwrite() -> Result<(), Box<dyn Error>> {
    let source = fixture(true)?;
    let dest = tempfile::tempdir()?;
    let path = dest.path().join("export");
    fs::write(source.path().join("untrusted-extra"), "do not copy")?;
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(["audit", "export"])
            .arg(source.path())
            .arg("--destination")
            .arg(&path)
            .output()
    };
    let output = run()?;
    assert!(output.status.success(), "{:?}", output);
    assert!(!path.join("untrusted-extra").exists());
    assert!(path.join("REPORT.md").is_file());
    assert!(command(&["verify"], &path)?.status.success());
    assert!(!run()?.status.success());
    assert_eq!(
        fs::read(source.path().join("findings.json"))?,
        fs::read(path.join("findings.json"))?
    );
    Ok(())
}
#[test]
fn export_refuses_symlink_parent() -> Result<(), Box<dyn Error>> {
    let source = fixture(false)?;
    let dest = tempfile::tempdir()?;
    std::os::unix::fs::symlink(dest.path(), source.path().join("link"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "export"])
        .arg(source.path())
        .arg("--destination")
        .arg(source.path().join("link/export"))
        .output()?;
    assert!(!output.status.success());
    assert!(!dest.path().join("export").exists());
    Ok(())
}

#[test]
fn export_uses_the_verified_snapshot_after_source_mutation() -> Result<(), Box<dyn Error>> {
    let source = fixture(true)?;
    let verified = ladyshell::audit::verify::load(source.path())?;
    let original = fs::read(source.path().join("agents/verifier/artifacts/proof.txt"))?;
    fs::write(
        source.path().join("agents/verifier/artifacts/proof.txt"),
        "replaced after verification",
    )?;
    let dest = tempfile::tempdir()?;
    let output = dest.path().join("export");
    ladyshell::audit::export::export(&verified, &output)?;
    assert_eq!(
        fs::read(output.join("agents/verifier/artifacts/proof.txt"))?,
        original
    );
    assert!(command(&["verify"], &output)?.status.success());
    Ok(())
}
