use ladybom::deps;
use std::{fs, path::Path};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn write(root: &Path, path: &str, text: &str) -> std::io::Result<()> {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap_or(root))?;
    fs::write(path, text)
}
#[test]
fn vendor_observations_have_purls_but_never_lock_or_complete_the_graph() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.mod",
        "module example.org/app\ngo 1.24.0\nrequire example.org/lib v1.2.3\n",
    )?;
    write(
        root.path(),
        "vendor/modules.txt",
        "# example.org/lib v1.2.3\n## explicit; go 1.20\nexample.org/lib/sub\n",
    )?;
    let report = deps::scan_project(root.path())?;
    let graph = deps::graph::project(report)?;
    assert!(!ladybom_graph::plan_alignment(&graph)?.analysis_complete);
    Ok(())
}
