//! Capture a bounded source selection for an experiment without changing its checkout.
//! Usage: source_snapshot ABSOLUTE_PROJECT SOURCES_JSON NEW_CAPTURE_DIRECTORY
use ladyshell::{files, sources};
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err(
            "usage: source_snapshot ABSOLUTE_PROJECT SOURCES_JSON NEW_CAPTURE_DIRECTORY".into(),
        );
    }
    let root = files::absolute(&PathBuf::from(&args[0]))?;
    let selection: sources::Sources = serde_json::from_value(ladyshell::json::parse(
        &files::read_limited(&PathBuf::from(&args[1]), 1024 * 1024)?,
    )?)?;
    let capture = files::absolute(&PathBuf::from(&args[2]))?;
    if capture.starts_with(&root) || root.starts_with(&capture) {
        return Err("capture must be outside and independent from the source checkout".into());
    }
    files::open_directory(capture.parent().ok_or("capture parent missing")?)?;
    fs::DirBuilder::new().mode(0o700).create(&capture)?;
    let project = capture.join("project");
    fs::create_dir(&project)?;
    let snapshot = sources::snapshot(&root, &selection, Some(&project))?;
    if sources::snapshot(&project, &selection, None)? != snapshot {
        return Err("copied sources differ from captured bytes".into());
    }
    files::publish_json(
        &capture.join("receipt.json"),
        &serde_json::json!({
            "schema_version": 1, "origin": root, "project": project,
            "selection": selection, "sources": snapshot,
            "limitation": "Per-file capture; not a transactional snapshot of concurrent checkout changes."
        }),
        false,
    )?;
    println!("{}", project.display());
    Ok(())
}
