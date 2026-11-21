use ladyshell::files::{open_regular, read_limited};
use std::{fs, io::Read};
#[test]
fn reads_regular_files_but_rejects_links_in_any_component_and_oversize(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("real"))?;
    fs::write(dir.path().join("real/file"), "content")?;
    let mut s = String::new();
    open_regular(&dir.path().join("real/file"))?.read_to_string(&mut s)?;
    assert_eq!(s, "content");
    std::os::unix::fs::symlink("real", dir.path().join("alias"))?;
    std::os::unix::fs::symlink("real/file", dir.path().join("link"))?;
    assert!(open_regular(&dir.path().join("alias/file")).is_err());
    assert!(open_regular(&dir.path().join("link")).is_err());
    assert!(open_regular(&dir.path().join("real")).is_err());
    assert!(read_limited(&dir.path().join("real/file"), 3).is_err());
    Ok(())
}
#[test]
fn child_open_cannot_escape_its_directory_descriptor() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let folder = ladyshell::files::open_directory(dir.path())?;
    assert!(ladyshell::files::open_child(&folder, std::ffi::OsStr::new(".."), true).is_err());
    assert!(
        ladyshell::files::open_child(&folder, std::ffi::OsStr::new("/etc/passwd"), false).is_err()
    );
    Ok(())
}
