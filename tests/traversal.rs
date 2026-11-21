use std::{fs, os::unix::fs::PermissionsExt};
#[test]
fn traversal_does_not_require_listing_ancestor_directories(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let ancestor = temp.path().join("ancestor");
    let allowed = ancestor.join("allowed");
    fs::create_dir_all(&allowed)?;
    fs::write(allowed.join("file"), b"readable")?;
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111))?;
    let result = ladyshell::files::read_limited(&allowed.join("file"), 32);
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
    assert_eq!(result?, b"readable");
    Ok(())
}
#[test]
fn creating_auth_directory_does_not_list_ancestors() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let ancestor = temp.path().join("ancestor");
    let allowed = ancestor.join("allowed");
    fs::create_dir_all(&allowed)?;
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o111))?;
    let result = ladyshell::state::create_directory(&allowed.join("auth"));
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
    result?;
    assert!(allowed.join("auth").is_dir());
    Ok(())
}
