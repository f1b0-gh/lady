use super::*;
use crate::error::Result;
use crate::storage::{Limits, Profile};
use std::{fs, io::Cursor};

fn request() -> Request {
    let limits = Limits {
        bytes: 65536,
        inodes: 32,
    };
    Request {
        format: 1,
        token: "a".repeat(64),
        profile: Profile {
            control: limits.clone(),
            artifacts: limits.clone(),
            incoming: limits,
        },
    }
}
fn roots(root: &std::path::Path) -> Result<[fs::File; 3]> {
    for name in ["control", "artifacts", "incoming"] {
        fs::create_dir(root.join(name))?;
    }
    Ok([
        crate::files::open_directory(&root.join("control"))?,
        crate::files::open_directory(&root.join("artifacts"))?,
        crate::files::open_directory(&root.join("incoming"))?,
    ])
}
#[test]
fn sealed_export_preserves_empty_barriers_partial_files_and_exact_bytes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let roots = roots(root.path())?;
    fs::create_dir(root.path().join("control/.lifecycle"))?;
    fs::create_dir(root.path().join("control/empty-dispatch"))?;
    fs::create_dir(root.path().join("control/partial-dispatch"))?;
    fs::write(
        root.path().join("control/partial-dispatch/dispatch.json"),
        b"{",
    )?;
    fs::write(root.path().join("incoming/blob"), b"original bytes")?;
    let mut bytes = Vec::new();
    snapshot(&request(), &roots, &mut bytes)?;
    let receipt = verify(&request(), Cursor::new(&bytes))?;
    assert_eq!(receipt.bytes, bytes.len() as u64);
    assert_eq!(receipt.entries, 8);
    let mut tar = tar::Archive::new(Cursor::new(bytes));
    let mut names = Vec::new();
    for item in tar.entries()? {
        let mut item = item?;
        let name = item.path()?.to_string_lossy().into_owned();
        if name == "incoming/blob" {
            let mut body = Vec::new();
            std::io::Read::read_to_end(&mut item, &mut body)?;
            assert_eq!(body, b"original bytes");
        }
        names.push(name);
    }
    assert!(names.contains(&"control/empty-dispatch".into()));
    assert!(names.contains(&"control/partial-dispatch/dispatch.json".into()));
    Ok(())
}
#[test]
fn export_refuses_open_uninitialized_busy_or_linked_storage() -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::symlink};
    let root = tempfile::tempdir()?;
    let roots = roots(root.path())?;
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    fs::create_dir(root.path().join("control/.lifecycle"))?;
    fs::create_dir(root.path().join("control/.lifecycle/open"))?;
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    fs::remove_dir(root.path().join("control/.lifecycle/open"))?;
    let active = fs::File::open(root.path().join("control"))?;
    // SAFETY: descriptor is live; the test releases it before the next export.
    assert_eq!(
        unsafe { libc::flock(active.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        0
    );
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    drop(active);
    symlink("/etc/passwd", root.path().join("incoming/link"))?;
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    fs::remove_file(root.path().join("incoming/link"))?;
    fs::write(root.path().join("incoming/one"), b"one")?;
    fs::hard_link(
        root.path().join("incoming/one"),
        root.path().join("incoming/two"),
    )?;
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    Ok(())
}
#[test]
fn verifier_refuses_truncation_substitution_trailing_data_and_quota_overflow() -> Result<()> {
    let root = tempfile::tempdir()?;
    let roots = roots(root.path())?;
    fs::create_dir(root.path().join("control/.lifecycle"))?;
    let mut bytes = Vec::new();
    snapshot(&request(), &roots, &mut bytes)?;
    for cut in [0, 511, 1024, bytes.len() - 1, bytes.len() - 512] {
        assert!(
            verify(&request(), Cursor::new(&bytes[..cut])).is_err(),
            "{cut}"
        );
    }
    let mut other = request();
    other.token = "b".repeat(64);
    assert!(verify(&other, Cursor::new(&bytes)).is_err());
    bytes.push(1);
    assert!(verify(&request(), Cursor::new(&bytes)).is_err());
    let sparse = fs::File::create(root.path().join("incoming/sparse"))?;
    sparse.set_len(request().profile.incoming.bytes + 1)?;
    assert!(snapshot(&request(), &roots, Vec::new()).is_err());
    Ok(())
}

fn encoded_entries(entries: &[(&str, bool, &[u8])]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut tar = tar::Builder::new(&mut bytes);
    let manifest = serde_json::to_vec(&request())?;
    tar.append(
        &archive::header(archive::MANIFEST, false, manifest.len() as u64)?,
        manifest.as_slice(),
    )?;
    for (path, directory, body) in entries {
        tar.append(
            &archive::header(path, *directory, body.len() as u64)?,
            *body,
        )?;
    }
    tar.finish()?;
    drop(tar);
    Ok(bytes)
}

#[test]
fn verifier_requires_each_parent_once_and_bounded_ordered_scopes() -> Result<()> {
    let original = [
        ("control", true, b"".as_slice()),
        ("control/.lifecycle", true, b"".as_slice()),
        ("artifacts", true, b"".as_slice()),
        ("incoming", true, b"".as_slice()),
    ];
    verify(&request(), Cursor::new(encoded_entries(&original)?))?;
    for extra in [
        ("control/.lifecycle", true, b"".as_slice()),
        ("control/missing/child", false, b"".as_slice()),
        ("control/.lifecycle/open", true, b"".as_slice()),
        ("control/.lifecycle", false, b"".as_slice()),
    ] {
        let mut entries = original.to_vec();
        entries.insert(2, extra);
        assert!(verify(&request(), Cursor::new(encoded_entries(&entries)?)).is_err());
    }
    let mut entries = original.to_vec();
    entries.insert(2, ("control/file", false, b""));
    entries.insert(3, ("control/file/child", false, b""));
    assert!(verify(&request(), Cursor::new(encoded_entries(&entries)?)).is_err());
    let mut entries = original.to_vec();
    entries.swap(2, 3);
    assert!(verify(&request(), Cursor::new(encoded_entries(&entries)?)).is_err());
    let oversized = vec![0; 65537];
    let mut entries = original.to_vec();
    entries.push(("incoming/large", false, &oversized));
    assert!(verify(&request(), Cursor::new(encoded_entries(&entries)?)).is_err());
    let names = (0..32)
        .map(|i| format!("incoming/{i:03}"))
        .collect::<Vec<_>>();
    let mut entries = original.to_vec();
    for name in &names {
        entries.push((name, false, b""));
    }
    assert!(verify(&request(), Cursor::new(encoded_entries(&entries)?)).is_err());
    Ok(())
}

#[test]
fn canonical_headers_reject_links_traversal_corruption_and_nonzero_padding() -> Result<()> {
    let entries = [
        ("control", true, b"".as_slice()),
        ("control/.lifecycle", true, b"".as_slice()),
        ("artifacts", true, b"".as_slice()),
        ("incoming", true, b"".as_slice()),
    ];
    let bytes = encoded_entries(&entries)?;
    // Correlated manifest occupies one header and one padded block.
    for mutate in [0, 1, 2] {
        let mut changed = bytes.clone();
        if mutate == 0 {
            let mut header = tar::Header::from_byte_slice(&changed[1024..1536]).clone();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("/etc/passwd")?;
            header.set_cksum();
            changed[1024..1536].copy_from_slice(header.as_bytes());
        } else if mutate == 1 {
            let mut header = tar::Header::from_byte_slice(&changed[1024..1536]).clone();
            header.as_mut_bytes()[..10].copy_from_slice(b"../escape\0");
            header.set_cksum();
            changed[1024..1536].copy_from_slice(header.as_bytes());
        } else {
            changed[1024 + 148] = b'!';
        }
        assert!(verify(&request(), Cursor::new(changed)).is_err());
    }
    let mut changed = bytes;
    changed[1023] = 1;
    assert!(verify(&request(), Cursor::new(changed)).is_err());
    Ok(())
}

#[test]
fn capture_requires_successful_transport_and_complete_verified_archive() -> Result<()> {
    use std::io::Write;
    let root = tempfile::tempdir()?;
    let roots = roots(root.path())?;
    fs::create_dir(root.path().join("control/.lifecycle"))?;
    let mut source = tempfile::NamedTempFile::new()?;
    snapshot(&request(), &roots, source.as_file_mut())?;
    source.flush()?;
    let source_path = source.path().to_owned();
    let command = || {
        let mut command = std::process::Command::new("cat");
        command.arg(&source_path);
        command
    };
    let mut target = tempfile::tempfile()?;
    let receipt = capture(
        &request(),
        command(),
        &mut target,
        std::time::Duration::from_secs(3),
    )?;
    assert_eq!(receipt.bytes, source.as_file().metadata()?.len());
    let mut failed = std::process::Command::new("sh");
    failed
        .args(["-c", "cat -- \"$1\"; exit 3", "export-fixture"])
        .arg(source.path());
    assert!(capture(
        &request(),
        failed,
        &mut tempfile::tempfile()?,
        std::time::Duration::from_secs(3)
    )
    .is_err());
    let truncated = source.as_file().metadata()?.len() - 1;
    source.as_file_mut().set_len(truncated)?;
    assert!(capture(
        &request(),
        command(),
        &mut tempfile::tempfile()?,
        std::time::Duration::from_secs(3)
    )
    .is_err());
    Ok(())
}
