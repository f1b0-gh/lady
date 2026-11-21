//! Bounded OS initialization; never changes an existing account or adopts state.
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{chown, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Config {
    user: String,
    uid: u32,
    gid: u32,
    subuid: u32,
    subgid: u32,
    count: u32,
}

fn read_account(root: &Path, name: &str) -> Result<String> {
    let owner = fs::symlink_metadata(root)?.uid();
    let dir = fs::symlink_metadata(root.join("etc"))?;
    if !dir.is_dir() || dir.uid() != owner || dir.mode() & 0o022 != 0 {
        return Err("unsafe account directory".into());
    }
    // O_NOFOLLOW | O_NONBLOCK, fixed by the supported Linux x86_64 ABI.
    // Reject special files after open without waiting for a FIFO writer.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(root.join("etc").join(name))?;
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != owner || info.mode() & 0o022 != 0 || info.len() > 65536 {
        return Err("unsafe or oversized account file".into());
    }
    let mut text = String::new();
    (&mut file).take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err("account file grew beyond its bound".into());
    }
    Ok(text)
}

fn validate(root: &Path, c: &Config) -> Result<()> {
    let valid_range = |start: u32| {
        start >= 65536 && c.count > 0 && c.count <= 65536 && start.checked_add(c.count).is_some()
    };
    if c.user.is_empty()
        || c.user.len() > 32
        || c.user == "root"
        || !c.user.starts_with(|ch: char| ch.is_ascii_lowercase())
        || !c
            .user
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        || !(1000..=60000).contains(&c.uid)
        || !(1000..=60000).contains(&c.gid)
        || !valid_range(c.subuid)
        || !valid_range(c.subgid)
    {
        return Err("invalid rootless identity".into());
    }
    for (name, id, columns) in [("passwd", c.uid, 7), ("group", c.gid, 4)] {
        let text = read_account(root, name)?;
        let mut found = false;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() != columns {
                return Err("malformed account record".into());
            }
            let numeric: u32 = fields[2].parse()?;
            let start = if name == "passwd" { c.subuid } else { c.subgid };
            if (start..start + c.count).contains(&numeric) {
                return Err("subordinate range contains a host identity".into());
            }
            if name == "passwd"
                && (c.subgid..c.subgid + c.count).contains(&fields[3].parse::<u32>()?)
            {
                return Err("subordinate group range contains a host primary group".into());
            }
            if fields[0] == c.user || numeric == id {
                if found || fields[0] != c.user || numeric != id {
                    return Err("account identity collision".into());
                }
                if name == "passwd"
                    && (fields[3].parse::<u32>()? != c.gid
                        || fields[5] != format!("/var/home/{}", c.user))
                {
                    return Err("account home or group differs".into());
                }
                found = true;
            }
        }
        if !found {
            return Err("required account absent".into());
        }
    }
    for (name, expected) in [("subuid", c.subuid), ("subgid", c.subgid)] {
        let text = read_account(root, name)?;
        let mut found = false;
        for line in text.lines().filter(|l| !l.is_empty()) {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() != 3 {
                return Err("malformed subordinate range".into());
            }
            let start: u32 = fields[1].parse()?;
            let count: u32 = fields[2].parse()?;
            let end = start
                .checked_add(count)
                .ok_or("subordinate range overflow")?;
            // Shadow accepts a user UID in both subuid and subgid. Require
            // the canonical name so retained numeric aliases cannot add ranges.
            if fields[0].trim().parse::<u32>().ok() == Some(c.uid) {
                return Err("numeric subordinate owner alias".into());
            }
            if fields[0] == c.user {
                if found || start != expected || count != c.count {
                    return Err("subordinate identity differs".into());
                }
                found = true;
            } else if start < expected + c.count && expected < end {
                return Err("overlapping subordinate identity".into());
            }
        }
        if !found {
            return Err("required subordinate range absent".into());
        }
    }
    Ok(())
}

fn directory(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => {
            if !m.is_dir() || m.uid() != uid || m.gid() != gid || m.mode() & 0o7777 != mode {
                return Err(format!("refusing incompatible directory {}", path.display()).into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new().create(path)?;
            chown(path, Some(uid), Some(gid))?;
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn initialize(c: &Config) -> Result<()> {
    validate(Path::new("/"), c)?;
    directory(Path::new("/var/home"), 0, 0, 0o755)?;
    directory(
        &PathBuf::from(format!("/var/home/{}", c.user)),
        c.uid,
        c.gid,
        0o700,
    )?;
    directory(Path::new("/var/lib/systemd"), 0, 0, 0o755)?;
    directory(Path::new("/var/lib/systemd/linger"), 0, 0, 0o755)?;
    let linger = PathBuf::from(format!("/var/lib/systemd/linger/{}", c.user));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&linger)
    {
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let m = fs::symlink_metadata(&linger)?;
            if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err("unsafe linger file".into());
            }
        }
        Err(e) => return Err(e.into()),
    }
    directory(Path::new("/run/ladyboot-helpers"), 0, 0, 0o755)?;
    for name in ["newuidmap", "newgidmap"] {
        let source = Path::new("/usr/lib/ladyboot/helpers").join(name);
        let info = fs::symlink_metadata(&source)?;
        if !info.is_file() || info.uid() != 0 || info.len() > 4 * 1024 * 1024 {
            return Err("invalid mapping helper source".into());
        }
        let data = fs::read(source)?;
        let dest = Path::new("/run/ladyboot-helpers").join(name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&dest)
        {
            Ok(mut f) => {
                f.write_all(&data)?;
                f.sync_all()?;
                f.set_permissions(fs::Permissions::from_mode(0o4755))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let m = fs::symlink_metadata(&dest)?;
                if !m.is_file()
                    || m.uid() != 0
                    || m.mode() & 0o7777 != 0o4755
                    || m.len() != data.len() as u64
                    || fs::read(dest)? != data
                {
                    return Err("existing mapping helper differs".into());
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().take(8).collect();
    if args.len() != 7 {
        return Err("expected user uid gid subuid subgid count".into());
    }
    initialize(&Config {
        user: args[1].clone(),
        uid: args[2].parse()?,
        gid: args[3].parse()?,
        subuid: args[4].parse()?,
        subgid: args[5].parse()?,
        count: args[6].parse()?,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn fixture() -> Result<PathBuf> {
        let root = std::env::temp_dir().join(format!(
            "podman-init-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("etc"))?;
        fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\ncontainers:x:1000:1000:Containers:/var/home/containers:/bin/sh\n")?;
        fs::write(root.join("etc/group"), "root:x:0:\ncontainers:x:1000:\n")?;
        fs::write(root.join("etc/subuid"), "containers:65536:65536\n")?;
        fs::write(root.join("etc/subgid"), "containers:65536:65536\n")?;
        fs::set_permissions(root.join("etc"), fs::Permissions::from_mode(0o755))?;
        for file in ["passwd", "group", "subuid", "subgid"] {
            fs::set_permissions(
                root.join("etc").join(file),
                fs::Permissions::from_mode(0o644),
            )?;
        }
        Ok(root)
    }
    fn config() -> Config {
        Config {
            user: "containers".into(),
            uid: 1000,
            gid: 1000,
            subuid: 65536,
            subgid: 65536,
            count: 65536,
        }
    }
    #[test]
    fn accepts_matching_identity_without_rewriting_accounts() -> Result<()> {
        let root = fixture()?;
        let before = fs::read(root.join("etc/passwd"))?;
        validate(&root, &config())?;
        assert_eq!(fs::read(root.join("etc/passwd"))?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_changed_identity_and_preserves_existing_state() -> Result<()> {
        let root = fixture()?;
        fs::write(
            root.join("etc/passwd"),
            "containers:x:2000:1000:Containers:/var/home/containers:/bin/sh\n",
        )?;
        let before = fs::read(root.join("etc/passwd"))?;
        assert!(validate(&root, &config()).is_err());
        assert_eq!(fs::read(root.join("etc/passwd"))?, before);
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_symlink_accounts() -> Result<()> {
        let root = fixture()?;
        fs::rename(root.join("etc/subuid"), root.join("saved"))?;
        symlink("../saved", root.join("etc/subuid"))?;
        assert!(validate(&root, &config()).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_overlapping_subordinate_ranges() -> Result<()> {
        let root = fixture()?;
        fs::write(
            root.join("etc/subuid"),
            "containers:65536:65536\nforeign:70000:65536\n",
        )?;
        assert!(validate(&root, &config()).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_duplicate_identity() -> Result<()> {
        let root = fixture()?;
        fs::write(
            root.join("etc/group"),
            "containers:x:1000:\nforeign:x:1000:\n",
        )?;
        assert!(validate(&root, &config()).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_host_ids_inside_subordinate_ranges() -> Result<()> {
        for (name, record) in [
            (
                "passwd",
                "foreign:x:70000:1001:Foreign:/var/empty:/bin/false\n",
            ),
            (
                "passwd",
                "foreign:x:1001:70000:Foreign:/var/empty:/bin/false\n",
            ),
            ("group", "foreign:x:70000:\n"),
        ] {
            let root = fixture()?;
            let path = root.join("etc").join(name);
            let before = format!("{}{record}", fs::read_to_string(&path)?);
            fs::write(&path, &before)?;
            let result = validate(&root, &config());
            assert_eq!(fs::read_to_string(&path)?, before);
            fs::remove_dir_all(root)?;
            assert!(
                result.is_err(),
                "host identity in subordinate range: {record}"
            );
        }
        Ok(())
    }
    #[test]
    fn refuses_fifo_without_waiting_for_a_writer() -> Result<()> {
        let root = fixture()?;
        fs::remove_file(root.join("etc/subuid"))?;
        assert!(std::process::Command::new("mkfifo")
            .arg(root.join("etc/subuid"))
            .status()?
            .success());
        let start = std::time::Instant::now();
        assert!(validate(&root, &config()).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn refuses_numeric_subordinate_owner_aliases() -> Result<()> {
        for name in ["subuid", "subgid"] {
            for owner in ["1000", "01000", "+1000"] {
                let root = fixture()?;
                let mut c = config();
                c.gid = 2000;
                fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\ncontainers:x:1000:2000:Containers:/var/home/containers:/bin/sh\n")?;
                fs::write(root.join("etc/group"), "root:x:0:\ncontainers:x:2000:\n")?;
                let path = root.join("etc").join(name);
                let before = format!("containers:65536:65536\n{owner}:200000:65536\n");
                fs::write(&path, &before)?;
                let result = validate(&root, &c);
                assert_eq!(fs::read_to_string(&path)?, before);
                fs::remove_dir_all(root)?;
                assert!(
                    result.is_err(),
                    "numeric owner alias accepted in {name}: {owner}"
                );
            }
        }
        Ok(())
    }
}
