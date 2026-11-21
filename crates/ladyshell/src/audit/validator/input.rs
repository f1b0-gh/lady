// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use super::Error;
use std::{io::Read, path::Path};
pub trait Env {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Error>;
}
pub struct RealEnv;
impl Env for RealEnv {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)
                .map_err(|_| Error::Input)?;
            let metadata = file.metadata().map_err(|_| Error::Input)?;
            if !metadata.is_file() {
                return Err(Error::Input);
            }
            if metadata.len() > 5 * 1024 * 1024 {
                return Err(Error::Limit("5242880 byte limit"));
            }
            let mut bytes = Vec::new();
            file.take(5 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Input)?;
            if bytes.len() > 5 * 1024 * 1024 {
                return Err(Error::Limit("5242880 byte limit"));
            }
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(Error::Input)
        }
    }
}
