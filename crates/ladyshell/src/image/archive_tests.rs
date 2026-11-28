use super::*;
use flate2::{write::GzEncoder, Compression};
use serde_json::json;
use std::{
    cell::Cell,
    io::{Cursor, Write},
    rc::Rc,
};

fn entry<W: Write>(archive: &mut tar::Builder<W>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, name, bytes)?;
    Ok(())
}
fn manifest<W: Write>(archive: &mut tar::Builder<W>, name: &str) -> Result<()> {
    entry(
        archive,
        "manifest.json",
        &serde_json::to_vec(&json!([{"Config":name}]))?,
    )
}
fn invalid_metadata<W: Write>(
    archive: &mut tar::Builder<W>,
    name: &str,
    oversized: bool,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o644);
    if oversized {
        header.set_size(MAX_METADATA_BYTES + 1);
        header.set_cksum();
        archive.append_data(
            &mut header,
            name,
            std::io::repeat(0).take(MAX_METADATA_BYTES + 1),
        )?;
    } else {
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("unrelated")?;
        header.set_size(0);
        header.set_cksum();
        archive.append_data(&mut header, name, std::io::empty())?;
    }
    Ok(())
}
#[test]
fn config_digest_is_independent_of_manifest_order_and_archive_compression() -> Result<()> {
    for first in [false, true] {
        let mut archive = tar::Builder::new(Vec::new());
        if first {
            manifest(&mut archive, "config.json")?;
        }
        entry(&mut archive, "config.json", b"{}")?;
        if !first {
            manifest(&mut archive, "config.json")?;
        }
        let bytes = archive.into_inner()?;
        let expected = format!("sha256:{}", crate::files::hash(b"{}"));
        assert_eq!(image_id_from_reader(Cursor::new(&bytes))?, expected);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&bytes)?;
        assert_eq!(
            image_id_from_reader(flate2::read::GzDecoder::new(Cursor::new(gzip.finish()?)))?,
            expected
        );
    }
    Ok(())
}
#[test]
fn duplicate_selected_metadata_is_refused_before_and_after_manifest() -> Result<()> {
    for names in [
        ["config.json", "config.json", "manifest.json"],
        ["config.json", "manifest.json", "config.json"],
        ["manifest.json", "config.json", "config.json"],
        ["manifest.json", "config.json", "manifest.json"],
    ] {
        let mut archive = tar::Builder::new(Vec::new());
        for name in names {
            if name == "manifest.json" {
                manifest(&mut archive, "config.json")?;
            } else {
                entry(&mut archive, name, b"{}")?;
            }
        }
        assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
    }
    Ok(())
}
#[test]
fn metadata_type_size_paths_missing_and_manifest_cardinality_are_refused() -> Result<()> {
    for first in [false, true] {
        for oversized in [false, true] {
            let mut archive = tar::Builder::new(Vec::new());
            if first {
                manifest(&mut archive, "config.json")?;
            }
            invalid_metadata(&mut archive, "config.json", oversized)?;
            if !first {
                manifest(&mut archive, "config.json")?;
            }
            assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
        }
    }
    for name in ["../config.json", "/config.json", "missing.json"] {
        let mut archive = tar::Builder::new(Vec::new());
        manifest(&mut archive, name)?;
        entry(&mut archive, "config.json", b"{}")?;
        assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
    }
    for value in [json!([]), json!([{}, {}]), json!({}), json!([{}])] {
        let mut archive = tar::Builder::new(Vec::new());
        entry(&mut archive, "manifest.json", &serde_json::to_vec(&value)?)?;
        assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
    }
    for oversized in [false, true] {
        let mut archive = tar::Builder::new(Vec::new());
        invalid_metadata(&mut archive, "manifest.json", oversized)?;
        assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
    }
    Ok(())
}
struct Counted<R> {
    inner: R,
    bytes: Rc<Cell<u64>>,
}
impl<R: Read> Read for Counted<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(bytes)?;
        self.bytes.set(self.bytes.get() + read as u64);
        Ok(read)
    }
}
#[test]
fn large_compressed_layer_is_streamed_once_without_payload_retention() -> Result<()> {
    const LAYER: u64 = 32 * 1024 * 1024;
    let mut archive = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    entry(&mut archive, "config.json", b"{}")?;
    let mut header = tar::Header::new_gnu();
    header.set_size(LAYER);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, "layer.tar", std::io::repeat(0).take(LAYER))?;
    manifest(&mut archive, "config.json")?;
    let bytes = archive.into_inner()?.finish()?;
    let compressed_len = bytes.len() as u64;
    let compressed = Rc::new(Cell::new(0));
    let expanded = Rc::new(Cell::new(0));
    let started = std::time::Instant::now();
    let input = Counted {
        inner: Cursor::new(bytes),
        bytes: compressed.clone(),
    };
    let input = Counted {
        inner: flate2::read::GzDecoder::new(input),
        bytes: expanded.clone(),
    };
    assert_eq!(
        image_id_from_reader(input)?,
        format!("sha256:{}", crate::files::hash(b"{}"))
    );
    eprintln!(
        "image archive single pass: compressed={} expanded={} layer={} elapsed_ms={}",
        compressed.get(),
        expanded.get(),
        LAYER,
        started.elapsed().as_millis()
    );
    assert_eq!(compressed.get(), compressed_len);
    assert!(
        expanded.get() >= LAYER && expanded.get() <= LAYER + 4096,
        "{} decompressed bytes",
        expanded.get()
    );
    Ok(())
}

#[test]
fn entrypoint_detects_gzip_and_missing_manifest_is_refused() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("image.tar.gz");
    let mut archive = tar::Builder::new(GzEncoder::new(
        std::fs::File::create(&path)?,
        Compression::fast(),
    ));
    entry(&mut archive, "config.json", b"{}")?;
    manifest(&mut archive, "config.json")?;
    archive.into_inner()?.finish()?;
    assert_eq!(
        archive_image_id(&path)?,
        format!("sha256:{}", crate::files::hash(b"{}"))
    );
    let mut archive = tar::Builder::new(Vec::new());
    entry(&mut archive, "config.json", b"{}")?;
    assert!(image_id_from_reader(Cursor::new(archive.into_inner()?)).is_err());
    Ok(())
}

#[test]
fn extension_headers_are_refused_before_reading_their_payloads() -> Result<()> {
    for kind in *b"LKxgS" {
        let mut header = tar::Header::new_gnu();
        header.set_path("extension")?;
        header.set_entry_type(tar::EntryType::new(kind));
        header.set_mode(0o644);
        header.set_size(32 * 1024 * 1024);
        header.set_cksum();
        let bytes = Rc::new(Cell::new(0));
        let input = Counted {
            inner: Cursor::new(header.as_bytes().to_vec())
                .chain(std::io::repeat(0).take(32 * 1024 * 1024)),
            bytes: bytes.clone(),
        };
        assert!(image_id_from_reader(input).is_err());
        assert_eq!(bytes.get(), 512, "extension {kind} payload was read");
    }
    Ok(())
}
#[test]
fn archive_byte_limit_is_not_eof_and_trailing_duplicates_are_not_hidden_by_padding() -> Result<()> {
    let mut archive = tar::Builder::new(Vec::new());
    manifest(&mut archive, "config.json")?;
    entry(&mut archive, "config.json", b"{}")?;
    let mut bytes = archive.into_inner()?;
    let original_len = bytes.len() as u64;
    image_id_from_reader_with_limit(Cursor::new(&bytes), original_len)?;
    let error = image_id_from_reader_with_limit(Cursor::new(&bytes), 2048)
        .err()
        .ok_or_else(|| invalid("Byte limit treated as EOF".into()))?;
    assert!(error.to_string().contains("byte limit"), "{error}");
    let mut duplicate = tar::Builder::new(Vec::new());
    entry(&mut duplicate, "config.json", b"{}")?;
    bytes.extend(duplicate.into_inner()?);
    assert!(image_id_from_reader(Cursor::new(&bytes)).is_err());
    let error = image_id_from_reader_with_limit(Cursor::new(&bytes), original_len)
        .err()
        .ok_or_else(|| invalid("Duplicate after byte limit accepted".into()))?;
    assert!(error.to_string().contains("byte limit"), "{error}");
    Ok(())
}

#[test]
fn concatenated_gzip_members_are_one_stream_and_cannot_hide_metadata_or_trailing_data() -> Result<()>
{
    fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut output = GzEncoder::new(Vec::new(), Compression::fast());
        output.write_all(bytes)?;
        Ok(output.finish()?)
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("concatenated.tar.gz");
    for duplicate in [false, true] {
        let mut archive = tar::Builder::new(Vec::new());
        manifest(&mut archive, "config.json")?;
        entry(&mut archive, "config.json", b"{}")?;
        if duplicate {
            entry(&mut archive, "config.json", b"changed")?;
        }
        let bytes = archive.into_inner()?;
        let mut encoded = compress(&bytes[..2048])?;
        encoded.extend(compress(&bytes[2048..])?);
        std::fs::write(&path, &encoded)?;
        if duplicate {
            assert!(archive_image_id(&path).is_err());
        } else {
            assert_eq!(
                archive_image_id(&path)?,
                format!("sha256:{}", crate::files::hash(b"{}"))
            );
        }
        let error = image_id_from_reader_with_limit(
            flate2::read::MultiGzDecoder::new(Cursor::new(&encoded)),
            2048,
        )
        .err()
        .ok_or_else(|| invalid("Second gzip member escaped byte limit".into()))?;
        assert!(error.to_string().contains("byte limit"), "{error}");
        encoded.extend_from_slice(b"not another gzip member");
        std::fs::write(&path, &encoded)?;
        assert!(archive_image_id(&path).is_err());
    }
    Ok(())
}
