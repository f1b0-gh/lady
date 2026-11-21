// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use ladyshell::audit::validator::{validate, Mode};
#[test]
fn empty_array_is_valid() {
    assert_eq!(validate(Mode::Findings, b"[]"), Ok(0));
    assert_eq!(validate(Mode::Coverage, b"[]"), Ok(0));
}
#[test]
fn non_array_is_rejected() {
    assert!(validate(Mode::Findings, b"{}").is_err());
    assert!(validate(Mode::Coverage, b"{}").is_err());
}
#[test]
fn invalid_encoding_and_structure_are_rejected() {
    for input in [b"[".as_slice(), b"[\xff]", b"[1,]", b"\xef\xbb\xbf[]"] {
        assert!(validate(Mode::Findings, input).is_err());
    }
}
#[test]
fn structural_bounds_apply_even_to_overwritten_members() {
    let over_array = format!("{{\"x\":[{}],\"x\":[]}}", vec!["0"; 1001].join(","));
    assert!(validate(Mode::Findings, over_array.as_bytes()).is_err());
    let over_fields = format!("[{{{}}}]", vec!["\"x\":0"; 1001].join(","));
    assert!(validate(Mode::Coverage, over_fields.as_bytes()).is_err());
    let deep = format!("{}0{}", "[".repeat(65), "]".repeat(65));
    assert!(validate(Mode::Findings, deep.as_bytes()).is_err());
}
