// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use super::json::Value;
use super::unicode_tables::{FORBIDDEN, INVISIBLE};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;
fn contains(ranges: &[(u32, u32)], c: char) -> bool {
    let n = c as u32;
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < n {
                std::cmp::Ordering::Less
            } else if lo > n {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
pub fn visible(v: &Value) -> bool {
    v.text()
        .is_some_and(|s| s.chars().any(|c| !contains(INVISIBLE, c)))
}
pub fn js_whitespace(c: char) -> bool {
    matches!(c,'\u{9}'..='\u{d}'|'\u{20}'|'\u{a0}'|'\u{1680}'|'\u{2000}'..='\u{200a}'|'\u{2028}'|'\u{2029}'|'\u{202f}'|'\u{205f}'|'\u{3000}'|'\u{feff}')
}
pub fn text(v: &Value, max: usize) -> bool {
    v.text().is_some_and(|s| {
        !s.is_empty() && s.encode_utf16().count() <= max && s.trim_matches(js_whitespace) == s
    }) && visible(v)
}
pub fn canonical_ref(v: &Value) -> bool {
    text(v, 1024)
        && v.text()
            .is_some_and(|s| !s.chars().any(|c| contains(FORBIDDEN, c)) && s.nfc().eq(s.chars()))
}
pub fn source_path(v: &Value) -> bool {
    v.text().is_some_and(safe_path)
}
fn safe_path(s: &str) -> bool {
    if s.is_empty()
        || s.trim_matches(js_whitespace) != s
        || s.chars().any(|c| contains(FORBIDDEN, c))
        || s.contains(['\\', ':'])
        || s.starts_with(['~', '/'])
    {
        return false;
    }
    s.split('/').all(|part| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && !part.ends_with([' ', '.'])
            && !reserved_component(part)
    })
}
fn reserved_component(s: &str) -> bool {
    let base = s.split('.').next().unwrap_or("").to_lowercase();
    if ["con", "prn", "aux", "nul", "clock$", "conin$", "conout$"].contains(&base.as_str()) {
        return true;
    }
    ["com", "lpt"].iter().any(|p| {
        base.strip_prefix(p).is_some_and(|n| {
            n.chars().count() == 1 && n.chars().all(|c| matches!(c, '1'..='9' | '¹' | '²' | '³'))
        })
    })
}
pub fn agent(v: &Value) -> bool {
    v.text().is_some_and(|s| {
        !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
            && !(["con", "prn", "aux", "nul"].contains(&s)
                || ["com", "lpt"].iter().any(|p| {
                    s.strip_prefix(p).is_some_and(|n| {
                        n.len() == 1 && n.bytes().all(|c| matches!(c, b'1'..=b'9'))
                    })
                }))
    })
}
pub fn fingerprint(v: &Value) -> bool {
    v.text().is_some_and(|s| {
        !s.is_empty()
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._:/@+-".contains(&c))
    })
}
pub fn safe_diagnostic(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if contains(FORBIDDEN, c) {
            if c as u32 <= 0xffff {
                out.push_str(&format!("\\u{:04x}", c as u32));
            } else {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
        } else {
            out.push(c);
        }
    }
    out
}
#[derive(Default)]
pub struct Errors(pub Vec<String>);
impl Errors {
    pub fn push(&mut self, location: &str, message: &str) {
        if self.0.len() < 100 {
            self.0.push(format!(
                "{}: {}",
                safe_diagnostic(location),
                safe_diagnostic(message)
            ));
        }
    }
    pub fn check(&mut self, good: bool, location: &str, message: &str) {
        if !good {
            self.push(location, message);
        }
    }
    pub fn full(&self) -> bool {
        self.0.len() >= 100
    }
}
pub fn required(v: &Value, fields: &[&str], p: &str, e: &mut Errors) {
    for field in fields {
        e.check(v.has(field), p, &format!("missing required field {field}"));
    }
}
pub fn strings(
    v: &Value,
    p: &str,
    e: &mut Errors,
    nonempty: bool,
    paths: bool,
    fingerprints: bool,
) {
    let Some(items) = v.array() else {
        e.push(p, "expected array");
        return;
    };
    e.check(!nonempty || !items.is_empty(), p, "must not be empty");
    let mut seen = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        if e.full() {
            break;
        }
        let loc = format!("{p}[{i}]");
        e.check(
            if paths {
                source_path(item)
            } else {
                text(item, 4096)
            },
            &loc,
            if paths {
                "invalid repository-relative path"
            } else {
                "invalid text"
            },
        );
        if fingerprints {
            e.check(fingerprint(item), &loc, "invalid fingerprint");
        }
        if let Value::String(s) = item {
            e.check(seen.insert(s), &loc, "duplicate entry");
        }
    }
}
pub fn number_string(n: f64) -> String {
    if n == 0.0 {
        "0".into()
    } else {
        ryu_js::Buffer::new().format(n).to_owned()
    }
}
