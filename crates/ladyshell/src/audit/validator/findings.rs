// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use super::{
    common::*,
    json::{self, JsString, Value},
    Error, Mode,
};
use std::collections::BTreeSet;
pub fn validate(v: &Value) -> Result<Errors, Error> {
    let schema = json::parse(include_str!("report-schema.json"), Mode::Findings)
        .map_err(|_| Error::Configuration)?;
    let mut e = Errors::default();
    check(v, &schema, "$", &mut e)?;
    let mut fingerprints = BTreeSet::new();
    let mut previous = None;
    for (i, f) in v.items().iter().enumerate() {
        if e.full() {
            break;
        }
        if f.object().is_none() {
            continue;
        }
        let p = format!("$[{i}]");
        if let Value::String(id) = f.get("fingerprint") {
            e.check(
                fingerprints.insert(id),
                &format!("{p}.fingerprint"),
                "duplicate fingerprint",
            );
            e.check(
                previous.is_none_or(|old| old <= id),
                &format!("{p}.fingerprint"),
                "findings must be sorted lexicographically",
            );
            previous = Some(id);
        }
        for field in ["trace", "evidence"] {
            for (j, entry) in f.get(field).items().iter().enumerate() {
                if entry.has("line") {
                    e.check(
                        entry.get("line").positive_integer(),
                        &format!("{p}.{field}[{j}].line"),
                        "must be a positive integer",
                    );
                }
                if entry.has("file") {
                    e.check(
                        source_path(entry.get("file")),
                        &format!("{p}.{field}[{j}].file"),
                        "must be a safe repository-relative source path",
                    );
                }
            }
        }
        for (j, change) in f
            .get("remediation")
            .get("code_changes")
            .items()
            .iter()
            .enumerate()
        {
            if change.has("file_name") {
                e.check(
                    source_path(change.get("file_name")),
                    &format!("{p}.remediation.code_changes[{j}].file_name"),
                    "must be a safe repository-relative source path",
                );
            }
        }
        let trace = f.get("trace").items();
        for (j, step) in trace.iter().enumerate() {
            let kind = step.get("kind");
            let good = if trace.len() == 1 {
                kind.is("entrypoint") || kind.is("sink")
            } else if j == 0 {
                kind.is("entrypoint")
            } else if j + 1 == trace.len() {
                kind.is("sink")
            } else {
                kind.is("propagation")
            };
            e.check(
                good,
                &format!("{p}.trace[{j}].kind"),
                "invalid trace ordering",
            );
        }
        if f.get("verdict").is("confirmed") {
            e.check(
                visible(f.get("execution").get("observed_result")),
                &p,
                "confirmed finding requires visible execution observed_result",
            );
            e.check(
                visible(f.get("remediation").get("strategy")),
                &p,
                "confirmed finding requires visible remediation",
            );
            let levels = ["informational", "low", "medium", "high", "critical"];
            let overall = levels
                .iter()
                .position(|s| f.get("severity").get("overall_severity").is(s));
            let impact = levels
                .iter()
                .position(|s| f.get("severity").get("impact").get("score").is(s));
            if let (Some(a), Some(b)) = (overall, impact) {
                e.check(
                    a <= b,
                    &format!("{p}.severity.overall_severity"),
                    "cannot exceed demonstrated impact",
                );
            }
        } else if f.get("verdict").is("needs_validation") {
            let plan = f.get("validation_plan");
            e.check(
                visible(plan.get("local")) || visible(plan.get("deployment")),
                &format!("{p}.validation_plan"),
                "requires at least one visible local or deployment plan",
            );
        }
    }
    Ok(e)
}
fn property(p: &str, key: &JsString) -> String {
    let label = key.as_str();
    if label.is_some_and(|s| {
        !s.is_empty()
            && s.bytes()
                .enumerate()
                .all(|(i, c)| c.is_ascii_alphabetic() || c == b'_' || (i > 0 && c.is_ascii_digit()))
    }) {
        format!("{p}.{}", label.unwrap_or(""))
    } else {
        format!("{p}[{}]", key.quote())
    }
}
fn check(v: &Value, s: &Value, p: &str, e: &mut Errors) -> Result<(), Error> {
    if e.full() {
        return Ok(());
    }
    if let Some(branches) = s.get("oneOf").array() {
        let mut matched = 0;
        let mut selected = None;
        for branch in branches {
            let mut errors = Errors::default();
            check(v, branch, p, &mut errors)?;
            if errors.0.is_empty() {
                matched += 1;
            }
            if branch.get("properties").get("verdict").get("const") == v.get("verdict") {
                selected = Some(errors);
            }
        }
        if matched != 1 {
            e.push(p, "must match exactly one schema in oneOf");
            if matched == 0 {
                if let Some(errors) = selected {
                    for err in errors.0 {
                        if !e.full() {
                            e.0.push(err);
                        }
                    }
                }
            }
        }
    }
    if s.has("const") {
        e.check(
            v == s.get("const"),
            p,
            "value does not match required constant",
        );
    }
    if let Some(allowed) = s.get("enum").array() {
        e.check(allowed.contains(v), p, "invalid enum value");
    }
    if let Some(t) = s.get("type").text() {
        let good = v.kind() == t
            || (t == "integer"
                && v.number()
                    .is_some_and(|n| n.is_finite() && n.fract() == 0.0));
        if !good {
            e.push(p, &format!("expected {t}, got {}", v.kind()));
            return Ok(());
        }
    }
    match v {
        Value::Object(m) => {
            for req in s.get("required").items() {
                if let Some(key) = req.text() {
                    e.check(v.has(key), p, &format!("missing required field {key}"));
                }
            }
            for (key, child) in m {
                if e.full() {
                    break;
                }
                let sub = key
                    .as_str()
                    .filter(|k| s.get("properties").has(k))
                    .map(|k| s.get("properties").get(k));
                if let Some(sub) = sub {
                    check(child, sub, &property(p, key), e)?;
                } else if s.get("additionalProperties") == &Value::Bool(false) {
                    e.push(p, &format!("unexpected field {}", key.quote()));
                }
            }
        }
        Value::Array(items) => {
            if let Some(min) = s.get("minItems").number() {
                e.check(items.len() as f64 >= min, p, "too few array items");
            }
            if s.get("uniqueItems") == &Value::Bool(true) {
                let mut seen = BTreeSet::new();
                let mut bytes = 0;
                for (i, item) in items.iter().enumerate() {
                    match canonical(item) {
                        Ok(key) => {
                            if seen.contains(&key) {
                                e.push(p, &format!("items must be unique; duplicate at index {i}"));
                            } else {
                                bytes += key.len();
                                if bytes > 5 * 1024 * 1024 {
                                    e.push(
                                        p,
                                        "canonical uniqueness set exceeds 5242880 byte limit",
                                    );
                                    break;
                                }
                                seen.insert(key);
                            }
                        }
                        Err(()) => {
                            e.push(
                                &format!("{p}[{i}]"),
                                "canonical key exceeds 1048576 byte limit",
                            );
                            break;
                        }
                    }
                }
            }
            if s.has("items") {
                for (i, item) in items.iter().enumerate() {
                    if e.full() {
                        break;
                    }
                    check(item, s.get("items"), &format!("{p}[{i}]"), e)?;
                }
            }
        }
        Value::String(string) => {
            if let Some(min) = s.get("minLength").number() {
                e.check(string.codepoints() as f64 >= min, p, "string is too short");
            }
            if s.get("visibleContent") == &Value::Bool(true) {
                e.check(
                    visible(v),
                    p,
                    "must contain visible content and valid Unicode scalar values",
                );
            }
            if s.has("pattern") {
                if !s.get("pattern").is("^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$") {
                    return Err(Error::Configuration);
                }
                e.check(fingerprint(v), p, "invalid fingerprint pattern");
            }
        }
        Value::Number(n) => {
            if let Some(min) = s.get("minimum").number() {
                e.check(*n >= min, p, "number is below minimum");
            }
        }
        _ => {}
    }
    Ok(())
}
fn canonical(v: &Value) -> Result<String, ()> {
    let mut out = String::new();
    encode(v, &mut out)?;
    Ok(out)
}
fn append(out: &mut String, s: &str) -> Result<(), ()> {
    if out.len() + s.len() > 1024 * 1024 {
        return Err(());
    }
    out.push_str(s);
    Ok(())
}
fn string_key(s: &JsString, out: &mut String) -> Result<(), ()> {
    append(out, "\"")?;
    for c in char::decode_utf16(s.units.iter().copied()) {
        match c {
            Ok('"') => append(out, "\\\"")?,
            Ok('\\') => append(out, "\\\\")?,
            Ok('\n') => append(out, "\\n")?,
            Ok('\r') => append(out, "\\r")?,
            Ok('\t') => append(out, "\\t")?,
            Ok('\u{8}') => append(out, "\\b")?,
            Ok('\u{c}') => append(out, "\\f")?,
            Ok(c) if c < '\u{20}' => append(out, &format!("\\u{:04x}", c as u32))?,
            Ok(c) => append(out, c.encode_utf8(&mut [0; 4]))?,
            Err(e) => append(out, &format!("\\u{:04x}", e.unpaired_surrogate()))?,
        }
    }
    append(out, "\"")
}
fn encode(v: &Value, out: &mut String) -> Result<(), ()> {
    match v {
        Value::Null => append(out, "null"),
        Value::Bool(b) => append(out, if *b { "boolean:true" } else { "boolean:false" }),
        Value::Number(n) => {
            append(out, "number:")?;
            append(out, &number_string(*n))
        }
        Value::String(s) => {
            append(out, "string:")?;
            string_key(s, out)
        }
        Value::Array(a) => {
            append(out, "array:[")?;
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    append(out, ",")?;
                }
                encode(v, out)?;
            }
            append(out, "]")
        }
        Value::Object(m) => {
            append(out, "object:{")?;
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    append(out, ",")?;
                }
                string_key(k, out)?;
                append(out, ":")?;
                encode(v, out)?;
            }
            append(out, "}")
        }
    }
}
