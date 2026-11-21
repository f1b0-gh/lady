// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use super::{
    common::*,
    json::{JsString, Value},
};
use std::collections::{BTreeMap, BTreeSet};
const REFS: [&str; 4] = ["surface", "boundary", "subsystem", "attack_class"];
const REQUIRED: [&str; 19] = [
    "coverage_id",
    "canonical_refs",
    "surface",
    "boundary",
    "subsystem",
    "attack_class",
    "starting_paths",
    "ordinary_attack_class_block",
    "selected_companion_blocks",
    "excluded_blocks",
    "prior_status",
    "attempts",
    "wave",
    "status",
    "agent_id",
    "reviewed_paths",
    "local_checks",
    "result_fingerprints",
    "unresolved",
];
const STATUSES: [&str; 8] = [
    "planned",
    "not_applicable",
    "out_of_scope",
    "in_progress",
    "covered",
    "candidate",
    "blocked",
    "deferred",
];
const PRIOR: [&str; 11] = [
    "new",
    "prior_confirmed_same_source",
    "prior_confirmed_changed_source",
    "prior_needs_validation",
    "prior_deferred",
    "prior_blocked",
    "prior_out_of_scope",
    "prior_covered_same_source",
    "prior_covered_changed_source",
    "prior_rejected_claim_changed",
    "none",
];
fn string(v: &Value) -> Option<&JsString> {
    if let Value::String(s) = v {
        Some(s)
    } else {
        None
    }
}
fn null(v: &Value) -> bool {
    matches!(v, Value::Null)
}
fn member(v: &Value, list: &[&str]) -> bool {
    v.text().is_some_and(|s| list.contains(&s))
}
fn canonical_id(refs: &Value) -> Option<String> {
    let fields = if refs.has("lifecycle") {
        vec![
            "surface",
            "boundary",
            "subsystem",
            "attack_class",
            "lifecycle",
        ]
    } else {
        REFS.to_vec()
    };
    if refs.object()?.len() != fields.len() {
        return None;
    }
    let mut out = String::new();
    for (i, field) in fields.iter().enumerate() {
        let v = refs.get(field);
        if !canonical_ref(v) {
            return None;
        }
        if i > 0 {
            out.push_str("::");
        }
        for b in v.text()?.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    Some(out)
}
pub fn validate(v: &Value) -> Errors {
    let mut e = Errors::default();
    let mut ids = BTreeSet::new();
    let mut semantics = BTreeMap::new();
    let mut previous = None;
    for (i, u) in v.items().iter().enumerate() {
        if e.full() {
            break;
        }
        let p = format!("$[{i}]");
        unit(u, &p, &mut e);
        if e.full() {
            break;
        }
        if let Some(id) = string(u.get("coverage_id")) {
            e.check(
                ids.insert(id),
                &format!("{p}.coverage_id"),
                "duplicate coverage ID or canonical identity collision",
            );
            let valid = REFS.iter().all(|f| text(u.get(f), 4096))
                && (!u.has("lifecycle") || text(u.get("lifecycle"), 4096));
            if valid {
                let key = [
                    u.get("surface").text(),
                    u.get("boundary").text(),
                    u.get("subsystem").text(),
                    u.get("attack_class").text(),
                    u.get("lifecycle").text(),
                ];
                if let Some(prior) = semantics.insert(key, id) {
                    e.check(
                        prior == id,
                        &format!("{p}.canonical_refs"),
                        "semantic tuple already uses a different coverage ID",
                    );
                }
            }
            e.check(
                previous.is_none_or(|prior| prior <= id),
                &format!("{p}.coverage_id"),
                "units must be sorted lexicographically",
            );
            previous = Some(id);
        }
    }
    e
}
fn unit(u: &Value, p: &str, e: &mut Errors) {
    if u.object().is_none() {
        e.push(p, "expected object");
        return;
    }
    required(u, &REQUIRED, p, e);
    for f in REFS {
        e.check(text(u.get(f), 4096), &format!("{p}.{f}"), "invalid text");
    }
    if u.has("lifecycle") {
        e.check(
            text(u.get("lifecycle"), 4096),
            &format!("{p}.lifecycle"),
            "invalid text",
        );
    }
    let refs = u.get("canonical_refs");
    if let Some(m) = refs.object() {
        for f in REFS {
            e.check(
                refs.has(f) && canonical_ref(refs.get(f)),
                &format!("{p}.canonical_refs.{f}"),
                "invalid canonical reference",
            );
        }
        if refs.has("lifecycle") {
            e.check(
                canonical_ref(refs.get("lifecycle")),
                &format!("{p}.canonical_refs.lifecycle"),
                "invalid canonical reference",
            );
        }
        e.check(
            m.keys().all(|k| {
                k.as_str()
                    .is_some_and(|s| REFS.contains(&s) || s == "lifecycle")
            }),
            &format!("{p}.canonical_refs"),
            "contains unexpected fields",
        );
        e.check(
            u.has("lifecycle") == refs.has("lifecycle"),
            p,
            "lifecycle and canonical_refs.lifecycle must appear together",
        );
    } else {
        e.push(&format!("{p}.canonical_refs"), "expected object");
    }
    e.check(
        text(u.get("coverage_id"), 65536),
        &format!("{p}.coverage_id"),
        "invalid text",
    );
    if let Some(id) = canonical_id(refs) {
        e.check(
            u.get("coverage_id").is(&id),
            &format!("{p}.coverage_id"),
            "expected canonical ID derived from canonical_refs",
        );
    }
    strings(
        u.get("starting_paths"),
        &format!("{p}.starting_paths"),
        e,
        true,
        true,
        false,
    );
    e.check(
        null(u.get("ordinary_attack_class_block"))
            || text(u.get("ordinary_attack_class_block"), 4096),
        &format!("{p}.ordinary_attack_class_block"),
        "expected null or non-empty text",
    );
    strings(
        u.get("selected_companion_blocks"),
        &format!("{p}.selected_companion_blocks"),
        e,
        false,
        false,
        false,
    );
    excluded(
        u.get("excluded_blocks"),
        u.get("selected_companion_blocks"),
        &format!("{p}.excluded_blocks"),
        e,
    );
    e.check(
        member(u.get("prior_status"), &PRIOR),
        &format!("{p}.prior_status"),
        "invalid value",
    );
    e.check(
        member(u.get("status"), &STATUSES),
        &format!("{p}.status"),
        "invalid value",
    );
    e.check(
        u.get("wave").positive_integer(),
        &format!("{p}.wave"),
        "expected positive integer",
    );
    e.check(
        null(u.get("agent_id")) || agent(u.get("agent_id")),
        &format!("{p}.agent_id"),
        "expected null or safe agent ID",
    );
    attempts(u, p, e);
    evidence(u, p, e);
    state(u, p, e);
}
fn excluded(v: &Value, selected: &Value, p: &str, e: &mut Errors) {
    let Some(items) = v.array() else {
        e.push(p, "expected array");
        return;
    };
    let mut seen = BTreeSet::new();
    for (i, item) in items.iter().enumerate() {
        if e.full() {
            break;
        }
        let loc = format!("{p}[{i}]");
        if item.object().is_none() {
            e.push(&loc, "expected object");
            continue;
        }
        for field in ["block", "reason"] {
            e.check(
                text(item.get(field), 4096),
                &format!("{loc}.{field}"),
                "invalid text",
            );
        }
        if let Some(s) = string(item.get("block")) {
            e.check(seen.insert(s), &format!("{loc}.block"), "duplicate entry");
        }
        e.check(
            !selected.items().contains(item.get("block")),
            &format!("{loc}.block"),
            "block is also selected",
        );
    }
}
fn evidence(u: &Value, p: &str, e: &mut Errors) {
    strings(
        u.get("reviewed_paths"),
        &format!("{p}.reviewed_paths"),
        e,
        false,
        true,
        false,
    );
    checks(u.get("local_checks"), &format!("{p}.local_checks"), e);
    ownership(u, p, e);
    strings(
        u.get("result_fingerprints"),
        &format!("{p}.result_fingerprints"),
        e,
        false,
        false,
        true,
    );
    strings(
        u.get("unresolved"),
        &format!("{p}.unresolved"),
        e,
        false,
        false,
        false,
    );
}
fn checks(v: &Value, p: &str, e: &mut Errors) {
    let Some(items) = v.array() else {
        e.push(p, "expected array");
        return;
    };
    for (i, c) in items.iter().enumerate() {
        if e.full() {
            break;
        }
        let loc = format!("{p}[{i}]");
        if c.object().is_none() {
            e.push(&loc, "expected object");
            continue;
        }
        required(
            c,
            &[
                "agent_id",
                "reviewed_paths",
                "invariant",
                "method",
                "result",
                "artifact",
            ],
            &loc,
            e,
        );
        e.check(
            agent(c.get("agent_id")),
            &format!("{loc}.agent_id"),
            "expected canonical lowercase agent ID",
        );
        strings(
            c.get("reviewed_paths"),
            &format!("{loc}.reviewed_paths"),
            e,
            true,
            true,
            false,
        );
        for f in ["invariant", "result"] {
            e.check(text(c.get(f), 4096), &format!("{loc}.{f}"), "invalid text");
        }
        e.check(
            member(c.get("method"), &["source", "local"]),
            &format!("{loc}.method"),
            "expected source or local",
        );
        if c.get("method").is("source") {
            e.check(
                null(c.get("artifact")),
                &format!("{loc}.artifact"),
                "source-only check must use null",
            );
        } else if c.get("method").is("local") {
            let owned = agent(c.get("agent_id"))
                && source_path(c.get("artifact"))
                && c.get("artifact")
                    .text()
                    .zip(c.get("agent_id").text())
                    .is_some_and(|(artifact, id)| {
                        let prefix = format!("agents/{id}/artifacts/");
                        artifact.starts_with(&prefix) && artifact.len() > prefix.len()
                    });
            e.check(
                owned,
                &format!("{loc}.artifact"),
                "local check requires an artifact owned by its agent",
            );
        } else {
            e.check(
                null(c.get("artifact")) || source_path(c.get("artifact")),
                &format!("{loc}.artifact"),
                "expected null or safe output-relative path",
            );
        }
    }
}
fn ownership(u: &Value, p: &str, e: &mut Errors) {
    let (Some(paths), Some(checks)) = (
        u.get("reviewed_paths").array(),
        u.get("local_checks").array(),
    ) else {
        return;
    };
    let aggregate: BTreeSet<_> = paths.iter().filter_map(string).collect();
    let owned: BTreeSet<_> = checks
        .iter()
        .flat_map(|c| c.get("reviewed_paths").items())
        .filter_map(string)
        .collect();
    e.check(
        aggregate == owned,
        p,
        "reviewed_paths and check-owned paths must match",
    );
}
fn empty(u: &Value, field: &str, p: &str, e: &mut Errors) {
    e.check(
        u.get(field).items().is_empty(),
        &format!("{p}.{field}"),
        "status requires an empty array",
    );
}
fn nonempty(u: &Value, field: &str, p: &str, e: &mut Errors) {
    e.check(
        !u.get(field).items().is_empty(),
        &format!("{p}.{field}"),
        "status requires entries",
    );
}
fn state(u: &Value, p: &str, e: &mut Errors) {
    let status = u.get("status");
    if !status.is("candidate") {
        empty(u, "result_fingerprints", p, e);
    }
    if member(
        status,
        &[
            "planned",
            "not_applicable",
            "out_of_scope",
            "deferred",
            "in_progress",
        ],
    ) {
        for f in ["reviewed_paths", "local_checks"] {
            empty(u, f, p, e);
        }
        if status.is("in_progress") {
            e.check(
                agent(u.get("agent_id")),
                &format!("{p}.agent_id"),
                "status requires canonical agent ID",
            );
        } else {
            e.check(
                null(u.get("agent_id")),
                &format!("{p}.agent_id"),
                "status must be unassigned",
            );
        }
        if member(status, &["planned", "in_progress"]) {
            empty(u, "unresolved", p, e);
        } else {
            nonempty(u, "unresolved", p, e);
        }
    } else if member(status, &["covered", "blocked", "candidate"]) {
        e.check(
            agent(u.get("agent_id")),
            &format!("{p}.agent_id"),
            "status requires canonical agent ID",
        );
        for f in ["reviewed_paths", "local_checks"] {
            nonempty(u, f, p, e);
        }
        if status.is("covered") {
            empty(u, "unresolved", p, e);
        } else if status.is("blocked") {
            nonempty(u, "unresolved", p, e);
        } else {
            nonempty(u, "result_fingerprints", p, e);
        }
    }
}
fn attempts(u: &Value, p: &str, e: &mut Errors) {
    let Some(items) = u.get("attempts").array() else {
        e.push(&format!("{p}.attempts"), "expected array");
        return;
    };
    let mut owners = BTreeSet::new();
    let mut artifacts = BTreeSet::new();
    let mut wave = 0.0;
    for (i, a) in items.iter().enumerate() {
        if e.full() {
            break;
        }
        let loc = format!("{p}.attempts[{i}]");
        if a.object().is_none() {
            e.push(&loc, "expected object");
            continue;
        }
        required(
            a,
            &[
                "wave",
                "status",
                "agent_id",
                "reviewed_paths",
                "local_checks",
                "result_fingerprints",
                "unresolved",
                "reassignment_reason",
            ],
            &loc,
            e,
        );
        e.check(
            a.get("wave").positive_integer(),
            &format!("{loc}.wave"),
            "expected positive integer",
        );
        if let Some(n) = a
            .get("wave")
            .number()
            .filter(|_| a.get("wave").positive_integer())
        {
            e.check(
                n > wave,
                &format!("{loc}.wave"),
                "archived attempt waves must be strictly increasing",
            );
            if let Some(current) = u
                .get("wave")
                .number()
                .filter(|n| n.is_finite() && n.fract() == 0.0)
            {
                e.check(
                    n < current,
                    &format!("{loc}.wave"),
                    "archived attempt wave must precede current wave",
                );
            }
            wave = n;
        }
        e.check(
            member(a.get("status"), &["covered", "candidate", "blocked"]),
            &format!("{loc}.status"),
            "expected covered, candidate, or blocked",
        );
        let owner = a.get("agent_id");
        e.check(
            agent(owner),
            &format!("{loc}.agent_id"),
            "archived attempt requires canonical agent ID",
        );
        if let Some(id) = string(owner) {
            e.check(
                !owners.contains(id),
                &format!("{loc}.agent_id"),
                "assignment owner must be fresh for each attempt",
            );
        }
        evidence(a, &loc, e);
        e.check(
            text(a.get("reassignment_reason"), 4096),
            &format!("{loc}.reassignment_reason"),
            "invalid text",
        );
        state(a, &loc, e);
        for (j, c) in a.get("local_checks").items().iter().enumerate() {
            if c.object().is_none() {
                continue;
            }
            let base = format!("{loc}.local_checks[{j}]");
            if let Some(id) = string(c.get("agent_id")) {
                e.check(
                    !owners.contains(id),
                    &format!("{base}.agent_id"),
                    "prior assignment owner evidence must remain in earlier attempt",
                );
            }
            if let Some(artifact) = string(c.get("artifact")) {
                e.check(
                    !artifacts.contains(artifact),
                    &format!("{base}.artifact"),
                    "artifact from earlier attempt cannot be reused",
                );
                if c.get("method").is("local") {
                    artifacts.insert(artifact);
                }
            }
        }
        if agent(owner) {
            if let Some(id) = string(owner) {
                owners.insert(id);
            }
        }
    }
    if agent(u.get("agent_id")) {
        if let Some(id) = string(u.get("agent_id")) {
            e.check(
                !owners.contains(id),
                &format!("{p}.agent_id"),
                "current assignment owner must be fresh after reassignment",
            );
        }
    }
    for (j, c) in u.get("local_checks").items().iter().enumerate() {
        let loc = format!("{p}.local_checks[{j}]");
        if let Some(id) = string(c.get("agent_id")) {
            e.check(
                !owners.contains(id),
                &format!("{loc}.agent_id"),
                "prior assignment owner evidence must remain archived",
            );
        }
        if let Some(artifact) = string(c.get("artifact")) {
            e.check(
                !artifacts.contains(artifact),
                &format!("{loc}.artifact"),
                "archived artifact cannot be reused",
            );
        }
    }
}
