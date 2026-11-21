//! Bounded, non-executing reader for Go module directive syntax.
use super::super::invalid;
use crate::error::Result;
pub(super) const MAX_ITEMS: usize = 20_000;
#[derive(Debug)]
pub(super) struct Statement {
    pub directive: String,
    pub words: Vec<String>,
    pub indirect: bool,
}
fn tokens(line: &str) -> Result<(Vec<String>, &str)> {
    let mut words = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        if let Some(comment) = rest.strip_prefix("//") {
            return Ok((words, comment));
        }
        if words.len() >= 128 {
            return Err(invalid("Too many tokens in Go directive".into()));
        }
        let first = rest.as_bytes()[0];
        let (word, used) = if first == b'"' || first == b'`' {
            let mut end = None;
            let mut escaped = false;
            for (i, c) in rest.char_indices().skip(1) {
                if !escaped && c as u32 == u32::from(first) {
                    end = Some(i);
                    break;
                }
                escaped = first == b'"' && !escaped && c == '\\';
            }
            let end = end.ok_or_else(|| invalid("Unterminated Go quoted token".into()))?;
            let word = if first == b'`' {
                rest[1..end].to_owned()
            } else {
                serde_json::from_str::<String>(&rest[..=end])
                    .map_err(|_| invalid("Unsupported or invalid Go quoted escape".into()))?
            };
            (word, end + 1)
        } else if b"()[],".contains(&first) {
            (rest[..1].to_owned(), 1)
        } else {
            let end = rest
                .char_indices()
                .find(|(i, c)| {
                    c.is_whitespace() || "()[],\"`".contains(*c) || rest[*i..].starts_with("//")
                })
                .map_or(rest.len(), |(i, _)| i);
            if end == 0 {
                return Err(invalid("Invalid Go token".into()));
            }
            (rest[..end].to_owned(), end)
        };
        if word.is_empty() || word.chars().any(char::is_control) || word.len() > 4096 {
            return Err(invalid("Invalid or oversized Go token".into()));
        }
        words.push(word);
        rest = rest[used..].trim_start();
    }
    Ok((words, ""))
}
pub(super) fn parse(content: &str) -> Result<Vec<Statement>> {
    let mut block: Option<String> = None;
    let mut result = Vec::new();
    for line in content.lines() {
        let (mut words, comment) = tokens(line)?;
        if words.is_empty() {
            continue;
        }
        if words == [")"] {
            if block.take().is_none() {
                return Err(invalid("Unexpected Go block terminator".into()));
            }
            continue;
        }
        let directive = if let Some(block) = &block {
            block.clone()
        } else {
            words.remove(0)
        };
        if words == ["("] && block.is_none() {
            if !matches!(
                directive.as_str(),
                "require" | "replace" | "exclude" | "retract" | "tool" | "godebug" | "use"
            ) {
                return Err(invalid("Unsupported Go directive block".into()));
            }
            block = Some(directive);
            continue;
        }
        if words.iter().any(|w| w == "(" || w == ")") || words.is_empty() {
            return Err(invalid("Invalid Go directive or block".into()));
        }
        if result.len() >= MAX_ITEMS {
            return Err(invalid("Go directive count limit exceeded".into()));
        }
        result.push(Statement {
            directive,
            words,
            indirect: {
                let parts: Vec<_> = comment.split_whitespace().collect();
                parts == ["indirect"] || parts.len() > 1 && parts[0] == "indirect;"
            },
        });
    }
    if block.is_some() {
        return Err(invalid("Unterminated Go directive block".into()));
    }
    Ok(result)
}
