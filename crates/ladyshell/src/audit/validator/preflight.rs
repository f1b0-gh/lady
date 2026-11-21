// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use super::{Error, Mode};
#[derive(Clone, Copy, PartialEq)]
enum State {
    Empty,
    Value,
    Key,
    Colon,
    End,
}
struct Container {
    array: bool,
    state: State,
    count: usize,
}
fn begin(
    stack: &mut [Container],
    root: &mut bool,
    values: &mut usize,
    mode: Mode,
) -> Result<(), Error> {
    let top = stack.len() == 1;
    if let Some(c) = stack.last_mut() {
        if c.array {
            if !matches!(c.state, State::Empty | State::Value) {
                return Err(Error::Syntax);
            }
            c.count += 1;
            let limit = if top && matches!(mode, Mode::Coverage) {
                10000
            } else {
                1000
            };
            if c.count > limit {
                return Err(Error::Limit("array item limit"));
            }
        } else if c.state != State::Value {
            return Err(Error::Syntax);
        }
        c.state = State::End;
    } else {
        if *root {
            return Err(Error::Syntax);
        }
        *root = true;
    }
    *values += 1;
    if matches!(mode, Mode::Coverage) && *values > 500000 {
        return Err(Error::Limit("total value limit"));
    }
    Ok(())
}
pub fn scan(input: &str, mode: Mode) -> Result<(), Error> {
    let mut stack: Vec<Container> = Vec::with_capacity(64);
    let mut root = false;
    let mut values = 0;
    let mut in_string = false;
    let mut escaped = false;
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b' ' | b'\t' | b'\r' | b'\n' => {}
            b'"' => {
                if let Some(c) = stack
                    .last_mut()
                    .filter(|c| !c.array && matches!(c.state, State::Empty | State::Key))
                {
                    c.count += 1;
                    if matches!(mode, Mode::Coverage) && c.count > 1000 {
                        return Err(Error::Limit("object field limit"));
                    }
                    c.state = State::Colon;
                } else {
                    begin(&mut stack, &mut root, &mut values, mode)?;
                }
                in_string = true;
            }
            b'[' | b'{' => {
                begin(&mut stack, &mut root, &mut values, mode)?;
                if stack.len() >= 64 {
                    return Err(Error::Limit("nesting depth limit"));
                }
                stack.push(Container {
                    array: b == b'[',
                    state: State::Empty,
                    count: 0,
                });
            }
            b']' | b'}' => {
                let c = stack.pop().ok_or(Error::Syntax)?;
                if c.array != (b == b']') || !matches!(c.state, State::Empty | State::End) {
                    return Err(Error::Syntax);
                }
            }
            b':' => {
                let c = stack.last_mut().ok_or(Error::Syntax)?;
                if c.array || c.state != State::Colon {
                    return Err(Error::Syntax);
                }
                c.state = State::Value;
            }
            b',' => {
                let c = stack.last_mut().ok_or(Error::Syntax)?;
                if c.state != State::End {
                    return Err(Error::Syntax);
                }
                c.state = if c.array { State::Value } else { State::Key };
            }
            _ => {
                begin(&mut stack, &mut root, &mut values, mode)?;
                while i < bytes.len()
                    && !matches!(
                        bytes[i],
                        b' ' | b'\t'
                            | b'\r'
                            | b'\n'
                            | b','
                            | b':'
                            | b'['
                            | b']'
                            | b'{'
                            | b'}'
                            | b'"'
                    )
                {
                    i += 1;
                }
            }
        }
    }
    if in_string || !stack.is_empty() || !root {
        Err(Error::Syntax)
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn limits_before_materialization() {
        for mode in [Mode::Findings, Mode::Coverage] {
            assert!(scan(&format!("{}{}", "[".repeat(65), "]".repeat(65)), mode).is_err());
            assert!(scan(
                &format!("[{{\"x\":[{}]}}]", vec!["0"; 1001].join(",")),
                mode
            )
            .is_err());
            assert!(scan("[0 0]", mode).is_err());
        }
        assert!(scan(
            &format!("[{{{}}}]", vec!["\"x\":0"; 1001].join(",")),
            Mode::Coverage
        )
        .is_err());
        assert!(scan(r#"[{"x":"[\"}]", "y": [null]}]"#, Mode::Coverage).is_ok());
    }
}
