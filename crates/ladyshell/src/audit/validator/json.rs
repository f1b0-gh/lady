// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
//! Bounded JSON reader preserving ECMAScript UTF-16 strings and binary64 numbers.
use super::{Error, Mode};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct JsString {
    pub units: Vec<u16>,
    text: Option<String>,
}
impl JsString {
    fn new(units: Vec<u16>) -> Self {
        let text = String::from_utf16(&units).ok();
        Self { units, text }
    }
    pub fn as_str(&self) -> Option<&str> {
        self.text.as_deref()
    }
    pub fn json(&self) -> String {
        let mut out = String::from("\"");
        for c in char::decode_utf16(self.units.iter().copied()) {
            match c {
                Ok('"') => out.push_str("\\\""),
                Ok('\\') => out.push_str("\\\\"),
                Ok('\n') => out.push_str("\\n"),
                Ok('\r') => out.push_str("\\r"),
                Ok('\t') => out.push_str("\\t"),
                Ok('\u{8}') => out.push_str("\\b"),
                Ok('\u{c}') => out.push_str("\\f"),
                Ok(c) if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
                Ok(c) => out.push(c),
                Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
            }
        }
        out.push('"');
        out
    }
    pub fn quote(&self) -> String {
        let mut units: Vec<u16> = self.units.iter().take(256).copied().collect();
        if self.units.len() > 256 {
            units.extend([46, 46, 46]);
        }
        Self::new(units).json()
    }
    pub fn codepoints(&self) -> usize {
        char::decode_utf16(self.units.iter().copied()).count()
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(JsString),
    Array(Vec<Value>),
    Object(BTreeMap<JsString, Value>),
}
impl Value {
    pub fn get(&self, key: &str) -> &Self {
        if let Self::Object(m) = self {
            for (k, v) in m {
                if k.as_str() == Some(key) {
                    return v;
                }
            }
        }
        &Self::Null
    }
    pub fn has(&self, key: &str) -> bool {
        matches!(self, Self::Object(m) if m.keys().any(|k| k.as_str() == Some(key)))
    }
    pub fn text(&self) -> Option<&str> {
        if let Self::String(s) = self {
            s.as_str()
        } else {
            None
        }
    }
    pub fn is(&self, text: &str) -> bool {
        self.text() == Some(text)
    }
    pub fn array(&self) -> Option<&[Self]> {
        if let Self::Array(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn items(&self) -> &[Self] {
        self.array().unwrap_or(&[])
    }
    pub fn object(&self) -> Option<&BTreeMap<JsString, Self>> {
        if let Self::Object(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn number(&self) -> Option<f64> {
        if let Self::Number(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    pub fn positive_integer(&self) -> bool {
        self.number()
            .is_some_and(|n| n.is_finite() && n.fract() == 0.0 && n >= 1.0)
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "boolean",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }
}
pub fn parse(input: &str, mode: Mode) -> Result<Value, Error> {
    let mut p = Parser {
        input: input.as_bytes(),
        pos: 0,
        mode,
        values: 0,
    };
    let result = p.value(0)?;
    p.ws();
    if p.pos != p.input.len() {
        return Err(Error::Syntax);
    }
    Ok(result)
}
struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    mode: Mode,
    values: usize,
}
impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .input
            .get(self.pos)
            .is_some_and(|c| matches!(c, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }
    fn take(&mut self, byte: u8) -> bool {
        if self.input.get(self.pos) == Some(&byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        self.ws();
        self.values += 1;
        if matches!(self.mode, Mode::Coverage) && self.values > 500_000 {
            return Err(Error::Limit("total value limit"));
        }
        match self.input.get(self.pos).copied() {
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                if depth >= 64 {
                    return Err(Error::Limit("nesting depth limit"));
                }
                self.pos += 1;
                self.ws();
                let mut v = Vec::new();
                if self.take(b']') {
                    return Ok(Value::Array(v));
                }
                let limit = if depth == 0 && matches!(self.mode, Mode::Coverage) {
                    10_000
                } else {
                    1000
                };
                loop {
                    if v.len() >= limit {
                        return Err(Error::Limit("array item limit"));
                    }
                    v.push(self.value(depth + 1)?);
                    self.ws();
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(Error::Syntax);
                    }
                }
                Ok(Value::Array(v))
            }
            Some(b'{') => {
                if depth >= 64 {
                    return Err(Error::Limit("nesting depth limit"));
                }
                self.pos += 1;
                self.ws();
                let mut m = BTreeMap::new();
                let mut fields = 0;
                if self.take(b'}') {
                    return Ok(Value::Object(m));
                }
                loop {
                    self.ws();
                    fields += 1;
                    if matches!(self.mode, Mode::Coverage) && fields > 1000 {
                        return Err(Error::Limit("object field limit"));
                    }
                    let k = self.string()?;
                    self.ws();
                    if !self.take(b':') {
                        return Err(Error::Syntax);
                    }
                    let v = self.value(depth + 1)?;
                    m.insert(k, v);
                    self.ws();
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err(Error::Syntax);
                    }
                }
                Ok(Value::Object(m))
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(Error::Syntax),
        }
    }
    fn literal(&mut self, s: &[u8]) -> Result<(), Error> {
        if self.input.get(self.pos..self.pos + s.len()) == Some(s) {
            self.pos += s.len();
            Ok(())
        } else {
            Err(Error::Syntax)
        }
    }
    fn number(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        self.take(b'-');
        if !self.take(b'0') {
            let begin = self.pos;
            while self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
            if self.pos == begin {
                return Err(Error::Syntax);
            }
        }
        if self.take(b'.') {
            let begin = self.pos;
            while self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
            if self.pos == begin {
                return Err(Error::Syntax);
            }
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            let begin = self.pos;
            while self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
            if self.pos == begin {
                return Err(Error::Syntax);
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| Error::Syntax)?;
        Ok(Value::Number(text.parse().map_err(|_| Error::Syntax)?))
    }
    fn string(&mut self) -> Result<JsString, Error> {
        if !self.take(b'"') {
            return Err(Error::Syntax);
        }
        let mut units = Vec::new();
        loop {
            let c = *self.input.get(self.pos).ok_or(Error::Syntax)?;
            self.pos += 1;
            match c {
                b'"' => return Ok(JsString::new(units)),
                b'\\' => {
                    let e = *self.input.get(self.pos).ok_or(Error::Syntax)?;
                    self.pos += 1;
                    units.push(match e {
                        b'"' => 34,
                        b'\\' => 92,
                        b'/' => 47,
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        b'u' => {
                            let mut n = 0;
                            for _ in 0..4 {
                                let h = *self.input.get(self.pos).ok_or(Error::Syntax)?;
                                self.pos += 1;
                                n = n * 16
                                    + match h {
                                        b'0'..=b'9' => (h - b'0') as u16,
                                        b'a'..=b'f' => (h - b'a' + 10) as u16,
                                        b'A'..=b'F' => (h - b'A' + 10) as u16,
                                        _ => return Err(Error::Syntax),
                                    };
                            }
                            n
                        }
                        _ => return Err(Error::Syntax),
                    });
                }
                0..=31 => return Err(Error::Syntax),
                32..=127 => units.push(c as u16),
                _ => {
                    self.pos -= 1;
                    let width = match c {
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return Err(Error::Utf8),
                    };
                    let bytes = self
                        .input
                        .get(self.pos..self.pos + width)
                        .ok_or(Error::Utf8)?;
                    let rest = std::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
                    let ch = rest.chars().next().ok_or(Error::Syntax)?;
                    self.pos += ch.len_utf8();
                    units.extend(ch.encode_utf16(&mut [0; 2]).iter().copied());
                }
            }
        }
    }
}
