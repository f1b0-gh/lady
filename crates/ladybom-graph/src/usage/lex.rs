//! Bounded lexical evidence, deliberately not a language parser or macro expander.
#[derive(Debug, PartialEq)]
pub(super) enum Token {
    Word(String),
    String(String),
    Punct(u8),
}
impl Token {
    pub fn word(&self) -> Option<&str> {
        if let Self::Word(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn string(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn is(&self, value: &str) -> bool {
        self.word() == Some(value)
    }
    pub fn punct(&self, value: u8) -> bool {
        *self == Self::Punct(value)
    }
}
pub(super) fn tokens(text: &str, language: &str) -> (Vec<Token>, bool) {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut tokens = Vec::new();
    let mut uncertain = false;
    while i < bytes.len() {
        if tokens.len() >= 1_000_000 {
            uncertain = true;
            break;
        }
        let byte = bytes[i];
        if (language == "python" && byte == b'#')
            || (language != "python" && bytes[i..].starts_with(b"//"))
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if language != "python" && bytes[i..].starts_with(b"/*") {
            let mut nesting = 1;
            i += 2;
            while i < bytes.len() && nesting > 0 {
                if bytes[i..].starts_with(b"*/") {
                    nesting -= 1;
                    i += 2;
                } else if language == "rust" && bytes[i..].starts_with(b"/*") {
                    nesting += 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            uncertain |= nesting != 0;
            continue;
        }
        if language == "rust" && byte == b'r' {
            let start = i;
            let mut q = i + 1;
            while q < bytes.len() && bytes[q] == b'#' {
                q += 1;
            }
            if q < bytes.len() && bytes[q] == b'"' {
                let closing = format!("\"{}", "#".repeat(q - start - 1));
                if let Some(end) = text[q + 1..].find(&closing) {
                    tokens.push(Token::String(text[q + 1..q + 1 + end].into()));
                    i = q + 1 + end + closing.len();
                } else {
                    uncertain = true;
                    break;
                }
                continue;
            }
            if bytes[i..].starts_with(b"r#") {
                i += 2;
                continue;
            }
        }
        // Apostrophes in Rust also introduce lifetimes. Treat a simple character
        // literal as a string; otherwise keep the lifetime identifier as evidence.
        let rust_character = language == "rust"
            && byte == b'\''
            && ((i + 2 < bytes.len() && bytes[i + 2] == b'\'')
                || (i + 3 < bytes.len() && bytes[i + 1] == b'\\' && bytes[i + 3] == b'\''));
        if byte == b'"'
            || (byte == b'\'' && (language != "rust" || rust_character))
            || (language == "npm" && byte == b'`')
        {
            let triple = language == "python" && bytes[i..].starts_with(&[byte, byte, byte]);
            let width = if triple { 3 } else { 1 };
            let start = i + width;
            i = start;
            let mut escaped = false;
            let mut closed = false;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    escaped = true;
                    i = (i + 2).min(bytes.len());
                    continue;
                }
                if bytes[i] == byte && (!triple || bytes[i..].starts_with(&[byte, byte, byte])) {
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                uncertain = true;
                break;
            }
            if byte == b'`' || escaped {
                uncertain = true;
            }
            if !triple {
                tokens.push(Token::String(text[start..i].into()));
            }
            i += width;
            continue;
        }
        if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            tokens.push(Token::Word(text[start..i].into()));
            continue;
        }
        if !byte.is_ascii_whitespace() || byte == b'\n' {
            tokens.push(Token::Punct(byte));
        }
        i += 1;
    }
    (tokens, uncertain)
}
