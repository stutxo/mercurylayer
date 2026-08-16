use anyhow::{bail, ensure, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Token {
    Ident(String),
    String(String),
    Symbol(char),
}

pub(super) fn lex(source: &str) -> Result<Vec<Token>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset].is_ascii_whitespace() {
            offset += 1;
        } else if bytes[offset..].starts_with(b"//") {
            offset = source[offset..]
                .find('\n')
                .map_or(bytes.len(), |end| offset + end + 1);
        } else if bytes[offset..].starts_with(b"/*") {
            offset = block_comment(bytes, offset)?;
        } else if let Some((end, value)) = rust_raw_string(source, offset)? {
            tokens.push(Token::String(value));
            offset = end;
        } else if let Some((end, value)) = cpp_raw_string(source, offset)? {
            tokens.push(Token::String(value));
            offset = end;
        } else if bytes[offset] == b'"' {
            let (end, value) = quoted(source, offset, '"')?;
            tokens.push(Token::String(value));
            offset = end;
        } else if bytes[offset] == b'\'' && is_char_literal(source, offset) {
            let (end, _) = quoted(source, offset, '\'')?;
            offset = end;
        } else if bytes[offset].is_ascii_alphabetic() || bytes[offset] == b'_' {
            let start = offset;
            offset += 1;
            while offset < bytes.len()
                && (bytes[offset].is_ascii_alphanumeric() || bytes[offset] == b'_')
            {
                offset += 1;
            }
            tokens.push(Token::Ident(source[start..offset].into()));
        } else {
            let character = source[offset..]
                .chars()
                .next()
                .expect("offset is within source");
            tokens.push(Token::Symbol(character));
            offset += character.len_utf8();
        }
    }
    Ok(tokens)
}

fn is_char_literal(source: &str, start: usize) -> bool {
    let body = &source[start + 1..];
    if body.starts_with('\\') {
        return body
            .char_indices()
            .nth(2)
            .is_some_and(|(_, value)| value == '\'');
    }
    let mut characters = body.char_indices();
    characters.next();
    characters.next().is_some_and(|(_, value)| value == '\'')
}

fn block_comment(bytes: &[u8], mut offset: usize) -> Result<usize> {
    let mut depth = 0usize;
    while offset < bytes.len() {
        if bytes[offset..].starts_with(b"/*") {
            depth += 1;
            offset += 2;
        } else if bytes[offset..].starts_with(b"*/") {
            depth = depth.checked_sub(1).expect("comment depth is positive");
            offset += 2;
            if depth == 0 {
                return Ok(offset);
            }
        } else {
            offset += 1;
        }
    }
    bail!("unterminated block comment in route source")
}

fn quoted(source: &str, start: usize, quote: char) -> Result<(usize, String)> {
    let mut value = String::new();
    let mut escaped = false;
    for (relative, character) in source[start + quote.len_utf8()..].char_indices() {
        if escaped {
            value.push('\\');
            value.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == quote {
            return Ok((
                start + quote.len_utf8() + relative + quote.len_utf8(),
                value,
            ));
        } else if character == '\n' || character == '\r' {
            bail!("newline in quoted route-source literal")
        } else {
            value.push(character);
        }
    }
    bail!("unterminated quoted literal in route source")
}

fn rust_raw_string(source: &str, start: usize) -> Result<Option<(usize, String)>> {
    let bytes = source.as_bytes();
    if bytes.get(start) != Some(&b'r') {
        return Ok(None);
    }
    let mut quote = start + 1;
    while bytes.get(quote) == Some(&b'#') {
        quote += 1;
    }
    if bytes.get(quote) != Some(&b'"') {
        return Ok(None);
    }
    let hashes = quote - start - 1;
    let terminator = format!("\"{}", "#".repeat(hashes));
    let body = quote + 1;
    let end = source[body..]
        .find(&terminator)
        .map(|relative| body + relative)
        .ok_or_else(|| anyhow::anyhow!("unterminated Rust raw string"))?;
    Ok(Some((end + terminator.len(), source[body..end].to_owned())))
}

fn cpp_raw_string(source: &str, start: usize) -> Result<Option<(usize, String)>> {
    if !source.as_bytes()[start..].starts_with(b"R\"") {
        return Ok(None);
    }
    let delimiter_start = start + 2;
    let open = source[delimiter_start..]
        .find('(')
        .map(|relative| delimiter_start + relative)
        .ok_or_else(|| anyhow::anyhow!("malformed C++ raw string"))?;
    let delimiter = &source[delimiter_start..open];
    ensure!(
        delimiter.len() <= 16,
        "C++ raw-string delimiter is too long"
    );
    let terminator = format!("){}\"", delimiter);
    let body = open + 1;
    let end = source[body..]
        .find(&terminator)
        .map(|relative| body + relative)
        .ok_or_else(|| anyhow::anyhow!("unterminated C++ raw string"))?;
    Ok(Some((end + terminator.len(), source[body..end].to_owned())))
}

pub(super) fn balanced(tokens: &[Token], open: usize, left: char, right: char) -> Result<usize> {
    ensure!(
        tokens.get(open) == Some(&Token::Symbol(left)),
        "balanced scan has wrong opener"
    );
    let mut depth = 0usize;
    for (offset, token) in tokens.iter().enumerate().skip(open) {
        if token == &Token::Symbol(left) {
            depth += 1;
        } else if token == &Token::Symbol(right) {
            depth = depth.checked_sub(1).context("unbalanced route tokens")?;
            if depth == 0 {
                return Ok(offset);
            }
        }
    }
    bail!("unterminated balanced route tokens")
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_normal_and_raw_strings_are_single_non_code_tokens() {
        let tokens = lex("// CROW_ROUTE(x, \"/fake\")\n/* #[get(\"/fake\")] */ \
             \"#[post(\\\"/fake\\\")]\" r#\"CROW_ROUTE(x, \"/rust-raw\")\"# \
             R\"tag(CROW_ROUTE(x, \"/cpp-raw\"))tag\" ident")
        .unwrap();
        assert_eq!(
            tokens.iter().filter(|token| matches!(token, Token::Ident(value) if value == "CROW_ROUTE" || value == "get" || value == "post")).count(),
            0
        );
        assert_eq!(tokens.last(), Some(&Token::Ident("ident".into())));
    }
}
