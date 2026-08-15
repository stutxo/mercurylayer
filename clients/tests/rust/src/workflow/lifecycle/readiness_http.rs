use anyhow::{ensure, Context, Result};
use serde_json::Value;

use super::readiness::{HttpResponse, MAX_HTTP_BYTES};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ParseState<T> {
    Complete(T),
    Incomplete(&'static str),
}

#[cfg(test)]
pub(super) fn parse_http(bytes: &[u8]) -> Result<ParseState<HttpResponse>> {
    parse_http_stream(bytes, true)
}

pub(super) fn parse_http_stream(
    bytes: &[u8],
    reached_eof: bool,
) -> Result<ParseState<HttpResponse>> {
    let Some(boundary) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(ParseState::Incomplete("incomplete_headers"));
    };
    let headers =
        std::str::from_utf8(&bytes[..boundary]).context("HTTP readiness headers are not UTF-8")?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .context("HTTP readiness status line is absent")?;
    ensure!(
        status
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte)),
        "malformed HTTP readiness status line"
    );
    let fields = status.split_ascii_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() >= 2 && fields[0] == "HTTP/1.1",
        "malformed HTTP readiness status line"
    );
    let status = fields[1]
        .parse::<u16>()
        .context("HTTP readiness status is not numeric")?;
    ensure!(
        (100..=599).contains(&status),
        "HTTP readiness status is out of range"
    );
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let (name, value) = parse_field(line, "header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(!chunked, "duplicate HTTP transfer encoding");
            ensure!(
                value.eq_ignore_ascii_case("chunked"),
                "unsupported HTTP transfer encoding"
            );
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            ensure!(content_length.is_none(), "duplicate HTTP content length");
            ensure!(
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                "malformed HTTP content length"
            );
            content_length = Some(
                value
                    .parse::<usize>()
                    .context("malformed HTTP content length")?,
            );
        }
    }
    ensure!(
        !(chunked && content_length.is_some()),
        "ambiguous HTTP body framing"
    );
    let raw_body = &bytes[boundary + 4..];
    let body = if chunked {
        match decode_chunked(raw_body)? {
            ParseState::Complete(body) => body,
            ParseState::Incomplete(phase) => return Ok(ParseState::Incomplete(phase)),
        }
    } else if let Some(length) = content_length {
        if raw_body.len() < length {
            return Ok(ParseState::Incomplete("incomplete_content_length_body"));
        }
        ensure!(raw_body.len() == length, "HTTP body length mismatch");
        raw_body.to_vec()
    } else {
        if !reached_eof {
            return Ok(ParseState::Incomplete("incomplete_close_delimited_body"));
        }
        raw_body.to_vec()
    };
    let body = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => Value::String(
            String::from_utf8(body)
                .context("HTTP readiness body is neither JSON nor UTF-8")?
                .trim()
                .to_owned(),
        ),
    };
    Ok(ParseState::Complete(HttpResponse { status, body }))
}

fn decode_chunked(mut bytes: &[u8]) -> Result<ParseState<Vec<u8>>> {
    let mut output = Vec::new();
    loop {
        let Some(end) = bytes.windows(2).position(|window| window == b"\r\n") else {
            return Ok(ParseState::Incomplete("incomplete_chunk_size"));
        };
        let length =
            std::str::from_utf8(&bytes[..end]).context("HTTP chunk length is not UTF-8")?;
        ensure!(
            !length.contains(';'),
            "HTTP chunk extensions are unsupported"
        );
        let length = usize::from_str_radix(length, 16).context("HTTP chunk length is malformed")?;
        bytes = &bytes[end + 2..];
        if length == 0 {
            return decode_trailers(bytes).map(|state| state.map(|()| output));
        }
        let framed = length
            .checked_add(2)
            .context("HTTP chunk length exceeds addressable size")?;
        if bytes.len() < framed {
            return Ok(ParseState::Incomplete("incomplete_chunk_data"));
        }
        ensure!(
            &bytes[length..framed] == b"\r\n",
            "malformed HTTP chunk terminator"
        );
        output.extend_from_slice(&bytes[..length]);
        ensure!(
            output.len() as u64 <= MAX_HTTP_BYTES,
            "decoded HTTP response exceeds byte limit"
        );
        bytes = &bytes[framed..];
    }
}

fn decode_trailers(bytes: &[u8]) -> Result<ParseState<()>> {
    if bytes.len() < 2 {
        return Ok(ParseState::Incomplete("incomplete_chunk_trailer"));
    }
    if bytes.starts_with(b"\r\n") {
        ensure!(bytes.len() == 2, "bytes follow HTTP chunk terminator");
        return Ok(ParseState::Complete(()));
    }
    let Some(boundary) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(ParseState::Incomplete("incomplete_chunk_trailer"));
    };
    ensure!(
        boundary + 4 == bytes.len(),
        "bytes follow HTTP chunk trailers"
    );
    let trailers =
        std::str::from_utf8(&bytes[..boundary]).context("HTTP chunk trailers are not UTF-8")?;
    for line in trailers.split("\r\n") {
        parse_field(line, "chunk trailer")?;
    }
    Ok(ParseState::Complete(()))
}

fn parse_field<'a>(line: &'a str, label: &str) -> Result<(&'a str, &'a str)> {
    let (name, value) = line
        .split_once(':')
        .with_context(|| format!("malformed HTTP {label}"))?;
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte) }),
        "malformed HTTP {label}"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f)),
        "malformed HTTP {label}"
    );
    Ok((name, value.trim()))
}

impl<T> ParseState<T> {
    fn map<U>(self, map: impl FnOnce(T) -> U) -> ParseState<U> {
        match self {
            Self::Complete(value) => ParseState::Complete(map(value)),
            Self::Incomplete(phase) => ParseState::Incomplete(phase),
        }
    }
}
