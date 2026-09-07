//! Test support: a minimal async HTTP/1.1 client, hand-rolled over
//! `tokio::net` (the house pattern, ported from `unidpp-registry`'s
//! test support and `unidpp-resolver`'s `httpc` — no
//! reqwest/hyper-client/TLS dependency). `http://` only; integration
//! servers bind loopback.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parsed `http://` request URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub host: String,
    pub port: u16,
    /// Path plus query string, always starting with `/`.
    pub path_and_query: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let (scheme, rest) = s
            .split_once("://")
            .ok_or_else(|| format!("URL must be absolute: `{s}`"))?;
        if !scheme.eq_ignore_ascii_case("http") {
            return Err(format!("unsupported URL scheme `{scheme}`"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>().map_err(|_| format!("bad port in `{s}`"))?,
            ),
            None => (authority.to_string(), 80),
        };
        if host.is_empty() {
            return Err(format!("URL has no host: `{s}`"));
        }
        Ok(Url {
            host,
            port,
            path_and_query: path,
        })
    }

    /// Percent-encode a query-parameter value (everything outside
    /// unreserved gets escaped).
    pub fn encode_query_component(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

/// A raw HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Issue an HTTP/1.1 request. Sets `Connection: close` and reads to
/// EOF or `Content-Length` (chunked transfer decoding supported).
pub async fn request(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<HttpResponse> {
    let fut = async {
        let mut stream = TcpStream::connect((url.host.as_str(), url.port)).await?;
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            method, url.path_and_query, url.host
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        if let Some(b) = body {
            stream.write_all(b).await?;
        }
        stream.flush().await?;

        let mut raw = Vec::new();
        let mut buf = [0u8; 8192];
        let header_end;
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed before headers",
                ));
            }
            raw.extend_from_slice(&buf[..n]);
            if let Some(i) = find_subslice(&raw, b"\r\n\r\n") {
                header_end = i + 4;
                break;
            }
        }
        let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("bad status line `{status_line}`"),
                )
            })?;
        let mut resp_headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                resp_headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        let mut body_bytes = raw[header_end..].to_vec();
        let chunked = resp_headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
        });
        let content_length = resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse::<usize>().ok());
        if chunked {
            let decoded = loop {
                match decode_chunked_body(&body_bytes) {
                    Ok(d) => break d,
                    Err(_) => {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed mid-chunk",
                            ));
                        }
                        body_bytes.extend_from_slice(&buf[..n]);
                    }
                }
            };
            body_bytes = decoded;
        } else if let Some(len) = content_length {
            while body_bytes.len() < len {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&buf[..n]);
            }
            body_bytes.truncate(len);
        } else {
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&buf[..n]);
            }
        }
        Ok(HttpResponse {
            status,
            headers: resp_headers,
            body: body_bytes,
        })
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "http request timed out"))?
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode a complete chunked body; errors while more data is still
/// expected (the caller reads more and retries).
fn decode_chunked_body(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let line_end = find_subslice(&raw[pos..], b"\r\n")
            .ok_or_else(|| "incomplete chunk header".to_string())?
            + pos;
        let size_str =
            std::str::from_utf8(&raw[pos..line_end]).map_err(|_| "bad chunk header".to_string())?;
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("bad chunk size `{size_hex}`"))?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        if pos + size > raw.len() {
            return Err("incomplete chunk data".to_string());
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        pos += size;
        if raw.len() < pos + 2 {
            return Err("incomplete chunk trailer".to_string());
        }
        pos += 2;
    }
}

/// Convenience wrapper for JSON test requests.
pub async fn json_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> HttpResponse {
    let url = Url::parse(url).expect("test URL");
    let mut headers: Vec<(String, String)> = Vec::new();
    if body.is_some() {
        headers.push(("content-type".into(), "application/json".into()));
    }
    if let Some(t) = token {
        headers.push(("authorization".into(), format!("Bearer {t}")));
    }
    request(
        method,
        &url,
        &headers,
        body.map(str::as_bytes),
        Duration::from_secs(5),
    )
    .await
    .expect("http request")
}

pub async fn get(url: &str) -> HttpResponse {
    json_request("GET", url, None, None).await
}

pub fn enc(s: &str) -> String {
    Url::encode_query_component(s)
}

pub fn json_of(resp: &HttpResponse) -> serde_json::Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}
