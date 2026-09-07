//! Hex codec shared by the keyring (seed decoding, public-key encoding)
//! and the wire layer (signatures, public keys, attestations).
//! Hand-rolled on purpose — public keys and signatures are short, the
//! codec is twenty lines, and the dependency-light doctrine prefers
//! avoiding the `hex` crate.

/// Hex-encode bytes (lower-case).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 * bytes.len());
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode hex bytes; accepts lower- or upper-case, ignores `0x`/`0X`
/// prefixes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim();
    let body = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        rest
    } else {
        trimmed
    };
    if body.len() % 2 != 0 {
        return Err(format!("hex string of odd length `{}`", body.len()));
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("not a hex digit `{}`", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for bytes in [
            &b""[..],
            &b"\x00"[..],
            &b"\x01\x23\x45\x67\x89\xab\xcd\xef"[..],
        ] {
            assert_eq!(hex_decode(&hex_encode(bytes)).unwrap(), bytes);
        }
    }

    #[test]
    fn accepts_prefix_and_case() {
        assert_eq!(
            hex_decode("0xdeadBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode("DEADbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }
}
