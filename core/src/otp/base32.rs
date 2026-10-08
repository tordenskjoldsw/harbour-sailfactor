//! Base32 (RFC 4648) for TOTP secrets. Decoding is as lenient as KeePassXC:
//! lowercase is accepted, '0', '1' and '8' read as 'O', 'L' and 'B', and
//! any other character (spaces, dashes, padding) is skipped. Lengths that
//! no padding can complete are rejected, as KeePassXC rejects them.

use zeroize::Zeroizing;

use super::{OtpError, MAX_SECRET_LENGTH};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn decode(text: &str) -> Result<Zeroizing<Vec<u8>>, OtpError> {
    let symbols = text.bytes().filter_map(symbol_value);
    let count = symbols.clone().count();
    // A final quantum of 1, 3 or 6 symbols carries no whole byte.
    if count == 0 || matches!(count % 8, 1 | 3 | 6) {
        return Err(OtpError::InvalidSecret);
    }
    let length = count * 5 / 8;
    if length > MAX_SECRET_LENGTH {
        return Err(OtpError::TooLong);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    let mut buffer = 0u16;
    let mut bits = 0u32;
    for value in symbols {
        buffer = (buffer << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(bytes)
}

/// Canonical form with padding, as KeePassXC writes a secret.
pub fn encode(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    for chunk in bytes.chunks(5) {
        let mut block = [0u8; 5];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = block
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | u64::from(byte));
        let symbols = (chunk.len() * 8).div_ceil(5);
        for index in 0..8 {
            if index < symbols {
                let shift = 35 - 5 * index;
                text.push(char::from(ALPHABET[((value >> shift) & 31) as usize]));
            } else {
                text.push('=');
            }
        }
    }
    text
}

fn symbol_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a'),
        b'2'..=b'7' => Some(symbol - b'2' + 26),
        b'0' => Some(b'O' - b'A'),
        b'1' => Some(b'L' - b'A'),
        b'8' => Some(b'B' - b'A'),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_4648: [(&str, &str); 6] = [
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foo", "MZXW6==="),
        ("foob", "MZXW6YQ="),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI======"),
    ];

    #[test]
    fn matches_the_rfc_4648_vectors() {
        for (plain, encoded) in RFC_4648 {
            assert_eq!(encode(plain.as_bytes()).as_str(), encoded);
            assert_eq!(decode(encoded).unwrap().as_slice(), plain.as_bytes());
            assert_eq!(
                decode(encoded.trim_end_matches('=')).unwrap().as_slice(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn decodes_as_leniently_as_keepassxc() {
        let expected = decode("JBSWY3DPEHPK3PXP").unwrap();
        for variant in [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSW-Y3DP-EHPK-3PXP",
        ] {
            assert_eq!(decode(variant).unwrap(), expected, "{variant}");
        }
        assert_eq!(decode("0018"), decode("OOLB"));
    }

    #[test]
    fn rejects_secrets_without_a_whole_byte() {
        for secret in ["", "   ", "A", "ABC", "ABCDEF", "ABCDEFGHI", "9999"] {
            assert_eq!(decode(secret), Err(OtpError::InvalidSecret), "{secret:?}");
        }
    }

    #[test]
    fn rejects_secrets_over_the_limit() {
        let longest = "A".repeat((MAX_SECRET_LENGTH * 8).div_ceil(5));
        assert_eq!(decode(&longest).unwrap().len(), MAX_SECRET_LENGTH);
        assert_eq!(
            decode(&"A".repeat(longest.len() + 8)),
            Err(OtpError::TooLong)
        );
    }
}
