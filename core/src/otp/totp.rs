//! Codes per RFC 4226 (HMAC and dynamic truncation) and RFC 6238 (the
//! counter from the time). The HMAC state derived from the seed cannot be
//! wiped with the hmac crate; the threat model records this, as SailVault's
//! does for its block HMACs.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use super::{Algorithm, Encoder, TotpSettings};

const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// The code for the time step that contains `unix_seconds`.
pub fn code_at(settings: &TotpSettings, unix_seconds: u64) -> Zeroizing<String> {
    let counter = unix_seconds / u64::from(settings.period);
    let value = u64::from(truncated_hmac(settings, counter));
    let digits = usize::from(settings.digits);
    let mut code = Zeroizing::new(String::with_capacity(digits));
    match settings.encoder {
        Encoder::Decimal => {
            let modulus = 10u64.pow(u32::from(settings.digits));
            let mut remainder = value % modulus;
            let mut reversed = Zeroizing::new([0u8; 10]);
            for slot in reversed.iter_mut().take(digits) {
                *slot = b'0' + (remainder % 10) as u8;
                remainder /= 10;
            }
            for &digit in reversed[..digits].iter().rev() {
                code.push(char::from(digit));
            }
        }
        // Least significant character first, as Steam and KeePassXC do.
        Encoder::Steam => {
            let mut remainder = value;
            for _ in 0..digits {
                code.push(char::from(STEAM_ALPHABET[(remainder % 26) as usize]));
                remainder /= 26;
            }
        }
    }
    code
}

/// Seconds until the code changes, from 1 to the period.
pub fn seconds_remaining(settings: &TotpSettings, unix_seconds: u64) -> u32 {
    let period = u64::from(settings.period);
    (period - unix_seconds % period) as u32
}

/// RFC 4226 section 5.3: 31 bits from the HMAC at the offset its last
/// nibble names.
fn truncated_hmac(settings: &TotpSettings, counter: u64) -> u32 {
    let message = counter.to_be_bytes();
    let secret = settings.secret();
    let digest = match settings.algorithm {
        Algorithm::Sha1 => mac::<Hmac<Sha1>>(secret, &message),
        Algorithm::Sha256 => mac::<Hmac<Sha256>>(secret, &message),
        Algorithm::Sha512 => mac::<Hmac<Sha512>>(secret, &message),
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let bytes = [
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ];
    u32::from_be_bytes(bytes) & 0x7fff_ffff
}

fn mac<M: Mac + hmac::digest::KeyInit>(secret: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut mac = <M as Mac>::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}
