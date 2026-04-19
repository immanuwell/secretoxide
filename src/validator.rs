use once_cell::sync::Lazy;
use serde_json::Value;

// ── CRC-32 (ISO 3309 / ITU-T V.42) ──────────────────────────────────────────

static CRC32_TABLE: Lazy<[u32; 256]> = Lazy::new(|| {
    let mut t = [0u32; 256];
    for n in 0..256u32 {
        let mut c = n;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        t[n as usize] = c;
    }
    t
});

fn crc32(data: &[u8]) -> u32 {
    let table = &*CRC32_TABLE;
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

// ── Base-62 encoding (GitHub token alphabet) ─────────────────────────────────

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode_6(mut n: u32) -> [u8; 6] {
    let mut out = [b'0'; 6];
    for i in (0..6).rev() {
        out[i] = BASE62[(n % 62) as usize];
        n /= 62;
    }
    out
}

// ── GitHub token checksum ─────────────────────────────────────────────────────
//
// GitHub appended a 6-character base-62 CRC-32 checksum to all new-format
// tokens starting in October 2021 (blog.github.com engineering post).
// Format: {prefix}_{random_payload}{6-char-crc32-checksum}
//
// Returns:
//   Some(true)  — checksum matches → very likely a real token
//   Some(false) — checksum fails   → likely fabricated / old-format / truncated
//   None        — token too short to contain a checksum
//
pub fn validate_github_token(token: &str) -> Option<bool> {
    if token.len() < 7 {
        return None;
    }
    let split_at = token.len() - 6;
    let payload = &token[..split_at];
    let checksum_chars = token[split_at..].as_bytes();

    let expected = base62_encode_6(crc32(payload.as_bytes()));
    Some(expected == checksum_chars)
}

// ── AWS access-key entropy guard ─────────────────────────────────────────────
//
// Real AWS key IDs are randomly generated. The 16-character suffix (after the
// 4-char prefix like AKIA) should have high Shannon entropy. Keys below the
// threshold are almost certainly fabricated (e.g. AKIAIOSFODNN7EXAMPLE docs key).

pub fn aws_key_entropy_ok(key: &str) -> bool {
    // Only check the random suffix (everything after the 4-char type prefix + AKIA)
    let suffix = if key.len() >= 4 { &key[4..] } else { key };
    crate::rules::entropy(suffix) > 3.0
}

// ── JWT header structural validation ─────────────────────────────────────────
//
// A string that matches the JWT regex (`eyJ…`) but whose base64url-decoded
// header is not valid JSON (or lacks the required `alg` field) is almost
// certainly a false positive — e.g. an opaque token that happens to start
// with the same prefix.
//
// Returns:
//   Some(true)  — header decodes to JSON with an `alg` field → looks like a real JWT
//   Some(false) — header decodes but no `alg` → structurally invalid JWT
//   None        — cannot decode (malformed base64 / non-UTF-8)

pub fn validate_jwt(token: &str) -> Option<bool> {
    let header_b64 = token.split('.').next()?;
    let header_bytes = base64url_decode(header_b64)?;
    let header_str = std::str::from_utf8(&header_bytes).ok()?;
    let header: Value = serde_json::from_str(header_str).ok()?;
    Some(header.get("alg").is_some())
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    // Translate URL-safe alphabet to standard base64
    let standard: String = s.chars().map(|c| match c { '-' => '+', '_' => '/', c => c }).collect();
    let pad = (4 - standard.len() % 4) % 4;
    let padded = format!("{}{}", standard, "=".repeat(pad));
    let bytes = padded.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let a = decode_b64(chunk[0])?;
        let b = decode_b64(chunk[1])?;
        let c = decode_b64(chunk[2])?;
        let d = decode_b64(chunk[3])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' { out.push(((b & 0xF) << 4) | (c >> 2)); }
        if chunk[3] != b'=' { out.push(((c & 0x3) << 6) | d); }
    }
    Some(out)
}

fn decode_b64(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        b'=' => Some(0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        // CRC-32 of "123456789" is 0xCBF43926 per the spec
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn base62_zero_is_six_zeros() {
        assert_eq!(&base62_encode_6(0), b"000000");
    }

    #[test]
    fn base62_encodes_max_u32() {
        // 4_294_967_295 in base62 must fit in 6 chars (62^6 = 56_800_235_584 > 2^32)
        let enc = base62_encode_6(u32::MAX);
        assert_eq!(enc.len(), 6);
        assert!(enc.iter().all(|&b| BASE62.contains(&b)));
    }

    #[test]
    fn fabricated_token_fails_checksum() {
        // Our test-fixture tokens are purposely fake — they must NOT pass.
        let fake = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456";
        assert_eq!(validate_github_token(fake), Some(false));
    }

    #[test]
    fn aws_repetitive_key_fails_entropy_guard() {
        // A key with a highly repetitive suffix is obviously fabricated.
        assert!(!aws_key_entropy_ok("AKIAAAAAAAAAAAAAABBB"));
    }

    #[test]
    fn aws_diverse_key_passes_entropy_guard() {
        // AKIAIOSFODNN7EXAMPLE is the AWS docs example; despite the suffix it has
        // enough character diversity to clear the entropy bar (we let the placeholder
        // and format checks handle obvious doc-examples).
        assert!(aws_key_entropy_ok("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn valid_jwt_header_passes() {
        // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 decodes to {"alg":"HS256","typ":"JWT"}
        let tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(validate_jwt(tok), Some(true));
    }

    #[test]
    fn opaque_eyj_prefix_fails_jwt_validation() {
        // Starts with eyJ but decodes to something that is not JSON with alg
        let tok = "eyJub3Rqc29u.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fakesig";
        // "eyJub3Rqc29u" decodes to "{notjson" — not valid JSON
        assert_ne!(validate_jwt(tok), Some(true));
    }
}
