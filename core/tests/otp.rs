//! TOTP codes against the RFC vectors, and reading and writing settings as
//! KeePassXC does.

use std::collections::HashMap;

use sailtoken_core::otp::{
    code_at, parse_uri, seconds_remaining, settings_from_attributes, write_uri, Algorithm, Encoder,
    OtpError, TotpSettings, MAX_URI_LENGTH,
};

// The RFC 6238 seeds "1234567890..." of 20, 32 and 64 bytes in Base32.
const SEED_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const SEED_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
const SEED_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=";
const EXAMPLE_SECRET: &str = "JBSWY3DPEHPK3PXP";

fn settings(secret: &str, algorithm: Algorithm, digits: u8, period: u32) -> TotpSettings {
    TotpSettings::new(secret, algorithm, digits, period, Encoder::Decimal).unwrap()
}

fn from_attributes(attributes: &[(&str, &str)]) -> Result<Option<TotpSettings>, OtpError> {
    let attributes: HashMap<&str, &str> = attributes.iter().copied().collect();
    settings_from_attributes(|name| attributes.get(name).copied())
}

fn code(settings: &TotpSettings, unix_seconds: u64) -> String {
    code_at(settings, unix_seconds).to_string()
}

#[test]
fn matches_rfc_4226_appendix_d() {
    // HOTP is TOTP with a period of one second at time = counter.
    let hotp = settings(SEED_SHA1, Algorithm::Sha1, 6, 1);
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, expected) in expected.iter().enumerate() {
        assert_eq!(code(&hotp, counter as u64), *expected, "counter {counter}");
    }
}

#[test]
fn matches_rfc_6238_appendix_b() {
    let sha1 = settings(SEED_SHA1, Algorithm::Sha1, 8, 30);
    let sha256 = settings(SEED_SHA256, Algorithm::Sha256, 8, 30);
    let sha512 = settings(SEED_SHA512, Algorithm::Sha512, 8, 30);
    let table: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];
    for (time, expected_sha1, expected_sha256, expected_sha512) in table {
        assert_eq!(code(&sha1, time), expected_sha1, "SHA-1 at {time}");
        assert_eq!(code(&sha256, time), expected_sha256, "SHA-256 at {time}");
        assert_eq!(code(&sha512, time), expected_sha512, "SHA-512 at {time}");
    }
}

#[test]
fn steam_codes_use_five_letters_least_significant_first() {
    // Computed independently with Python's hmac module.
    let steam = TotpSettings::new(SEED_SHA1, Algorithm::Sha1, 5, 30, Encoder::Steam).unwrap();
    for (time, expected) in [
        (59, "PV9M4"),
        (1111111109, "PY4YB"),
        (1234567890, "VHHQY"),
        (2000000000, "9N776"),
    ] {
        assert_eq!(code(&steam, time), expected, "at {time}");
    }
}

#[test]
fn codes_keep_leading_zeros_for_every_length() {
    // The truncated HMAC at 1111111109 is 907081804 (computed independently
    // with Python); each length takes its last digits, zero-padded.
    let expected = [
        "4",
        "04",
        "804",
        "1804",
        "81804",
        "081804",
        "7081804",
        "07081804",
        "907081804",
        "0907081804",
    ];
    for (digits, expected) in (1..=10).zip(expected) {
        let settings = settings(SEED_SHA1, Algorithm::Sha1, digits, 30);
        assert_eq!(code(&settings, 1111111109), expected, "{digits} digits");
    }
}

#[test]
fn the_code_changes_exactly_at_the_period_boundary() {
    let settings = settings(SEED_SHA1, Algorithm::Sha1, 8, 30);
    assert_eq!(code(&settings, 1111111109), code(&settings, 1111111080));
    assert_ne!(code(&settings, 1111111109), code(&settings, 1111111110));
    assert_eq!(seconds_remaining(&settings, 1111111109), 1);
    assert_eq!(seconds_remaining(&settings, 1111111110), 30);
    assert_eq!(seconds_remaining(&settings, 0), 30);
}

#[test]
fn parses_the_key_uri_format_example() {
    let parsed =
        parse_uri("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
            .unwrap();
    assert_eq!(parsed.issuer, "Example");
    assert_eq!(parsed.account, "alice@google.com");
    assert_eq!(
        parsed.settings,
        settings(EXAMPLE_SECRET, Algorithm::Sha1, 6, 30)
    );
}

#[test]
fn parses_labels_parameters_and_percent_escapes() {
    let parsed = parse_uri(
        "otpauth://totp/ACME%20Co:%20john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ\
         &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
    )
    .unwrap();
    assert_eq!(parsed.issuer, "ACME Co");
    assert_eq!(parsed.account, "john.doe@email.com");
    assert_eq!(parsed.settings.algorithm(), Algorithm::Sha256);
    assert_eq!(parsed.settings.digits(), 8);
    assert_eq!(parsed.settings.period(), 60);

    let parsed = parse_uri("otpauth://totp/Label%20Issuer:bob?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(parsed.issuer, "Label Issuer");

    let parsed = parse_uri("otpauth://totp/Escaped%3Abob?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(
        (parsed.issuer.as_str(), parsed.account.as_str()),
        ("Escaped", "bob")
    );

    let parsed = parse_uri("otpauth://totp/A%3AB:carol?secret=JBSWY3DPEHPK3PXP").unwrap();
    assert_eq!(
        (parsed.issuer.as_str(), parsed.account.as_str()),
        ("A:B", "carol")
    );

    let parsed = parse_uri("OTPAUTH://TOTP/bob?secret=jbswy3dpehpk3pxp&issuer=Param").unwrap();
    assert_eq!(
        (parsed.issuer.as_str(), parsed.account.as_str()),
        ("Param", "bob")
    );

    let parsed =
        parse_uri("otpauth://totp/Valve:gaben?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
    assert_eq!(parsed.settings.encoder(), Encoder::Steam);
    assert_eq!(
        parsed.settings.digits(),
        5,
        "Steam without digits uses five"
    );
}

#[test]
fn secrets_with_escapes_keepassxc_keeps_encoded_are_refused() {
    // KeePassXC's QUrlQuery leaves these escapes encoded and its Base32
    // reader keeps the hex digits as symbols; the code would differ.
    for secret in [
        "JBSWY3DPEHPK3PXP%FF",
        "JBSWY3DP%FFEHPK3PXP",
        "JBSWY3DPEHPK3PXP%",
        "JBSWY3DPEHPK3PXP%2B",
    ] {
        assert_eq!(
            parse_uri(&format!("otpauth://totp/a?secret={secret}")).map(|_| ()),
            Err(OtpError::InvalidSecret),
            "{secret}"
        );
        assert_eq!(
            from_attributes(&[("otp", &format!("key={secret}&size=6&step=30"))]).map(|_| ()),
            Err(OtpError::InvalidSecret),
            "KeeOtp {secret}"
        );
    }
    // The escapes KeePassXC writes itself still read.
    let padded = parse_uri("otpauth://totp/a?secret=MZXW6YQ%3D&issuer=x").unwrap();
    let spaced = parse_uri("otpauth://totp/a?secret=MZXW%206YQ=&issuer=x").unwrap();
    assert_eq!(code(&padded.settings, 59), code(&spaced.settings, 59));
    assert_eq!(
        code(&padded.settings, 59),
        code(&settings("MZXW6YQ=", Algorithm::Sha1, 6, 30), 59)
    );
}

#[test]
fn rejects_uris_that_are_not_totp() {
    let cases = [
        (
            "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=0",
            OtpError::Hotp,
        ),
        (
            "otpauth://yandex/alice?secret=JBSWY3DPEHPK3PXP",
            OtpError::UnsupportedType,
        ),
        (
            "otpauth-migration://offline?data=AAAA",
            OtpError::InvalidUri,
        ),
        (
            "https://example.com/?secret=JBSWY3DPEHPK3PXP",
            OtpError::InvalidUri,
        ),
        (
            "otpauth://totp/Example:alice?issuer=Example",
            OtpError::InvalidSecret,
        ),
        (
            "otpauth://totp/Example:alice?secret=A",
            OtpError::InvalidSecret,
        ),
        (
            "otpauth://totp/%FF?secret=JBSWY3DPEHPK3PXP",
            OtpError::InvalidUri,
        ),
    ];
    for (uri, error) in cases {
        assert_eq!(parse_uri(uri).map(|_| ()), Err(error), "{uri}");
    }
}

#[test]
fn bounds_uri_length_and_parameter_count() {
    let prefix = "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&x=";
    let longest = format!("{prefix}{}", "y".repeat(MAX_URI_LENGTH - prefix.len()));
    assert!(parse_uri(&longest).is_ok());
    let too_long = format!("{longest}y");
    assert_eq!(parse_uri(&too_long).map(|_| ()), Err(OtpError::TooLong));

    let many = format!(
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP{}",
        "&x=1".repeat(32)
    );
    assert_eq!(parse_uri(&many).map(|_| ()), Err(OtpError::TooLong));
}

#[test]
fn clamps_digits_and_period_like_keepassxc() {
    let read = |query: &str| {
        from_attributes(&[(
            "otp",
            &format!("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&{query}"),
        )])
        .unwrap()
        .unwrap()
    };
    assert_eq!(read("digits=0").digits(), 1);
    assert_eq!(read("digits=12").digits(), 10);
    assert_eq!(read("digits=x").digits(), 1);
    assert_eq!(read("period=0").period(), 1);
    assert_eq!(read("period=100000").period(), 86_400);
    assert_eq!(
        read("algorithm=hmac-sha-512").algorithm(),
        Algorithm::Sha512
    );
    assert_eq!(read("algorithm=MD5").algorithm(), Algorithm::Sha1);
    assert_eq!(
        read("encoder=Steam").encoder(),
        Encoder::Decimal,
        "encoder names are exact"
    );
}

#[test]
fn reads_every_form_keepassxc_reads_in_its_order() {
    let uri = "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=8";
    assert_eq!(
        from_attributes(&[("otp", uri)]).unwrap().unwrap().digits(),
        8
    );

    let keeotp = from_attributes(&[(
        "otp",
        "key=JBSWY3DPEHPK3PXP&size=7&step=45&otpHashMode=SHA256",
    )])
    .unwrap()
    .unwrap();
    assert_eq!(
        (keeotp.digits(), keeotp.period(), keeotp.algorithm()),
        (7, 45, Algorithm::Sha256)
    );

    let legacy = from_attributes(&[("TOTP Seed", EXAMPLE_SECRET), ("TOTP Settings", "60;8")])
        .unwrap()
        .unwrap();
    assert_eq!((legacy.period(), legacy.digits()), (60, 8));
    let legacy_steam = from_attributes(&[("TOTP Seed", EXAMPLE_SECRET), ("TOTP Settings", "60;S")])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            legacy_steam.encoder(),
            legacy_steam.digits(),
            legacy_steam.period()
        ),
        (Encoder::Steam, 5, 30)
    );
    let legacy_default = from_attributes(&[("TOTP Seed", EXAMPLE_SECRET), ("TOTP Settings", "")])
        .unwrap()
        .unwrap();
    assert_eq!((legacy_default.period(), legacy_default.digits()), (30, 6));

    let keepass2 = from_attributes(&[
        ("TimeOtp-Secret-Base32", EXAMPLE_SECRET),
        ("TimeOtp-Algorithm", "HMAC-SHA-256"),
        ("TimeOtp-Length", "8"),
        ("TimeOtp-Period", "60"),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(
        (keepass2.algorithm(), keepass2.digits(), keepass2.period()),
        (Algorithm::Sha256, 8, 60)
    );

    let precedence = from_attributes(&[
        ("TOTP Seed", EXAMPLE_SECRET),
        ("TOTP Settings", "30;7"),
        ("otp", uri),
        ("TimeOtp-Secret-Base32", EXAMPLE_SECRET),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(precedence.digits(), 7, "TOTP Settings comes first");
}

#[test]
fn reports_entries_without_or_with_broken_settings() {
    assert_eq!(from_attributes(&[("Password", "x")]), Ok(None));
    assert_eq!(from_attributes(&[("otp", "")]), Ok(None));
    assert_eq!(from_attributes(&[("TOTP Settings", "")]), Ok(None));
    assert_eq!(
        from_attributes(&[("otp", "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP")]),
        Err(OtpError::Hotp)
    );
    assert_eq!(
        from_attributes(&[("TOTP Settings", "30;6")]),
        Err(OtpError::InvalidSecret)
    );
    assert_eq!(
        from_attributes(&[
            ("TimeOtp-Secret-Base32", EXAMPLE_SECRET),
            ("TimeOtp-Length", "0")
        ]),
        Err(OtpError::InvalidSettings)
    );
    assert_eq!(
        from_attributes(&[("otp", &"x".repeat(MAX_URI_LENGTH + 1))]),
        Err(OtpError::TooLong)
    );
}

#[test]
fn writes_uris_in_keepassxcs_layout() {
    let plain = settings(EXAMPLE_SECRET, Algorithm::Sha1, 6, 30);
    assert_eq!(
        write_uri("Example", "alice@example.org", &plain).as_str(),
        "otpauth://totp/Example:alice%40example.org?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&issuer=Example"
    );

    let custom = TotpSettings::new("NBSWY3DP", Algorithm::Sha512, 8, 60, Encoder::Steam).unwrap();
    assert_eq!(
        write_uri("ACME Co", "", &custom).as_str(),
        "otpauth://totp/ACME%20Co:none?secret=NBSWY3DP&period=60&digits=8&issuer=ACME%20Co&encoder=steam&algorithm=SHA512"
    );

    let padded = settings("NBSWY3DPEE", Algorithm::Sha256, 6, 30);
    assert_eq!(
        write_uri("", "bob", &padded).as_str(),
        "otpauth://totp/SailToken:bob?secret=NBSWY3DPEE%3D%3D%3D%3D%3D%3D&period=30&digits=6&issuer=SailToken&algorithm=SHA256"
    );
}

#[test]
fn a_written_uri_reads_back_the_same() {
    let cases = [
        TotpSettings::new(EXAMPLE_SECRET, Algorithm::Sha1, 6, 30, Encoder::Decimal).unwrap(),
        TotpSettings::new(SEED_SHA256, Algorithm::Sha256, 8, 60, Encoder::Decimal).unwrap(),
        TotpSettings::new(SEED_SHA512, Algorithm::Sha512, 10, 86_400, Encoder::Decimal).unwrap(),
        TotpSettings::new("NBSWY3DPEE", Algorithm::Sha1, 5, 30, Encoder::Steam).unwrap(),
    ];
    for settings in cases {
        let uri = write_uri("Issuer: with colon", "user name", &settings);
        assert_eq!(
            from_attributes(&[("otp", &uri)]).unwrap().as_ref(),
            Some(&settings)
        );
        let parsed = parse_uri(&uri).unwrap();
        assert_eq!(parsed.settings, settings);
        assert_eq!(parsed.issuer, "Issuer: with colon");
        assert_eq!(parsed.account, "user name");
    }
}

#[test]
fn new_settings_are_checked_strictly() {
    let new = |digits, period| {
        TotpSettings::new(
            EXAMPLE_SECRET,
            Algorithm::Sha1,
            digits,
            period,
            Encoder::Decimal,
        )
    };
    assert!(new(1, 1).is_ok());
    assert!(new(10, 86_400).is_ok());
    assert_eq!(new(0, 30), Err(OtpError::InvalidSettings));
    assert_eq!(new(11, 30), Err(OtpError::InvalidSettings));
    assert_eq!(new(6, 0), Err(OtpError::InvalidSettings));
    assert_eq!(new(6, 86_401), Err(OtpError::InvalidSettings));
}

#[test]
fn debug_output_leaves_out_the_secret() {
    let settings = settings(EXAMPLE_SECRET, Algorithm::Sha1, 6, 30);
    let text = format!("{settings:?}");
    assert!(!text.contains("JBSW") && !text.contains("secret"), "{text}");
}
