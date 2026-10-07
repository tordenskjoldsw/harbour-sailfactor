# SailFactor

A TOTP authenticator for Sailfish OS that keeps the second factor apart
from the password manager. The accounts live in an encrypted file of their
own, with its own master password, in the standard KeePass (KDBX 4) format:
KeePassXC on a computer opens the same file and shows the same codes.

What the separation gives: if the password manager's file or its master
password leaks, the second factor is still safe. What it does not give:
protection against a compromised phone, which holds both apps.

**Status:** in development, not usable yet. The app skeleton builds and
passes the Harbour validator; scanning QR codes, generating codes and
storing accounts come next. The full plan is in [PLAN.md](PLAN.md).

## Building

You need the [Sailfish SDK](https://docs.sailfishos.org/Tools/Sailfish_SDK/)
(tested with 3.13) and its aarch64 build target. Rust dependencies are
vendored in `core/vendor`, so the build works offline.

```sh
sfdk config --global --push target SailfishOS-5.1.0.11-aarch64
sfdk build
```

The RPM lands in `RPMS/`. To run the Harbour validator on it:

```sh
sfdk -c no-fix-version build
sfdk check RPMS/harbour-sailfactor-*.rpm
```

The core tests run on the host and need Rust 1.75 or newer:

```sh
cargo test --manifest-path core/Cargo.toml
```

## Contributing

Bug reports and ideas are welcome as
[issues](https://github.com/tordenskjoldsw/harbour-sailfactor/issues). If
you plan a pull request, open an issue first so we can agree on the
approach. Never attach a real secret, a real QR code or a real database,
not even an encrypted one.

## License

[MIT](LICENSE). The licenses of the bundled Rust crates are listed on the
About page in the app.

SailFactor is an independent project and not affiliated with KeePass,
KeePassXC or Jolla.
