TARGET = harbour-sailtoken

CONFIG += sailfishapp
QT += multimedia network

HEADERS += \
    src/accountlistmodel.h \
    src/authenticator.h \
    src/autolock.h \
    src/boottime.h \
    src/clipboardguard.h \
    src/corebridge.h \
    src/coretasks.h \
    src/databasefile.h \
    src/databases.h \
    src/framescanner.h \
    src/nextcloud.h \
    src/sync.h

SOURCES += \
    src/accountlistmodel.cpp \
    src/authenticator.cpp \
    src/autolock.cpp \
    src/clipboardguard.cpp \
    src/coretasks.cpp \
    src/databasefile.cpp \
    src/databases.cpp \
    src/framescanner.cpp \
    src/main.cpp \
    src/nextcloud.cpp \
    src/sync.cpp

INCLUDEPATH += core/include

# The spec passes the package version; the About page shows it. Builds
# without one, such as from Qt Creator, show a development version.
APP_VERSION = $$VERSION
isEmpty(APP_VERSION): APP_VERSION = 0.0.0+dev
DEFINES += APP_VERSION=\\\"$$APP_VERSION\\\"

# Build the Rust core with cargo before linking. CARGO_HOME is isolated so the
# build engine, which shares the host home directory, never reads the host's
# cargo configuration or registry. Cargo runs from the source root so it finds
# .cargo/config.toml with the vendored sources, also in shadow builds.
#
# Inside the build engine, cargo targets the engine's own architecture unless
# the triple is given explicitly.
equals(QT_ARCH, arm64): RUST_TRIPLE = aarch64-unknown-linux-gnu
else:equals(QT_ARCH, arm): RUST_TRIPLE = armv7-unknown-linux-gnueabihf
else:equals(QT_ARCH, i386): RUST_TRIPLE = i686-unknown-linux-gnu
else: error("Unsupported QT_ARCH for the Rust core: $$QT_ARCH")

RUST_TARGET_DIR = $$OUT_PWD/rust-target
RUST_STATICLIB = $$RUST_TARGET_DIR/$$RUST_TRIPLE/release/libsailtoken_core.a

# The binary would otherwise carry the build machine's absolute source
# paths in Rust's panic locations. RUSTFLAGS replaces the rustflags of
# .cargo/config.toml, so the aarch64 flag that enables the ARMv8 AES
# instructions is repeated here.
RUST_FLAGS = --remap-path-prefix=$$PWD=.
equals(QT_ARCH, arm64): RUST_FLAGS += --cfg aes_armv8

rust_core.target = $$RUST_STATICLIB
rust_core.commands = cd $$PWD && CARGO_HOME=$$OUT_PWD/cargo-home RUSTFLAGS=\"$$RUST_FLAGS\" \
    cargo build --release --offline --locked \
    --target $$RUST_TRIPLE \
    --manifest-path $$PWD/core/Cargo.toml --target-dir $$RUST_TARGET_DIR
rust_core.depends = FORCE
QMAKE_EXTRA_TARGETS += rust_core
PRE_TARGETDEPS += $$RUST_STATICLIB

LIBS += $$RUST_STATICLIB -lpthread -ldl -lm

# Full RELRO (read-only GOT after startup) and no symbol table in the
# shipped binary.
QMAKE_LFLAGS += -Wl,-z,relro,-z,now -s

DISTFILES += \
    qml/harbour-sailtoken.qml \
    qml/components/Paragraph.qml \
    qml/components/PasswordInput.qml \
    qml/components/ProtectionComboBox.qml \
    qml/components/QrCamera.qml \
    qml/components/SyncText.qml \
    qml/components/TwoLineLabel.qml \
    qml/cover/CoverPage.qml \
    qml/pages/AboutPage.qml \
    qml/pages/AccountDialog.qml \
    qml/pages/AccountListPage.qml \
    qml/pages/AddedPage.qml \
    qml/pages/CertificateDialog.qml \
    qml/pages/DeleteFileDialog.qml \
    qml/pages/HelpPage.qml \
    qml/pages/ImportDialog.qml \
    qml/pages/ImportFilePage.qml \
    qml/pages/ImportPage.qml \
    qml/pages/MergePage.qml \
    qml/pages/MovePage.qml \
    qml/pages/NewFileDialog.qml \
    qml/pages/RenameDialog.qml \
    qml/pages/SaveCopyDialog.qml \
    qml/pages/ScanPage.qml \
    qml/pages/SettingsPage.qml \
    qml/pages/SyncConfirmDialog.qml \
    qml/pages/SyncSetupPage.qml \
    qml/pages/ThirdPartyPage.qml \
    qml/pages/thirdparty.js \
    qml/pages/UnlockPage.qml \
    rpm/harbour-sailtoken.spec \
    harbour-sailtoken.desktop

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172
