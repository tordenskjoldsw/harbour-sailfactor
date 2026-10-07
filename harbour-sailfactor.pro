TARGET = harbour-sailfactor

CONFIG += sailfishapp
QT += multimedia

HEADERS += \
    src/boottime.h \
    src/framescanner.h

SOURCES += \
    src/framescanner.cpp \
    src/main.cpp

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
RUST_STATICLIB = $$RUST_TARGET_DIR/$$RUST_TRIPLE/release/libsailfactor_core.a

rust_core.target = $$RUST_STATICLIB
rust_core.commands = cd $$PWD && CARGO_HOME=$$OUT_PWD/cargo-home cargo build --release --offline --locked \
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
    qml/harbour-sailfactor.qml \
    qml/components/Paragraph.qml \
    qml/cover/CoverPage.qml \
    qml/pages/AboutPage.qml \
    qml/pages/MainPage.qml \
    qml/pages/ScanPage.qml \
    qml/pages/ThirdPartyPage.qml \
    qml/pages/thirdparty.js \
    rpm/harbour-sailfactor.spec \
    harbour-sailfactor.desktop

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172
