import QtQuick 2.0
import Sailfish.Silica 1.0
import "pages"

ApplicationWindow {
    id: window

    // Silica labels default to Text.AutoText, so markup in an issuer, an
    // account name or a file name would render inside headers, buttons and
    // notices. The property is Silica-internal; setting it only when it
    // exists keeps the app loading if a later Silica drops it. App labels
    // set PlainText themselves.
    Component.onCompleted: {
        if (window.hasOwnProperty("_defaultLabelFormat"))
            window._defaultLabelFormat = Text.PlainText
    }

    initialPage: Component { MainPage { } }
    cover: Qt.resolvedUrl("cover/CoverPage.qml")
    allowedOrientations: defaultAllowedOrientations
}
