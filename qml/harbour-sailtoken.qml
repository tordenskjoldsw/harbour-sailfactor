import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "pages"

ApplicationWindow {
    id: window

    // A notice would expire while the app is in the background, so the
    // unlock page shows the reason until the next unlock.
    property bool lockedAutomatically: false

    // Silica labels default to Text.AutoText, so markup in an issuer, an
    // account name or a file name would render inside headers, buttons and
    // notices. The property is Silica-internal; setting it only when it
    // exists keeps the app loading if a later Silica drops it. App labels
    // set PlainText themselves.
    Component.onCompleted: {
        if (window.hasOwnProperty("_defaultLabelFormat"))
            window._defaultLabelFormat = Text.PlainText
    }

    initialPage: Component { UnlockPage { } }
    cover: Qt.resolvedUrl("cover/CoverPage.qml")
    allowedOrientations: defaultAllowedOrientations

    Connections {
        target: authenticator
        onStateChanged: {
            if (authenticator.state === Authenticator.Unlocked)
                window.lockedAutomatically = false
            if (authenticator.state === Authenticator.Locked && pageStack.depth > 1) {
                pageStack.pop(pageStack.find(function(page) { return page.isUnlockPage === true }),
                              PageStackAction.Immediate)
            }
        }
        onLockedAutomatically: window.lockedAutomatically = true
        onSaveFailed: {
            Notices.show(authenticator.error === Authenticator.FileUnwritable
                         ? qsTr("The file could not be written")
                         : qsTr("The accounts could not be saved"), Notice.Long)
        }
        onSavedOverChangedFile: {
            Notices.show(qsTr("Another program had changed the file. Its version is kept in the backups."),
                         Notice.Long)
        }
    }
}
