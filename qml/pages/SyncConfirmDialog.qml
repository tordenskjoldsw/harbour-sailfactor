import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Asks before syncing to a configuration that was not set up on this phone,
// such as one in a file added from another device. Nothing is
// sent anywhere until the user accepts.
Dialog {
    allowedOrientations: Orientation.All

    onAccepted: sync.confirmConfiguration()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: qsTr("Sync with this server?")
                acceptText: qsTr("Sync")
            }

            Paragraph {
                text: qsTr("This file holds sync settings that were not set up on this phone, for example from a copy on another device. SailFactor would upload the encrypted file to this server. Only accept if it is your Nextcloud.")
            }

            DetailItem {
                label: qsTr("Server")
                value: sync.storedServer()
            }

            DetailItem {
                label: qsTr("Login name")
                value: sync.storedLoginName()
            }

            DetailItem {
                label: qsTr("File")
                value: sync.storedPath()
            }

            Paragraph {
                visible: text.length > 0
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                wrapMode: Text.WrapAnywhere
                text: sync.storedCertificate().length > 0
                      ? qsTr("Accepts the self-signed certificate %1").arg(sync.storedCertificate())
                      : ""
            }
        }
    }
}
