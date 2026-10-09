import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Confirms deleting the app's file. Every account in it is gone afterwards,
// and a lost seed means a recovery through each service, so the dialog
// says so and points to the copy.
Dialog {
    id: dialog

    canAccept: confirmSwitch.checked && !authenticator.saving
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                title: qsTr("Delete the file")
                acceptText: qsTr("Delete")
            }

            Paragraph {
                color: Theme.highlightColor
                text: qsTr("SailToken deletes its file with every account, its key file and its backups, and locks. Without another copy, each service has to be set up again through its account recovery.")
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Save a copy for the computer first if you still need the accounts. A copy saved earlier, and KeePassXC on a computer, keep working.")
            }

            TextSwitch {
                id: confirmSwitch

                text: qsTr("Delete all accounts on this phone")
            }
        }
    }
}
