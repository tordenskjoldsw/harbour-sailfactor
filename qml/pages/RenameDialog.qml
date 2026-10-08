import QtQuick 2.0
import Sailfish.Silica 1.0

// Renames an account. The previous names stay in the entry's history, as in
// KeePassXC.
Dialog {
    id: dialog

    property string accountId
    property string issuer
    property string name

    canAccept: issuerField.text.trim().length > 0 && !authenticator.saving
    allowedOrientations: Orientation.All

    onAccepted: {
        if (!authenticator.rename(accountId, issuerField.text.trim(), nameField.text.trim()))
            Notices.show(qsTr("The account could not be renamed"), Notice.Long)
    }

    Column {
        width: parent.width

        DialogHeader {
            title: qsTr("Rename")
            acceptText: qsTr("Save")
        }

        TextField {
            id: issuerField

            width: parent.width
            label: qsTr("Issuer")
            placeholderText: label
            text: dialog.issuer
            EnterKey.iconSource: "image://theme/icon-m-enter-next"
            EnterKey.onClicked: nameField.focus = true
        }

        TextField {
            id: nameField

            width: parent.width
            label: qsTr("Account")
            placeholderText: label
            text: dialog.name
            inputMethodHints: Qt.ImhNoAutoUppercase
            EnterKey.enabled: dialog.canAccept
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: dialog.accept()
        }
    }
}
