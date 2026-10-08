import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Asks for the master password of the new file. The caller creates it from
// these properties when accepted.
Dialog {
    id: dialog

    // NIST SP 800-63B rev. 4 asks for 15 characters when a password is the
    // only factor, as the master password is here.
    readonly property int minimumPasswordLength: 15
    property alias password: passwordField.text
    readonly property int kdfLevel: kdfBox.kdfLevel

    canAccept: passwordField.text.length >= minimumPasswordLength
               && repeatField.text === passwordField.text
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                title: qsTr("New file")
                acceptText: qsTr("Create")
            }

            ProtectionComboBox {
                id: kdfBox
            }

            PasswordInput {
                id: passwordField

                label: qsTr("Master password")
                errorText: text.length > 0 && text.length < dialog.minimumPasswordLength
                           ? qsTr("At least %1 characters").arg(dialog.minimumPasswordLength) : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: repeatField.focus = true
            }

            PasswordInput {
                id: repeatField

                label: qsTr("Repeat master password")
                errorText: text.length > 0 && text !== passwordField.text
                           ? qsTr("The passwords differ") : ""
                EnterKey.enabled: dialog.canAccept
                EnterKey.onClicked: dialog.accept()
            }

            Column {
                width: parent.width
                spacing: Theme.paddingMedium

                Repeater {
                    model: [
                        qsTr("Use a long passphrase of several words, and a different one than for your password manager: the separation only helps when the two passwords differ."),
                        qsTr("Nobody can open the file without the password, and it cannot be recovered. Keep it somewhere outside this phone, so you can restore your accounts if the phone is lost.")
                    ]

                    Paragraph {
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.secondaryHighlightColor
                        text: modelData
                    }
                }
            }
        }
    }
}
