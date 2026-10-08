import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0
import "../components"

Page {
    id: page

    readonly property bool isUnlockPage: true
    readonly property bool unlocking: authenticator.state === Authenticator.Unlocking
    property bool creating
    readonly property bool passwordError: authenticator.error === Authenticator.WrongPassword
    readonly property bool fileError: authenticator.error !== Authenticator.NoError && !passwordError

    function errorText(error) {
        switch (error) {
        case Authenticator.WrongPassword: return qsTr("Wrong password")
        case Authenticator.NotKdbx: return qsTr("The file is not a KeePass-compatible file")
        case Authenticator.UnsupportedFormat: return qsTr("The file uses an unsupported format")
        case Authenticator.Corrupted: return qsTr("The file is damaged")
        case Authenticator.TooLarge: return qsTr("The file or its settings exceed the supported limits")
        case Authenticator.FileUnreadable: return qsTr("The file cannot be read")
        case Authenticator.FileUnwritable: return qsTr("The file cannot be written")
        case Authenticator.FileExists: return qsTr("The file already exists")
        case Authenticator.ChangesDiscarded: return qsTr("Changes that could not be saved were discarded when the file locked")
        default: return ""
        }
    }

    function createFile() {
        var dialog = pageStack.push(Qt.resolvedUrl("NewFileDialog.qml"))
        dialog.accepted.connect(function() {
            page.creating = true
            authenticator.createFile(dialog.password, dialog.kdfLevel)
        })
    }

    function unlock() {
        if (unlocking)
            return
        authenticator.unlock(passwordField.text)
        passwordField.text = ""
    }

    allowedOrientations: Orientation.All

    // Swiping back from the account list leaves the file, so it locks
    // instead of staying open behind a page that looks locked.
    onStatusChanged: {
        if (status === PageStatus.Active && authenticator.state === Authenticator.Unlocked)
            authenticator.lock()
    }

    Connections {
        target: authenticator
        onStateChanged: {
            if (authenticator.state !== Authenticator.Unlocking)
                page.creating = false
            if (authenticator.state === Authenticator.Unlocked)
                pageStack.push(Qt.resolvedUrl("AccountListPage.qml"))
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            visible: !page.unlocking

            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
        }

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium
            enabled: !page.unlocking

            PageHeader {
                title: "SailFactor"
                description: window.lockedAutomatically ? qsTr("Locked automatically") : ""
            }

            Paragraph {
                visible: page.fileError
                color: Theme.errorColor
                text: page.errorText(authenticator.error)
            }

            PasswordInput {
                id: passwordField

                visible: authenticator.hasFile
                label: qsTr("Master password")
                errorText: page.passwordError ? page.errorText(authenticator.error) : ""
                EnterKey.onClicked: page.unlock()
                onTextChanged: {
                    if (text.length > 0)
                        authenticator.clearError()
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: authenticator.hasFile
                text: qsTr("Unlock")
                onClicked: page.unlock()
            }

            Paragraph {
                visible: !authenticator.hasFile
                color: Theme.highlightColor
                text: qsTr("SailFactor keeps the codes for two-factor login in an encrypted file of their own, apart from your password manager.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !authenticator.hasFile
                text: qsTr("Create file")
                onClicked: page.createFile()
            }
        }
    }

    BusyLabel {
        running: page.unlocking
        text: page.creating ? qsTr("Creating file") : qsTr("Unlocking")
    }
}
