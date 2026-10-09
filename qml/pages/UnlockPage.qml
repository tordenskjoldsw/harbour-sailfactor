import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailtoken 1.0
import "../components"

Page {
    id: page

    readonly property bool isUnlockPage: true
    readonly property bool unlocking: authenticator.state === Authenticator.Unlocking
    property bool creating
    // A file from outside the app is unlocked and stored; only while the
    // app has no file.
    readonly property bool adding: !authenticator.hasFile && authenticator.sourcePath.length > 0
    readonly property bool showsPassword: authenticator.hasFile || adding
    readonly property bool withKeyFile: adding ? authenticator.sourceKeyFilePath.length > 0
                                               : authenticator.hasKeyFile
    // An added file needs a password: its key file is stored next to it, so
    // the password is all that protects it.
    readonly property bool canUnlock: adding ? passwordField.text.length > 0 : authenticator.hasFile
    readonly property bool passwordError: authenticator.error === Authenticator.WrongPassword
    readonly property bool keyFileError: adding && authenticator.error === Authenticator.InvalidKeyFile
    readonly property bool fileError: authenticator.error !== Authenticator.NoError && !passwordError
                                      && !keyFileError

    function fileName(path) {
        return path.substring(path.lastIndexOf("/") + 1)
    }

    function cancelAdding() {
        authenticator.sourcePath = ""
        authenticator.sourceKeyFilePath = ""
    }

    function errorText(error) {
        switch (error) {
        case Authenticator.WrongPassword:
            return withKeyFile ? qsTr("Wrong password or key file") : qsTr("Wrong password")
        case Authenticator.InvalidKeyFile: return qsTr("The key file is not valid")
        case Authenticator.NotKdbx: return qsTr("The file is not a KeePass-compatible file")
        case Authenticator.UnsupportedFormat: return qsTr("The file uses an unsupported format")
        case Authenticator.Corrupted: return qsTr("The file is damaged")
        case Authenticator.TooLarge: return qsTr("The file or its settings exceed the supported limits")
        case Authenticator.FileUnreadable: return qsTr("The file cannot be read")
        case Authenticator.FileUnwritable: return qsTr("The file cannot be written")
        case Authenticator.FileExists: return qsTr("SailToken already has a file")
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
        if (!canUnlock || unlocking)
            return
        if (adding)
            authenticator.addFile(passwordField.text, kdfBox.kdfLevel)
        else
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
            if (authenticator.state === Authenticator.Unlocked) {
                if (authenticator.addedOriginals.length > 0)
                    pageStack.push(Qt.resolvedUrl("AddedPage.qml"))
                else
                    pageStack.push(Qt.resolvedUrl("AccountListPage.qml"))
            }
        }
    }

    Component {
        id: sourcePicker

        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: authenticator.sourcePath = selectedContentProperties.filePath
        }
    }

    Component {
        id: keyFilePicker

        FilePickerPage {
            onSelectedContentPropertiesChanged: authenticator.sourceKeyFilePath = selectedContentProperties.filePath
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        // Creating or adding a file is offered by the buttons below while the
        // app has none.
        PullDownMenu {
            visible: !page.unlocking

            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                visible: page.adding && authenticator.sourceKeyFilePath.length > 0
                text: qsTr("Remove key file")
                onClicked: authenticator.sourceKeyFilePath = ""
            }
            MenuItem {
                visible: page.adding
                text: qsTr("Cancel adding")
                onClicked: page.cancelAdding()
            }
        }

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium
            enabled: !page.unlocking

            PageHeader {
                title: "SailToken"
                description: window.lockedAutomatically ? qsTr("Locked automatically") : ""
            }

            Paragraph {
                visible: page.fileError
                color: Theme.errorColor
                text: page.errorText(authenticator.error)
            }

            Paragraph {
                visible: authenticator.hasFile && page.withKeyFile
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Opens with its stored key file")
            }

            ValueButton {
                visible: page.adding
                label: qsTr("File")
                value: page.fileName(authenticator.sourcePath)
                description: qsTr("SailToken keeps its own copy, which other apps cannot read")
                onClicked: pageStack.push(sourcePicker)
            }

            Paragraph {
                visible: page.adding && authenticator.sourceFromKdbx3
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("This file uses the older KDBX 3.1 format. SailToken stores it as KDBX 4 with the stronger Argon2id key derivation; KeePassXC opens it as before. The original file stays unchanged.")
            }

            ProtectionComboBox {
                id: kdfBox

                visible: page.adding && authenticator.sourceFromKdbx3
            }

            ValueButton {
                visible: page.adding
                label: qsTr("Key file")
                value: authenticator.sourceKeyFilePath.length > 0
                       ? page.fileName(authenticator.sourceKeyFilePath) : qsTr("None")
                descriptionColor: Theme.errorColor
                description: page.keyFileError ? page.errorText(authenticator.error) : ""
                onClicked: pageStack.push(keyFilePicker)
            }

            PasswordInput {
                id: passwordField

                visible: page.showsPassword
                label: qsTr("Master password")
                errorText: page.passwordError ? page.errorText(authenticator.error) : ""
                EnterKey.enabled: page.canUnlock
                EnterKey.onClicked: page.unlock()
                onTextChanged: {
                    if (text.length > 0)
                        authenticator.clearError()
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.showsPassword
                text: page.adding ? qsTr("Add and unlock") : qsTr("Unlock")
                enabled: page.canUnlock
                onClicked: page.unlock()
            }

            Paragraph {
                visible: page.adding
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Add the file with your two-factor accounts, not your password database: the separation only helps when the second factor lives in a file of its own, with a different master password. SailToken adds only files that need a password, because a key file is kept next to the file.")
            }

            Paragraph {
                visible: !page.showsPassword
                color: Theme.highlightColor
                text: qsTr("SailToken keeps the codes for two-factor login in an encrypted file of their own, apart from your password manager.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.showsPassword
                text: qsTr("Create file")
                onClicked: page.createFile()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.showsPassword
                text: qsTr("Add existing file")
                onClicked: pageStack.push(sourcePicker)
            }
        }
    }

    BusyLabel {
        running: page.unlocking
        text: page.creating ? qsTr("Creating file")
                            : page.adding ? qsTr("Adding file") : qsTr("Unlocking")
    }
}
