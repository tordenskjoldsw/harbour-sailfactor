import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailfactor 1.0
import "../components"

// Merges the copy of the file at path, such as the one from the computer,
// into the open file and offers to delete the copy once the result is
// saved. Copied from SailVault.
Page {
    id: page

    property string path
    readonly property bool merging: authenticator.merging
    property bool needsPassword
    property bool triedPassword
    // A KDBX file does not say whether a key file opens it, so the choice
    // is offered: the stored one of this file by default, if it has one.
    property bool useStoredKeyFile: authenticator.hasKeyFile
    property string keyFilePath
    readonly property bool hasKeyFile: useStoredKeyFile || keyFilePath.length > 0
    property bool finished
    property string resultText
    property string errorText

    function fileName(path) {
        return path.substring(path.lastIndexOf("/") + 1)
    }

    function failureText(error) {
        switch (error) {
        case Authenticator.NotKdbx: return qsTr("This file is not a KeePass-compatible file")
        case Authenticator.UnsupportedFormat: return qsTr("This file uses an unsupported format")
        case Authenticator.InvalidKeyFile: return qsTr("The stored key file does not open this file")
        case Authenticator.TooLarge: return qsTr("The file or its settings exceed the supported limits")
        case Authenticator.FileUnreadable: return qsTr("The file cannot be read")
        default: return qsTr("The file is damaged")
        }
    }

    function summary(added, modified, moved, deleted) {
        if (added + modified + moved + deleted === 0)
            return qsTr("SailFactor already has every change from this file.")
        // No translations exist yet, so counts go after a label instead of
        // into %n plurals.
        var lines = []
        if (added > 0)
            lines.push(qsTr("Added: %1").arg(added))
        if (modified > 0)
            lines.push(qsTr("Changed: %1").arg(modified))
        if (moved > 0)
            lines.push(qsTr("Moved: %1").arg(moved))
        if (deleted > 0)
            lines.push(qsTr("Deleted: %1").arg(deleted))
        return lines.join("\n")
    }

    function mergeWithPassword() {
        if ((passwordField.text.length > 0 || hasKeyFile) && !merging) {
            needsPassword = false
            triedPassword = true
            authenticator.mergeFileWith(path, passwordField.text, keyFilePath, useStoredKeyFile)
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All
    backNavigation: !merging

    Component.onCompleted: authenticator.mergeFile(path)

    RemorsePopup {
        id: remorse
    }

    Component {
        id: keyFilePicker

        FilePickerPage {
            onSelectedContentPropertiesChanged: {
                page.keyFilePath = selectedContentProperties.filePath
                page.useStoredKeyFile = false
            }
        }
    }

    Connections {
        target: authenticator
        onMergeNeedsPassword: page.needsPassword = true
        onMergeFinished: {
            page.finished = true
            page.resultText = page.summary(added, modified, moved, deleted)
        }
        onMergeFailed: page.errorText = page.failureText(error)
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            visible: page.needsPassword && page.hasKeyFile

            MenuItem {
                text: qsTr("Remove key file")
                onClicked: {
                    page.keyFilePath = ""
                    page.useStoredKeyFile = false
                }
            }
        }

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Merge with file")
                description: page.fileName(page.path)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: page.merging || authenticator.saving
                visible: running
            }

            Paragraph {
                visible: page.needsPassword
                text: qsTr("This file does not open with the master password of SailFactor's file. Enter the master password of this file and choose its key file if it uses one.")
            }

            PasswordInput {
                id: passwordField

                visible: page.needsPassword
                label: qsTr("Master password of the file")
                errorText: page.triedPassword ? qsTr("Wrong password or key file") : ""
                focus: visible
                EnterKey.enabled: text.length > 0 || page.hasKeyFile
                EnterKey.onClicked: page.mergeWithPassword()
            }

            ValueButton {
                visible: page.needsPassword
                label: qsTr("Key file")
                value: page.keyFilePath.length > 0 ? page.fileName(page.keyFilePath)
                     : page.useStoredKeyFile ? qsTr("Stored key file") : qsTr("None")
                onClicked: pageStack.push(keyFilePicker)
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.needsPassword
                enabled: passwordField.text.length > 0 || page.hasKeyFile
                text: qsTr("Merge")
                onClicked: page.mergeWithPassword()
            }

            Paragraph {
                visible: page.errorText.length > 0
                color: Theme.errorColor
                text: page.errorText
            }

            Paragraph {
                visible: page.finished
                text: page.resultText
            }

            Paragraph {
                visible: page.finished && !authenticator.saving && !authenticator.dirty
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("The file stays where it is, and other apps can read it. Delete it once you no longer need it.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.finished
                enabled: !authenticator.saving && !authenticator.dirty
                text: qsTr("Delete file")
                onClicked: remorse.execute(qsTr("Deleting the file"), function() {
                    Notices.show(authenticator.removeMergedFile() ? qsTr("File deleted")
                                                          : qsTr("The file could not be deleted"),
                                 Notice.Short)
                    pageStack.pop()
                })
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.finished || page.errorText.length > 0
                enabled: !page.merging
                text: page.finished ? qsTr("Keep file") : qsTr("Back")
                onClicked: pageStack.pop()
            }
        }
    }
}
