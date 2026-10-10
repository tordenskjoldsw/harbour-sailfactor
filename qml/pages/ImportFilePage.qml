import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// Reads an Aegis vault the user picked. A plain vault opens at once; an
// encrypted one asks for its password, and its key derivation runs off
// the UI thread. Then the dialog lists the accounts to add.
Page {
    id: page

    property string path
    property int result: -1
    property bool started

    function read(password) {
        // The password field stays while the key derivation runs.
        result = asksPassword ? Authenticator.ImportFileNeedsPassword : -1
        authenticator.importFile(path, password)
    }

    function resultText() {
        switch (result) {
        case Authenticator.ImportFileWrongPassword:
            return qsTr("Wrong password")
        case Authenticator.ImportFileNotExport:
            return qsTr("This file is no Aegis vault")
        case Authenticator.ImportFileUnsupported:
            return qsTr("SailToken cannot read this vault. Export it again from a current Aegis.")
        case Authenticator.ImportFileTooLarge:
            return qsTr("This vault is beyond SailToken's limits")
        case Authenticator.ImportFileUnreadable:
            return qsTr("The file could not be read")
        default:
            return ""
        }
    }

    readonly property bool asksPassword: result === Authenticator.ImportFileNeedsPassword
                                         || result === Authenticator.ImportFileWrongPassword

    allowedOrientations: Orientation.All

    // Reads once the page is in place, so the result never meets a page
    // transition.
    onStatusChanged: {
        if (status === PageStatus.Active && !started) {
            started = true
            read("")
        }
    }

    Connections {
        target: authenticator
        onImportFileFinished: {
            // A result for a page the user has left is not wanted.
            if (page.status !== PageStatus.Active) {
                authenticator.clearImport()
                return
            }
            page.result = result
            if (result === Authenticator.ImportFileReady)
                pageStack.replace(Qt.resolvedUrl("ImportDialog.qml"))
            else if (page.asksPassword)
                password.forceActiveFocus()
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Aegis backup")
            }

            Paragraph {
                visible: page.asksPassword
                color: Theme.highlightColor
                text: qsTr("This vault is encrypted. Enter the password you set in Aegis.")
            }

            PasswordInput {
                id: password

                visible: page.asksPassword
                enabled: !authenticator.importingFile
                label: qsTr("Vault password")
                errorText: page.result === Authenticator.ImportFileWrongPassword ? page.resultText() : ""
                EnterKey.enabled: text.length > 0
                EnterKey.onClicked: page.read(text)
            }

            Button {
                visible: page.asksPassword
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: password.text.length > 0 && !authenticator.importingFile
                text: qsTr("Open")
                onClicked: page.read(password.text)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Large
                running: authenticator.importingFile
                visible: running
            }

            Paragraph {
                visible: !page.asksPassword && page.resultText().length > 0
                color: Theme.errorColor
                text: page.resultText()
            }
        }

        VerticalScrollDecorator {}
    }
}
