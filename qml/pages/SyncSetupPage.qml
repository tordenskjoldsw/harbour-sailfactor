import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// Sets up sync of the file with a copy on Nextcloud: through the Nextcloud
// login in the browser, or with an app password created by hand. Copied
// from SailVault; the page warns that the Nextcloud login must not depend
// on a code from this file.
Page {
    id: page

    readonly property bool working: sync.setupState === Sync.WaitingForBrowser
                                    || sync.setupState === Sync.Checking
    readonly property bool ready: serverField.text.trim().length > 0
                                  && pathField.text.trim().length > 0 && !working
    // Set up before: the fields show the stored settings.
    readonly property bool configured: sync.configured
    readonly property bool sameServer: configured
                                       && serverField.text.trim() === sync.storedServer()

    function useAppPassword() {
        if (!manualButton.enabled)
            return
        sync.setUpManually(serverField.text, pathField.text, loginField.text,
                           appPasswordField.text)
        appPasswordField.text = ""
    }

    allowedOrientations: Orientation.All
    backNavigation: !working

    Component.onCompleted: {
        sync.cancelSetup()
        if (configured) {
            serverField.text = sync.storedServer()
            pathField.text = sync.storedPath()
            loginField.text = sync.storedLoginName()
        }
    }

    SyncText {
        id: syncText
    }

    Connections {
        target: sync
        onSetupChanged: {
            if (sync.setupState === Sync.SetupDone) {
                Notices.show(qsTr("Sync set up"), Notice.Short)
                pageStack.pop()
            } else if (sync.setupState === Sync.SetupFailed
                       && sync.setupProblem === Sync.CertificateUnknown) {
                pageStack.push(Qt.resolvedUrl("CertificateDialog.qml"))
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: qsTr("Sync with Nextcloud")
            }

            Paragraph {
                visible: page.configured
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Sync is set up. Change the file and save, or log in again for another server or account.")
            }

            Paragraph {
                visible: !page.configured
                color: Theme.highlightColor
                text: qsTr("Your Nextcloud login must not need a code from this file. If the phone is lost, the copy on Nextcloud and KeePassXC on a computer are how you get your codes back, and that only works if you can still log in to Nextcloud without them.")
            }

            TextField {
                id: serverField

                width: parent.width
                enabled: !page.working
                label: qsTr("Nextcloud address")
                placeholderText: "https://cloud.example.org"
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase
                                  | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: pathField.focus = true
            }

            TextField {
                id: pathField

                width: parent.width
                enabled: !page.working
                label: qsTr("File on Nextcloud")
                placeholderText: label
                text: page.configured ? "" : sync.defaultPath()
                description: qsTr("Missing folders and the file are created.")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            Paragraph {
                visible: sync.setupState === Sync.SetupFailed
                color: Theme.errorColor
                text: syncText.problem(sync.setupProblem)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: page.working
                visible: running
            }

            Paragraph {
                visible: sync.setupState === Sync.WaitingForBrowser
                text: qsTr("Log in to Nextcloud in the browser and grant access. Then come back here; SailFactor waits for 20 minutes. If Nextcloud says that the state token does not match, close its older tabs in the browser, cancel here and log in again.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.working
                text: qsTr("Cancel")
                onClicked: sync.cancelSetup()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.sameServer && !page.working
                enabled: page.ready && pathField.text.trim() !== sync.storedPath()
                text: qsTr("Save")
                onClicked: sync.changePath(pathField.text)
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.working
                enabled: page.ready
                text: page.configured ? qsTr("Log in again with the browser")
                                      : qsTr("Log in with the browser")
                onClicked: sync.startLogin(serverField.text, pathField.text)
            }

            SectionHeader {
                visible: !page.working
                text: qsTr("Or with an app password")
            }

            TextField {
                id: loginField

                visible: !page.working
                width: parent.width
                label: qsTr("Login name")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: appPasswordField.focus = true
            }

            PasswordInput {
                id: appPasswordField

                visible: !page.working
                label: qsTr("App password")
                placeholderText: page.configured ? qsTr("Stored; enter a new one to replace it")
                                                 : label
                EnterKey.enabled: page.ready && loginField.text.length > 0 && text.length > 0
                EnterKey.onClicked: page.useAppPassword()
            }

            Button {
                id: manualButton

                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.working
                enabled: page.ready && loginField.text.trim().length > 0
                         && appPasswordField.text.length > 0
                text: qsTr("Use app password")
                onClicked: page.useAppPassword()
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("An app password is recommended: create one in Nextcloud under Settings > Security. SailFactor keeps it in an entry of this file, protected by the master password; the account list does not show that entry, KeePassXC on a computer does. Anyone who can open the file can see the app password. You can revoke it in Nextcloud at any time.")
            }
        }
    }
}
