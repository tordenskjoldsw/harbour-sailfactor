import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0
import "../components"

Page {
    id: page

    // Splits a code in two groups for reading aloud; Steam codes stay whole.
    function formatCode(code, steam) {
        if (steam || code.length < 6)
            return code
        var half = Math.floor(code.length / 2)
        return code.substring(0, half) + " " + code.substring(half)
    }

    function kindText(kind) {
        switch (kind) {
        case AccountListModel.Hotp: return qsTr("Counter-based code, not supported")
        case AccountListModel.Unreadable: return qsTr("Its settings cannot be read")
        case AccountListModel.NoCode: return qsTr("No one-time code")
        default: return ""
        }
    }

    // A page-level remorse: the list reloads after the deletion, which would
    // destroy a remorse shown inside the deleted row.
    function deleteAccount(accountId, issuer) {
        var permanent = authenticator.deletesPermanently(accountId)
        var text = permanent ? qsTr("Deleting %1 permanently").arg(issuer)
                             : qsTr("Moving %1 to the recycle bin").arg(issuer)
        remorse.execute(text, function() {
            if (!authenticator.deleteAccount(accountId))
                Notices.show(qsTr("Not deleted, the file is being saved"), Notice.Short)
        })
    }

    // A certificate or a configuration to confirm interrupts: syncing stops
    // until the user decides. Only the top page asks, a configuration once.
    function askForSyncDecision() {
        if (page.status !== PageStatus.Active || sync.state !== Sync.Failed)
            return
        if (sync.problem === Sync.CertificateUnknown)
            pageStack.push(Qt.resolvedUrl("CertificateDialog.qml"))
        else if (sync.problem === Sync.Unconfirmed && sync.takeConfirmationRequest())
            pageStack.push(Qt.resolvedUrl("SyncConfirmDialog.qml"))
    }

    allowedOrientations: Orientation.All

    onStatusChanged: {
        if (status === PageStatus.Active && sync.problem === Sync.Unconfirmed)
            askForSyncDecision()
    }

    Connections {
        target: sync
        onStateChanged: page.askForSyncDecision()
    }

    SyncText {
        id: syncText
    }

    RemorsePopup {
        id: remorse
    }

    SilicaListView {
        id: listView

        anchors.fill: parent
        currentIndex: -1

        model: AccountListModel {
            id: accounts
            source: authenticator
            query: listView.headerItem ? listView.headerItem.query : ""
        }

        header: Column {
            property alias query: searchField.text

            width: parent.width

            PageHeader {
                title: "SailFactor"
                description: authenticator.saving ? qsTr("Saving")
                           : authenticator.dirty ? qsTr("Not saved")
                           : !sync.configured ? ""
                           : sync.state === Sync.Syncing ? qsTr("Syncing")
                           : sync.state === Sync.Failed ? syncText.problem(sync.problem)
                           : sync.state === Sync.Idle ? qsTr("Synced")
                           : ""
            }

            SearchField {
                id: searchField

                width: parent.width
                visible: authenticator.accountCount > 0
                placeholderText: qsTr("Search")
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
        }

        PullDownMenu {
            busy: authenticator.saving

            // Rare actions live on their own page, so the menu stays short.
            MenuItem {
                text: qsTr("Settings")
                onClicked: pageStack.push(Qt.resolvedUrl("SettingsPage.qml"))
            }
            MenuItem {
                text: qsTr("Lock")
                onClicked: authenticator.lock()
            }
            MenuItem {
                text: qsTr("Type in an account")
                onClicked: pageStack.push(Qt.resolvedUrl("AccountDialog.qml"), { "manual": true })
            }
            MenuItem {
                text: qsTr("Scan QR code")
                onClicked: pageStack.push(Qt.resolvedUrl("ScanPage.qml"))
            }
        }

        delegate: ListItem {
            id: item

            readonly property bool hasCode: model.kind === AccountListModel.Totp

            contentHeight: Theme.itemSizeLarge
            onClicked: {
                if (hasCode && authenticator.copyCode(model.accountId)) {
                    Notices.show(qsTr("Code copied, cleared in %1 s")
                                 .arg(authenticator.clipboardClearSeconds), Notice.Short)
                }
            }

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Rename")
                    onClicked: pageStack.push(Qt.resolvedUrl("RenameDialog.qml"),
                                              { "accountId": model.accountId,
                                                "issuer": model.issuer,
                                                "name": model.name })
                }
                MenuItem {
                    text: qsTr("Delete")
                    onClicked: page.deleteAccount(model.accountId, model.issuer)
                }
            }

            Column {
                anchors {
                    left: parent.left
                    leftMargin: Theme.horizontalPageMargin
                    right: code.visible ? code.left : parent.right
                    rightMargin: Theme.paddingLarge
                    verticalCenter: parent.verticalCenter
                }

                Label {
                    width: parent.width
                    textFormat: Text.PlainText
                    truncationMode: TruncationMode.Fade
                    color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                    text: model.issuer.length > 0 ? model.issuer : qsTr("No issuer")
                }

                Label {
                    width: parent.width
                    visible: text.length > 0
                    textFormat: Text.PlainText
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: item.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                    text: item.hasCode ? model.name : page.kindText(model.kind)
                }
            }

            Label {
                id: code

                anchors {
                    right: ring.left
                    rightMargin: Theme.paddingMedium
                    verticalCenter: parent.verticalCenter
                }
                visible: item.hasCode
                textFormat: Text.PlainText
                font.pixelSize: Theme.fontSizeLarge
                color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                text: page.formatCode(model.code, model.steam)
            }

            ProgressCircle {
                id: ring

                anchors {
                    right: parent.right
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
                visible: item.hasCode
                width: Theme.iconSizeSmallPlus
                height: width
                value: model.period > 0 ? model.remaining / model.period : 0
                progressColor: model.remaining <= 5 ? Theme.errorColor : Theme.highlightColor
                backgroundColor: Theme.rgba(Theme.highlightDimmerColor, 0.5)
            }
        }

        ViewPlaceholder {
            enabled: listView.count === 0 && authenticator.accountCount === 0
            text: qsTr("No accounts yet")
            hintText: qsTr("Pull down to scan the QR code a service shows when you turn on two-factor login")
        }

        VerticalScrollDecorator {}
    }
}
