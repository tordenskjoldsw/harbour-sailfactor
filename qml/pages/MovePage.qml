import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// Moves an account to any place in the list with one tap: on the account
// it should come before, or on the end.
Page {
    id: page

    property string accountId
    property string issuer

    function moveBefore(beforeId) {
        if (!authenticator.moveAccount(accountId, beforeId))
            Notices.show(qsTr("Not moved, the file is being saved"), Notice.Short)
        pageStack.pop()
    }

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent

        model: AccountListModel {
            source: authenticator
        }

        header: Column {
            width: parent.width

            PageHeader {
                title: qsTr("Move")
                description: page.issuer
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Tap the account it should come before.")
            }

            Item {
                width: 1
                height: Theme.paddingMedium
            }
        }

        delegate: BackgroundItem {
            id: row

            readonly property bool isMoved: model.accountId === page.accountId

            width: listView.width
            height: Theme.itemSizeMedium
            enabled: !isMoved && !authenticator.busy
            onClicked: page.moveBefore(model.accountId)

            TwoLineLabel {
                anchors.fill: parent
                highlighted: row.highlighted || row.isMoved
                title: model.issuer.length > 0 ? model.issuer : qsTr("No issuer")
                description: model.name
            }
        }

        footer: BackgroundItem {
            id: end

            width: listView.width
            height: Theme.itemSizeMedium
            enabled: !authenticator.busy
            onClicked: page.moveBefore("")

            TwoLineLabel {
                anchors.fill: parent
                highlighted: end.highlighted
                title: qsTr("To the end")
            }
        }

        VerticalScrollDecorator {}
    }
}
