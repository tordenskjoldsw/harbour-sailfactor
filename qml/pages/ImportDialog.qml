import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// The accounts of a scanned export, to choose from before anything is
// written. Accounts whose secret the file already has start unselected.
// Accepting adds the chosen ones and saves once.
Dialog {
    id: dialog

    readonly property var summary: authenticator.importSummary()
    readonly property int skipped: (summary.hotp || 0) + (summary.unsupported || 0)
                                   + (summary.invalid || 0)
    property int selectedCount

    function updateSelectedCount() {
        var count = 0
        for (var index = 0; index < accounts.count; ++index) {
            if (accounts.get(index).selected)
                ++count
        }
        selectedCount = count
    }

    allowedOrientations: Orientation.All
    canAccept: selectedCount > 0

    Component.onCompleted: {
        var list = authenticator.importAccounts()
        for (var index = 0; index < list.length; ++index) {
            accounts.append({
                "issuer": list[index].issuer,
                "name": list[index].name,
                "duplicate": list[index].duplicate,
                "selected": !list[index].duplicate
            })
        }
        updateSelectedCount()
    }

    onAccepted: {
        var selection = []
        for (var index = 0; index < accounts.count; ++index)
            selection.push(accounts.get(index).selected)
        var added = authenticator.addImported(selection)
        // No translations exist yet, so the count goes after a label
        // instead of into a %n plural.
        Notices.show(added >= 0 ? qsTr("Accounts added: %1").arg(added)
                                : qsTr("The accounts could not be added"), Notice.Short)
    }
    onRejected: authenticator.clearImport()

    ListModel {
        id: accounts
    }

    SilicaListView {
        anchors.fill: parent
        model: accounts

        header: Column {
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                acceptText: qsTr("Add")
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: qsTr("Accounts found: %1. Accounts SailToken already has are not selected.")
                      .arg(accounts.count)
            }

            Paragraph {
                visible: dialog.skipped > 0
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Not imported: %1. Counter-based: %2, not supported: %3, unreadable: %4. Keep them in the other app.")
                      .arg(dialog.skipped).arg(dialog.summary.hotp || 0)
                      .arg(dialog.summary.unsupported || 0).arg(dialog.summary.invalid || 0)
            }

            Item {
                width: 1
                height: Theme.paddingSmall
            }
        }

        delegate: TextSwitch {
            text: model.issuer.length > 0 ? model.issuer : qsTr("No issuer")
            description: model.duplicate ? qsTr("%1, already in SailToken").arg(model.name)
                                         : model.name
            checked: model.selected
            onCheckedChanged: {
                accounts.setProperty(index, "selected", checked)
                dialog.updateSelectedCount()
            }
        }

        VerticalScrollDecorator {}
    }
}
