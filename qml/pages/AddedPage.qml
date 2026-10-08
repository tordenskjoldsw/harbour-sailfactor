import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Shown once after a file was added: SailFactor now has its own copy, and
// the originals outside the app can be deleted or kept.
Page {
    id: page

    readonly property bool withKeyFile: authenticator.addedOriginals.length > 1

    function openAccounts() {
        pageStack.replace(Qt.resolvedUrl("AccountListPage.qml"))
    }

    // Going back would lock the file just added; the buttons decide.
    backNavigation: false
    allowedOrientations: Orientation.All

    RemorsePopup {
        id: remorse
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("File added")
            }

            Paragraph {
                text: page.withKeyFile
                      ? qsTr("SailFactor now keeps its own copies of the file and the key file, which other apps cannot read. The original files are still where they were and can be deleted.")
                      : qsTr("SailFactor now keeps its own copy of the file, which other apps cannot read. The original file is still where it was and can be deleted.")
            }

            Repeater {
                model: authenticator.addedOriginals

                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    textFormat: Text.PlainText
                    wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.secondaryHighlightColor
                    text: modelData
                }
            }

            Paragraph {
                visible: page.withKeyFile
                color: Theme.highlightColor
                text: qsTr("Keep a copy of the key file away from this phone. Without it, the file cannot be opened if the phone is lost.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.withKeyFile ? qsTr("Delete originals") : qsTr("Delete original")
                onClicked: remorse.execute(qsTr("Deleting the original files"), function() {
                    Notices.show(authenticator.removeAddedOriginals()
                                 ? qsTr("Original files deleted")
                                 : qsTr("The original files could not be deleted"),
                                 Notice.Short)
                    page.openAccounts()
                })
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.withKeyFile ? qsTr("Keep originals") : qsTr("Keep original")
                onClicked: page.openAccounts()
            }
        }
    }
}
