import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0

// The files SailFactor stores; choosing one makes it the file the unlock
// page opens.
Page {
    id: page

    function saveCopy(name) {
        var dialog = pageStack.push(Qt.resolvedUrl("SaveCopyDialog.qml"), { "name": name })
        dialog.accepted.connect(function() {
            switch (databases.saveCopy(name, dialog.location, dialog.fileName, dialog.withKeyFile)) {
            case Databases.CopySaved:
                Notices.show(dialog.location === Databases.Downloads ? qsTr("Copy saved in Downloads")
                                                                     : qsTr("Copy saved in Documents"),
                             Notice.Short)
                break
            case Databases.CopyExists:
                Notices.show(qsTr("A file with this name already exists"), Notice.Short)
                break
            default:
                Notices.show(qsTr("The copy could not be saved"), Notice.Short)
            }
        })
    }

    // A page-level remorse: the list reloads after the deletion, which would
    // destroy a remorse shown inside the deleted item's delegate.
    function removeFile(name) {
        remorse.execute(qsTr("Deleting file and backups"), function() {
            if (!authenticator.removeFile(name))
                Notices.show(qsTr("The file could not be deleted completely"), Notice.Short)
            listView.model = databases.names()
        })
    }

    allowedOrientations: Orientation.All

    RemorsePopup {
        id: remorse
    }

    SilicaListView {
        id: listView

        anchors.fill: parent
        model: databases.names()

        header: PageHeader {
            title: qsTr("Files")
        }

        delegate: ListItem {
            id: item

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                truncationMode: TruncationMode.Fade
                color: item.highlighted || modelData === authenticator.databaseName
                       ? Theme.highlightColor : Theme.primaryColor
                text: modelData
            }

            onClicked: {
                authenticator.databaseName = modelData
                pageStack.pop()
            }

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Save copy")
                    onClicked: page.saveCopy(modelData)
                }
                MenuItem {
                    text: qsTr("Delete")
                    onClicked: page.removeFile(modelData)
                }
            }
        }

        ViewPlaceholder {
            enabled: listView.count === 0
            text: qsTr("No files")
        }

        VerticalScrollDecorator {}
    }
}
