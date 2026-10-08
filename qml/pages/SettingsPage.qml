import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0
import "../components"

Page {
    id: page

    function saveCopy() {
        var dialog = pageStack.push(Qt.resolvedUrl("SaveCopyDialog.qml"))
        dialog.accepted.connect(function() {
            switch (databases.saveCopy(databases.defaultName, dialog.location, dialog.fileName,
                                       dialog.withKeyFile)) {
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

    // Set when the delete dialog was accepted; the file is deleted once the
    // dialog has closed, because deleting locks and returns to the unlock
    // page, which must not happen while the dialog's transition runs.
    property bool deleteRequested

    function deleteFile() {
        var dialog = pageStack.push(Qt.resolvedUrl("DeleteFileDialog.qml"))
        dialog.accepted.connect(function() { page.deleteRequested = true })
    }

    allowedOrientations: Orientation.All

    onStatusChanged: {
        if (status !== PageStatus.Active || !deleteRequested)
            return
        deleteRequested = false
        if (!authenticator.removeFile())
            Notices.show(qsTr("The file could not be deleted completely"), Notice.Long)
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Settings")
            }

            Column {
                width: parent.width

                Repeater {
                    model: [
                        { "text": qsTr("My code is rejected"), "page": "HelpPage.qml" },
                        { "text": qsTr("About SailFactor"), "page": "AboutPage.qml" }
                    ]

                    BackgroundItem {
                        id: link

                        width: parent.width
                        onClicked: pageStack.push(Qt.resolvedUrl(modelData.page))

                        Label {
                            x: Theme.horizontalPageMargin
                            width: parent.width - 2 * Theme.horizontalPageMargin
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            truncationMode: TruncationMode.Fade
                            color: link.highlighted ? Theme.highlightColor : Theme.primaryColor
                            text: modelData.text
                        }
                    }
                }
            }

            SectionHeader {
                text: qsTr("File")
            }

            Column {
                width: parent.width

                Repeater {
                    model: [
                        { "text": qsTr("Save a copy for the computer"), "action": "copy" },
                        { "text": qsTr("Delete the file"), "action": "delete" }
                    ]

                    BackgroundItem {
                        id: fileAction

                        width: parent.width
                        enabled: !authenticator.saving
                        onClicked: modelData.action === "copy" ? page.saveCopy() : page.deleteFile()

                        Label {
                            x: Theme.horizontalPageMargin
                            width: parent.width - 2 * Theme.horizontalPageMargin
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            truncationMode: TruncationMode.Fade
                            color: fileAction.highlighted ? Theme.highlightColor : Theme.primaryColor
                            text: modelData.text
                        }
                    }
                }
            }

            SectionHeader {
                text: qsTr("Protection")
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: qsTr("SailFactor locks after 2 minutes without use and after 30 seconds in the background. A copied code is removed from the clipboard after %1 seconds, and when the file locks.")
                      .arg(authenticator.clipboardClearSeconds)
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: qsTr("Every change is saved at once. The last three versions of the file are kept as backups in the app's private storage.")
            }
        }

        VerticalScrollDecorator {}
    }
}
