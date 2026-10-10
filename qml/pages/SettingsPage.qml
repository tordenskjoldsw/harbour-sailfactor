import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailtoken 1.0
import "../components"

// Settings and occasional actions for the open file: sync, importing from
// another app, merging a copy, saving a copy, deleting it, and help. The
// account list keeps its pulley menu for the frequent actions.
Page {
    id: page

    // The file picker closes itself after a selection; the merge page opens
    // once this page is back.
    property string pendingMergePath
    property string pendingImportPath
    // Set when the delete dialog was accepted; the file is deleted once the
    // dialog has closed, because deleting locks and returns to the unlock
    // page, which must not happen while the dialog's transition runs.
    property bool deleteRequested

    function syncDescription() {
        if (!sync.configured)
            return qsTr("Not set up")
        switch (sync.state) {
        case Sync.Syncing:
            return qsTr("Syncing")
        case Sync.Failed:
            return syncText.problem(sync.problem)
        default:
            return isNaN(sync.lastSynced.getTime())
                    ? qsTr("Set up")
                    : qsTr("Last synced %1").arg(Qt.formatDateTime(sync.lastSynced,
                                                                   Qt.DefaultLocaleShortDate))
        }
    }

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

    function emptyRecycleBin() {
        remorse.execute(qsTr("Emptying the recycle bin"), function() {
            if (!authenticator.emptyRecycleBin())
                Notices.show(qsTr("The recycle bin could not be emptied"), Notice.Short)
        })
    }

    function deleteFile() {
        var dialog = pageStack.push(Qt.resolvedUrl("DeleteFileDialog.qml"))
        dialog.accepted.connect(function() { page.deleteRequested = true })
    }

    allowedOrientations: Orientation.All

    onStatusChanged: {
        if (status !== PageStatus.Active)
            return
        if (deleteRequested) {
            deleteRequested = false
            if (!authenticator.removeFile())
                Notices.show(qsTr("The file could not be deleted completely"), Notice.Long)
        } else if (pendingMergePath.length > 0) {
            var path = pendingMergePath
            pendingMergePath = ""
            pageStack.push(Qt.resolvedUrl("MergePage.qml"), { "path": path })
        } else if (pendingImportPath.length > 0) {
            var importPath = pendingImportPath
            pendingImportPath = ""
            pageStack.push(Qt.resolvedUrl("ImportFilePage.qml"), { "path": importPath })
        }
    }

    SyncText {
        id: syncText
    }

    RemorsePopup {
        id: remorse
    }

    Component {
        id: mergePicker

        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: page.pendingMergePath = selectedContentProperties.filePath
        }
    }

    Component {
        id: importPicker

        FilePickerPage {
            nameFilters: ["*.json"]
            onSelectedContentPropertiesChanged: page.pendingImportPath = selectedContentProperties.filePath
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            PageHeader {
                title: qsTr("Settings")
            }

            SectionHeader {
                text: qsTr("Sync")
            }

            BackgroundItem {
                id: syncItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy
                onClicked: pageStack.push(Qt.resolvedUrl(
                    sync.problem === Sync.Unconfirmed ? "SyncConfirmDialog.qml"
                                                      : "SyncSetupPage.qml"))

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: syncItem.highlighted
                    title: qsTr("Sync with Nextcloud")
                    description: page.syncDescription()
                }
            }

            BackgroundItem {
                id: syncNowItem

                visible: sync.configured
                enabled: sync.state !== Sync.Syncing && sync.problem !== Sync.Unconfirmed
                onClicked: sync.sync()

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: syncNowItem.highlighted
                    title: qsTr("Sync now")
                }
            }

            SectionHeader {
                text: qsTr("Import accounts")
            }

            BackgroundItem {
                id: importCodesItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy
                onClicked: pageStack.push(Qt.resolvedUrl("ImportPage.qml"))

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: importCodesItem.highlighted
                    title: qsTr("From Google Authenticator")
                    description: qsTr("Scan its export codes")
                }
            }

            BackgroundItem {
                id: importFileItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy && !authenticator.importingFile
                onClicked: pageStack.push(importPicker)

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: importFileItem.highlighted
                    title: qsTr("From an Aegis backup")
                    description: qsTr("Every account with its settings, from Documents or Downloads")
                }
            }

            SectionHeader {
                text: qsTr("File")
            }

            BackgroundItem {
                id: mergeItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy
                onClicked: pageStack.push(mergePicker)

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: mergeItem.highlighted
                    title: qsTr("Merge with file")
                    description: qsTr("Bring in the changes of another copy")
                }
            }

            BackgroundItem {
                id: binItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy && authenticator.recycleBinItems > 0
                onClicked: page.emptyRecycleBin()

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: binItem.highlighted
                    title: qsTr("Empty recycle bin")
                    // No translations exist yet, so the count goes after a
                    // label instead of into a %n plural.
                    description: authenticator.recycleBinItems > 0
                                 ? qsTr("Deleted accounts keep their secrets there. Items: %1")
                                   .arg(authenticator.recycleBinItems)
                                 : qsTr("Empty")
                }
            }

            BackgroundItem {
                id: copyItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy
                onClicked: page.saveCopy()

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: copyItem.highlighted
                    title: qsTr("Save a copy for the computer")
                    description: qsTr("To Documents or Downloads")
                }
            }

            BackgroundItem {
                id: deleteItem

                height: Theme.itemSizeMedium
                enabled: !authenticator.busy
                onClicked: page.deleteFile()

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: deleteItem.highlighted
                    title: qsTr("Delete the file")
                    description: qsTr("With every account, its key file and backups")
                }
            }

            SectionHeader {
                text: qsTr("Help")
            }

            Repeater {
                model: [
                    { "text": qsTr("My code is rejected"), "page": "HelpPage.qml" },
                    { "text": qsTr("About SailToken"), "page": "AboutPage.qml" }
                ]

                BackgroundItem {
                    id: link

                    width: parent.width
                    onClicked: pageStack.push(Qt.resolvedUrl(modelData.page))

                    TwoLineLabel {
                        anchors.fill: parent
                        highlighted: link.highlighted
                        title: modelData.text
                    }
                }
            }

            SectionHeader {
                text: qsTr("Protection")
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: qsTr("SailToken locks after 2 minutes without use and after 30 seconds in the background. A copied code is removed from the clipboard after %1 seconds, and when the file locks.")
                      .arg(authenticator.clipboardClearSeconds)
            }

            Item {
                width: 1
                height: Theme.paddingMedium
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
