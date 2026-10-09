import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// Asks where to save a copy of the app's file. The caller saves it from
// these properties when accepted.
Dialog {
    id: dialog

    readonly property bool hasKeyFile: authenticator.hasKeyFile
    readonly property string fileName: nameField.text.trim()
    readonly property int location: locationBox.currentIndex === 1 ? Databases.Downloads
                                                                    : Databases.Documents
    readonly property bool withKeyFile: hasKeyFile && keyFileSwitch.checked
    readonly property bool validName: databases.isValidName(fileName)
    readonly property bool exists: databases.copyExists(location, fileName, withKeyFile)

    canAccept: validName && !exists
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                title: qsTr("Save copy")
                acceptText: qsTr("Save")
            }

            TextField {
                id: nameField

                width: parent.width
                label: qsTr("File name")
                placeholderText: label
                text: databases.defaultName
                errorHighlight: dialog.fileName.length > 0 && !dialog.canAccept
                description: dialog.exists ? qsTr("A file with this name already exists")
                           : dialog.fileName.length > 0 && !dialog.validName
                             ? qsTr("Not a valid file name")
                           : dialog.withKeyFile ? dialog.fileName + ".kdbx, " + dialog.fileName + ".key"
                           : dialog.fileName + ".kdbx"
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            ComboBox {
                id: locationBox

                label: qsTr("Folder")
                menu: ContextMenu {
                    MenuItem { text: qsTr("Documents") }
                    MenuItem { text: qsTr("Downloads") }
                }
            }

            TextSwitch {
                id: keyFileSwitch

                visible: dialog.hasKeyFile
                text: qsTr("Include key file")
                description: qsTr("Move the key file to your computer apart from the file and delete it here afterwards. In the same folder as the file it adds little protection.")
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("The copy is encrypted like the file, but other apps with access to the folder can read it. Delete it once it is on your computer.")
            }
        }
    }
}
