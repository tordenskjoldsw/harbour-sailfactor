import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

Page {
    allowedOrientations: Orientation.All

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
