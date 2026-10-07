import QtQuick 2.0
import Sailfish.Silica 1.0

Page {
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                text: qsTr("Test the QR scan")
                onClicked: pageStack.push(Qt.resolvedUrl("ScanPage.qml"))
            }
        }

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: "SailFactor"
            }

            DetailItem {
                label: qsTr("Version")
                value: appVersion
            }

            DetailItem {
                label: qsTr("Core")
                value: coreVersion
            }
        }

        VerticalScrollDecorator {}
    }
}
