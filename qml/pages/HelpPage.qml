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
                title: qsTr("My code is rejected")
            }

            Repeater {
                model: [
                    qsTr("A code depends on the current time. If the phone's clock is off by more than about half a minute, services reject the codes, and SailFactor cannot notice it."),
                    qsTr("Check in the phone's settings under Time and date that the time is set automatically, then try a fresh code."),
                    qsTr("Enter the code before the ring runs out. A code that changes while you type it is often still accepted, but not always."),
                    qsTr("If only one account fails, its settings may differ from the usual ones. Add it again from the service's QR code, or type in the algorithm, digits and period the service names.")
                ]

                Paragraph {
                    color: Theme.highlightColor
                    text: modelData
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
