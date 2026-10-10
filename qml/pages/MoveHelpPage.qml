import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// How to bring the accounts of another authenticator app into SailToken.
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
                title: qsTr("Moving from another app")
            }

            SectionHeader {
                text: qsTr("Google Authenticator")
            }

            Repeater {
                model: [
                    qsTr("In Google Authenticator, open the menu, choose Transfer accounts, then Export accounts, and select the accounts. It shows one QR code for every ten accounts."),
                    qsTr("In SailToken, open Settings and choose From Google Authenticator. Hold each code inside the frame; the order does not matter. Nothing is written before you choose the accounts to add."),
                    qsTr("Google Authenticator exports no time step, so every account gets 30 seconds, as it has in Google Authenticator.")
                ]

                Paragraph {
                    color: Theme.highlightColor
                    text: modelData
                }
            }

            SectionHeader {
                text: qsTr("Aegis")
            }

            Repeater {
                model: [
                    qsTr("In Aegis, open Settings, Import & Export, Export, and choose the Aegis format, best with encryption. Copy the file to Documents or Downloads on this phone."),
                    qsTr("In SailToken, open Settings and choose From an Aegis backup, then enter the password you set in Aegis. The file keeps every account with its settings."),
                    qsTr("Aegis can also show its accounts as codes for Google Authenticator, but it leaves out some accounts, such as those with eight digits or SHA256. Use the file to move them all.")
                ]

                Paragraph {
                    color: Theme.highlightColor
                    text: modelData
                }
            }

            SectionHeader {
                text: qsTr("Afterwards")
            }

            Repeater {
                model: [
                    qsTr("Delete the export file wherever you copied it, on this phone, the computer and the cloud: it holds every account."),
                    qsTr("Counter-based accounts and kinds SailToken does not support are not imported. Keep them in the other app."),
                    qsTr("Keep the old app until you have logged in once with every account you moved.")
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
