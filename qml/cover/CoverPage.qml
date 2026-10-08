import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0

// Shows the lock state and the number of accounts, never a code.
CoverBackground {
    readonly property bool unlocked: authenticator.state === Authenticator.Unlocked

    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.paddingLarge
        spacing: Theme.paddingMedium

        Label {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            textFormat: Text.PlainText
            text: "SailFactor"
        }

        Label {
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            textFormat: Text.PlainText
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.secondaryColor
            wrapMode: Text.Wrap
            text: unlocked ? qsTr("%n account(s)", "", authenticator.accountCount) : qsTr("Locked")
        }
    }

    CoverActionList {
        enabled: unlocked

        CoverAction {
            iconSource: "image://theme/icon-m-device-lock"
            onTriggered: authenticator.lock()
        }
    }
}
