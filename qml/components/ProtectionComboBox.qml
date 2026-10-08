import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0

// The Argon2id level of a new file, Standard by default.
ComboBox {
    readonly property int kdfLevel: [Authenticator.KdfStandard, Authenticator.KdfHigh,
                                     Authenticator.KdfMaximum][currentIndex]

    label: qsTr("Protection")
    description: qsTr("Higher levels make each guess of the master password cost an attacker more. The time applies to every unlock and save on this phone.")
    menu: ContextMenu {
        MenuItem { text: qsTr("Standard (about 1 s)") }
        MenuItem { text: qsTr("High (about 2.5 s)") }
        MenuItem { text: qsTr("Maximum (about 5 s)") }
    }
}
