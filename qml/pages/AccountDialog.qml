import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0
import "../components"

// Adds the pending account: one found by the scanner, shown for
// confirmation, or one typed in by hand. Either way the first code shows
// before saving, so it can be checked against the service.
Dialog {
    id: dialog

    property bool manual
    property int status: Authenticator.PendingReady
    property var current: ({})

    function prepare() {
        if (!manual)
            return
        status = secretField.text.length === 0
                ? Authenticator.InvalidSecret
                : authenticator.preparePending(secretField.text, algorithmBox.currentIndex,
                                               parseInt(digitsField.text, 10) || 0,
                                               parseInt(periodField.text, 10) || 0,
                                               steamSwitch.checked)
        refresh()
    }

    function refresh() {
        current = authenticator.pendingCode()
    }

    function statusText() {
        if (secretField.text.length === 0)
            return ""
        switch (status) {
        case Authenticator.InvalidSecret: return qsTr("Not a Base32 secret")
        case Authenticator.InvalidSettings: return qsTr("Digits from 1 to 10, a period from 1 to 86400 seconds")
        default: return ""
        }
    }

    canAccept: authenticator.hasPending && issuerField.text.trim().length > 0
               && !authenticator.saving
    allowedOrientations: Orientation.All

    Component.onCompleted: refresh()
    onAccepted: {
        if (!authenticator.addPending(issuerField.text.trim(), nameField.text.trim()))
            Notices.show(qsTr("The account could not be added"), Notice.Long)
    }
    onRejected: authenticator.clearPending()

    Timer {
        running: authenticator.hasPending && Qt.application.state === Qt.ApplicationActive
        interval: 1000
        repeat: true
        onTriggered: dialog.refresh()
    }

    Connections {
        target: authenticator
        // A lock clears the pending account.
        onPendingChanged: dialog.refresh()
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                title: dialog.manual ? qsTr("Type in an account") : qsTr("Add account")
                acceptText: qsTr("Add")
            }

            TextField {
                id: issuerField

                width: parent.width
                label: qsTr("Issuer")
                placeholderText: qsTr("Service, such as the website")
                text: dialog.manual ? "" : authenticator.pendingIssuer
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: nameField.focus = true
            }

            TextField {
                id: nameField

                width: parent.width
                label: qsTr("Account")
                placeholderText: qsTr("Your user name or e-mail address")
                text: dialog.manual ? "" : authenticator.pendingName
                inputMethodHints: Qt.ImhNoAutoUppercase
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: dialog.manual ? secretField.focus = true : nameField.focus = false
            }

            PasswordInput {
                id: secretField

                visible: dialog.manual
                label: qsTr("Secret key")
                errorText: dialog.statusText()
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhSensitiveData
                onTextChanged: dialog.prepare()
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            TextSwitch {
                id: advancedSwitch

                visible: dialog.manual
                text: qsTr("Settings other than the usual")
                description: qsTr("Only when the service names an algorithm, digits or period")
            }

            Column {
                width: parent.width
                visible: dialog.manual && advancedSwitch.checked

                ComboBox {
                    id: algorithmBox

                    label: qsTr("Algorithm")
                    menu: ContextMenu {
                        MenuItem { text: "SHA-1" }
                        MenuItem { text: "SHA-256" }
                        MenuItem { text: "SHA-512" }
                    }
                    onCurrentIndexChanged: dialog.prepare()
                }

                TextField {
                    id: digitsField

                    width: parent.width
                    label: qsTr("Digits")
                    text: "6"
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 10 }
                    onTextChanged: dialog.prepare()
                }

                TextField {
                    id: periodField

                    width: parent.width
                    label: qsTr("Period in seconds")
                    text: "30"
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 86400 }
                    onTextChanged: dialog.prepare()
                }

                TextSwitch {
                    id: steamSwitch

                    text: qsTr("Steam Guard")
                    description: qsTr("Five letters instead of digits")
                    onCheckedChanged: {
                        digitsField.text = checked ? "5" : "6"
                        dialog.prepare()
                    }
                }
            }

            DetailItem {
                visible: authenticator.hasPending && dialog.current.code !== undefined
                label: qsTr("Current code")
                value: dialog.current.code !== undefined
                       ? qsTr("%1, %2 s left").arg(dialog.current.code).arg(dialog.current.remaining)
                       : ""
            }

            Paragraph {
                visible: authenticator.hasPending
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("If the service asks for a code to finish setting up two-factor login, enter this one before you add the account.")
            }
        }
    }
}
