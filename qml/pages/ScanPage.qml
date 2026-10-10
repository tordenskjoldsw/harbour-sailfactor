import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// The camera viewfinder until a QR code with a TOTP account is in view; then
// the confirmation dialog takes its place. The code itself never reaches
// QML, only its issuer, account name and first code once found. An export
// code of another app leads to the import.
Page {
    id: page

    function rejectionText(rejection) {
        switch (rejection) {
        case Authenticator.Hotp: return qsTr("This is a counter-based code, which SailToken does not support")
        case Authenticator.UnsupportedType: return qsTr("This code type is not supported")
        case Authenticator.InvalidSecret: return qsTr("This code has an unreadable secret")
        case Authenticator.InvalidSettings: return qsTr("This code has settings out of range")
        case Authenticator.NotOtpauth: return qsTr("This QR code holds no two-factor account")
        default: return ""
        }
    }

    allowedOrientations: Orientation.Portrait

    FrameScanner {
        id: scanner

        onCodeFound: {
            if (authenticator.takeScan(scanner))
                pageStack.replace(Qt.resolvedUrl("AccountDialog.qml"), { "manual": false })
            else
                scanner.rearm()
        }
        onExportCodeFound: pageStack.replace(Qt.resolvedUrl("ImportPage.qml"))
    }

    QrCamera {
        active: page.status === PageStatus.Active
                && Qt.application.state === Qt.ApplicationActive
        scanner: scanner
        title: qsTr("Scan QR code")
        hintIsError: scanner.rejection !== Authenticator.PendingReady || scanner.unsupportedFrames
        hint: scanner.unsupportedFrames ? qsTr("The camera delivers frames SailToken cannot read")
            : scanner.rejection !== Authenticator.PendingReady ? page.rejectionText(scanner.rejection)
            : qsTr("Hold the QR code inside the frame. Tap to focus.")
    }
}
