import QtQuick 2.0
import QtMultimedia 5.6
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0
import "../components"

// The camera viewfinder until a QR code with a TOTP account is in view; then
// the confirmation dialog takes its place. The code itself never reaches
// QML, only its issuer, account name and first code once found.
Page {
    id: page

    readonly property bool cameraWanted: status === PageStatus.Active
                                         && Qt.application.state === Qt.ApplicationActive

    function rejectionText(rejection) {
        switch (rejection) {
        case Authenticator.Hotp: return qsTr("This is a counter-based code, which SailFactor does not support")
        case Authenticator.UnsupportedType: return qsTr("This code type is not supported")
        case Authenticator.InvalidSecret: return qsTr("This code has an unreadable secret")
        case Authenticator.InvalidSettings: return qsTr("This code has settings out of range")
        case Authenticator.NotOtpauth: return qsTr("This QR code holds no two-factor account")
        default: return ""
        }
    }

    allowedOrientations: Orientation.Portrait

    Camera {
        id: camera

        captureMode: Camera.CaptureViewfinder
        cameraState: page.cameraWanted ? Camera.ActiveState : Camera.UnloadedState
        focus.focusMode: Camera.FocusContinuous
        // Measured in the Phase 1 spike: a third of the mapping time of the
        // default 2560 x 1440, and the decoder sees 1280 x 720 either way.
        viewfinder.resolution: Qt.size(1280, 720)
    }

    FrameScanner {
        id: scanner

        onCodeFound: {
            if (authenticator.takeScan(scanner))
                pageStack.replace(Qt.resolvedUrl("AccountDialog.qml"), { "manual": false })
            else
                scanner.rearm()
        }
    }

    // The Sailfish camera plugin delivers frames upright for the portrait
    // page; autoOrientation would turn them a second time.
    VideoOutput {
        anchors.fill: parent
        source: camera
        filters: [ scanner ]
        fillMode: VideoOutput.PreserveAspectCrop
    }

    Rectangle {
        width: parent.width
        height: header.height
        color: Theme.rgba(Theme.overlayBackgroundColor, 0.7)

        PageHeader {
            id: header

            title: qsTr("Scan QR code")
        }
    }

    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: hint.height + 2 * Theme.paddingLarge
        color: Theme.rgba(Theme.overlayBackgroundColor, 0.7)

        Paragraph {
            id: hint

            anchors.verticalCenter: parent.verticalCenter
            horizontalAlignment: Text.AlignHCenter
            color: scanner.rejection !== Authenticator.PendingReady || scanner.unsupportedFrames
                   ? Theme.errorColor : Theme.highlightColor
            text: scanner.unsupportedFrames ? qsTr("The camera delivers frames SailFactor cannot read")
                : scanner.rejection !== Authenticator.PendingReady ? page.rejectionText(scanner.rejection)
                : qsTr("Point the camera at the QR code the service shows")
        }
    }
}
