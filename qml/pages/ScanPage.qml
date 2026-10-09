import QtQuick 2.0
import QtMultimedia 5.6
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
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
        case Authenticator.Hotp: return qsTr("This is a counter-based code, which SailToken does not support")
        case Authenticator.UnsupportedType: return qsTr("This code type is not supported")
        case Authenticator.InvalidSecret: return qsTr("This code has an unreadable secret")
        case Authenticator.InvalidSettings: return qsTr("This code has settings out of range")
        case Authenticator.NotOtpauth: return qsTr("This QR code holds no two-factor account")
        default: return ""
        }
    }

    allowedOrientations: Orientation.Portrait

    // Still image mode, as other Sailfish QR scanners use it: on the Jolla
    // Phone the viewfinder mode left codes blurry, this one keeps them sharp.
    Camera {
        id: camera

        captureMode: Camera.CaptureStillImage
        cameraState: page.cameraWanted ? Camera.ActiveState : Camera.UnloadedState
        flash.mode: Camera.FlashOff
        focus {
            focusMode: Camera.FocusContinuous
            focusPointMode: Camera.FocusPointAuto
        }
        // The scanner decodes the central 1080 x 1080 square at full
        // resolution; mapping a 1920 x 1080 frame costs less than the 2560 x
        // 1440 default (Phase 1 spike).
        viewfinder.resolution: Qt.size(1920, 1080)
    }

    // A tap starts a new focus search, for a code the continuous focus
    // missed; the lock is released after a moment.
    Timer {
        id: focusRelease

        interval: 3000
        onTriggered: camera.unlock()
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
        id: viewfinder

        anchors.fill: parent
        source: camera
        filters: [ scanner ]
        fillMode: VideoOutput.PreserveAspectCrop

        MouseArea {
            anchors.fill: parent
            onClicked: {
                camera.unlock()
                camera.searchAndLock()
                focusRelease.restart()
            }
        }
    }

    // Where the decoded square lies: the middle of the frame, a little
    // larger than this guide.
    Rectangle {
        anchors.centerIn: parent
        width: Math.min(parent.width, parent.height) * 0.75
        height: width
        color: "transparent"
        border.color: Theme.highlightColor
        border.width: Theme.paddingSmall / 2
        radius: Theme.paddingMedium
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
            text: scanner.unsupportedFrames ? qsTr("The camera delivers frames SailToken cannot read")
                : scanner.rejection !== Authenticator.PendingReady ? page.rejectionText(scanner.rejection)
                : qsTr("Hold the QR code inside the frame. Tap to focus.")
        }
    }
}
