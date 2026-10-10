import QtQuick 2.0
import QtMultimedia 5.6
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0

// The camera viewfinder of the scan pages. The scanner decodes the central
// square, which the guide marks; a tap starts a new focus search. The page
// keeps the scanner and decides what a find means.
Item {
    id: root

    property bool active
    property FrameScanner scanner
    property alias title: header.title
    property string hint
    property bool hintIsError

    anchors.fill: parent

    // Still image mode, as other Sailfish QR scanners use it: on the Jolla
    // Phone the viewfinder mode left codes blurry, this one keeps them sharp.
    Camera {
        id: camera

        captureMode: Camera.CaptureStillImage
        cameraState: root.active ? Camera.ActiveState : Camera.UnloadedState
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

    // The Sailfish camera plugin delivers frames upright for the portrait
    // page; autoOrientation would turn them a second time.
    VideoOutput {
        anchors.fill: parent
        source: camera
        filters: [ root.scanner ]
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
        }
    }

    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: hintText.height + 2 * Theme.paddingLarge
        color: Theme.rgba(Theme.overlayBackgroundColor, 0.7)

        Paragraph {
            id: hintText

            anchors.verticalCenter: parent.verticalCenter
            horizontalAlignment: Text.AlignHCenter
            color: root.hintIsError ? Theme.errorColor : Theme.highlightColor
            text: root.hint
        }
    }
}
