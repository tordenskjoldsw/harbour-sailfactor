import QtQuick 2.0
import QtMultimedia 5.6
import Sailfish.Silica 1.0
import harbour.sailfactor 1.0

// Phase 1 spike: shows what the camera delivers and how fast the core
// decodes it. The payload itself never reaches QML.
Page {
    id: page

    readonly property bool cameraWanted: status === PageStatus.Active
                                         && Qt.application.state === Qt.ApplicationActive
    property real activeSince: 0
    property int timeToCodeMs: -1

    function statusText() {
        switch (scanner.status) {
        case FrameScanner.Waiting: return qsTr("Waiting for frames")
        case FrameScanner.Scanning: return qsTr("Scanning")
        case FrameScanner.Found: return scanner.totpUri ? qsTr("TOTP link found") : qsTr("Other QR code found")
        case FrameScanner.Unmappable: return qsTr("Frames cannot be read")
        case FrameScanner.UnsupportedFormat: return qsTr("Unsupported frame format")
        }
        return ""
    }

    function restart() {
        timeToCodeMs = -1
        activeSince = Date.now()
        scanner.rearm()
    }

    allowedOrientations: Orientation.Portrait

    Camera {
        id: camera

        captureMode: Camera.CaptureViewfinder
        cameraState: page.cameraWanted ? Camera.ActiveState : Camera.UnloadedState
        focus.focusMode: Camera.FocusContinuous
        onCameraStateChanged: {
            if (cameraState === Camera.ActiveState)
                page.restart()
        }
    }

    FrameScanner {
        id: scanner

        onCodeFound: page.timeToCodeMs = Date.now() - page.activeSince
    }

    VideoOutput {
        anchors.fill: parent
        source: camera
        filters: [ scanner ]
        fillMode: VideoOutput.PreserveAspectCrop
        autoOrientation: true
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Scan again")
                onClicked: page.restart()
            }
        }

        Column {
            id: column

            width: parent.width

            PageHeader {
                title: qsTr("QR scan test")
            }

            Rectangle {
                width: parent.width
                height: details.height + 2 * Theme.paddingMedium
                color: Theme.rgba(Theme.overlayBackgroundColor, 0.7)

                Column {
                    id: details

                    y: Theme.paddingMedium
                    width: parent.width

                    DetailItem { label: qsTr("Status"); value: page.statusText() }
                    DetailItem {
                        visible: scanner.status === FrameScanner.Found
                        label: qsTr("Payload length")
                        value: scanner.payloadLength
                    }
                    DetailItem {
                        visible: page.timeToCodeMs >= 0
                        label: qsTr("Time to code")
                        value: qsTr("%1 ms").arg(page.timeToCodeMs)
                    }
                    DetailItem { label: qsTr("Format"); value: scanner.pixelFormat }
                    DetailItem { label: qsTr("Handle"); value: scanner.handleType }
                    DetailItem {
                        label: qsTr("Size")
                        value: scanner.frameSize.width + " x " + scanner.frameSize.height
                    }
                    DetailItem {
                        label: qsTr("Bytes per line, planes")
                        value: scanner.bytesPerLine + ", " + scanner.planeCount
                    }
                    DetailItem {
                        label: qsTr("Frames per second")
                        value: scanner.framesPerSecond.toFixed(1)
                    }
                    DetailItem {
                        label: qsTr("Decodes")
                        value: qsTr("%1, every %2. frame").arg(scanner.decodeCount).arg(scanner.frameInterval)
                    }
                    DetailItem {
                        label: qsTr("Decode last, mean, max")
                        value: qsTr("%1, %2, %3 ms").arg(scanner.lastDecodeMs)
                                                     .arg(scanner.averageDecodeMs.toFixed(0))
                                                     .arg(scanner.maxDecodeMs)
                    }
                }
            }
        }
    }
}
