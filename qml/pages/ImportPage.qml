import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailtoken 1.0
import "../components"

// Scans the export codes another app shows on its screen, one after the
// other in any order, until the export is complete; then the dialog lists
// the accounts to add. No code or secret reaches QML.
Page {
    id: page

    function rejectionText(rejection) {
        switch (rejection) {
        case Authenticator.NotExport: return qsTr("This is no export code. In Google Authenticator, choose Transfer accounts, then Export accounts.")
        case Authenticator.OtherExport: return qsTr("This code belongs to another export. Scan the codes of one export.")
        case Authenticator.UnreadableExport: return qsTr("SailToken cannot read this export code")
        default: return ""
        }
    }

    allowedOrientations: Orientation.Portrait

    FrameScanner {
        id: scanner

        importMode: true
        onImportComplete: {
            if (authenticator.takeImport(scanner))
                pageStack.replace(Qt.resolvedUrl("ImportDialog.qml"), { "fromGoogle": true })
        }
    }

    QrCamera {
        active: page.status === PageStatus.Active
                && Qt.application.state === Qt.ApplicationActive
        scanner: scanner
        title: qsTr("Import accounts")
        hintIsError: scanner.rejection !== Authenticator.PendingReady || scanner.unsupportedFrames
        hint: scanner.unsupportedFrames ? qsTr("The camera delivers frames SailToken cannot read")
            : scanner.rejection !== Authenticator.PendingReady ? page.rejectionText(scanner.rejection)
            : scanner.exportSize > 0 ? qsTr("Code %1 of %2 scanned. Show the next code of the export.")
                                       .arg(scanner.scanned).arg(scanner.exportSize)
            : qsTr("Show the export code of the other app inside the frame. Tap to focus.")
    }
}
