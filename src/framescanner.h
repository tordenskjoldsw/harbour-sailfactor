#ifndef FRAMESCANNER_H
#define FRAMESCANNER_H

#include <QAbstractVideoFilter>
#include <QThreadPool>

#include <atomic>

#include "corebridge.h"

// Looks for a QR code with a TOTP account in the camera's viewfinder
// frames, or, in import mode, for the export codes of another app. The
// runnable maps each frame on the render thread and copies the brightness
// of its central square; a decode on a worker thread turns it into a
// pending account or adds it to the import in the Rust core, and frames
// that arrive meanwhile are skipped. The QR payload never leaves the core.
// After a find, or once every export code is in, the scanner pauses until
// rearm.
class FrameScanner : public QAbstractVideoFilter
{
    Q_OBJECT
    Q_PROPERTY(bool found READ found NOTIFY foundChanged)
    // The Authenticator::PendingStatus of the last code that is not what
    // the scanner looks for, PendingReady while none was seen.
    Q_PROPERTY(int rejection READ rejection NOTIFY rejectionChanged)
    Q_PROPERTY(bool unsupportedFrames READ unsupportedFrames NOTIFY unsupportedFramesChanged)
    // Set before the camera starts; collects export codes instead of
    // looking for one account.
    Q_PROPERTY(bool importMode READ importMode WRITE setImportMode NOTIFY importModeChanged)
    // Export codes scanned and codes in the export, 0 before the first.
    Q_PROPERTY(int scanned READ scanned NOTIFY progressChanged)
    Q_PROPERTY(int exportSize READ exportSize NOTIFY progressChanged)

public:
    explicit FrameScanner(QObject *parent = nullptr);
    ~FrameScanner() override;

    QVideoFilterRunnable *createFilterRunnable() override;

    bool found() const;
    int rejection() const;
    bool unsupportedFrames() const;
    bool importMode() const;
    void setImportMode(bool importMode);
    int scanned() const;
    int exportSize() const;

    // Called on the render thread.
    bool accepting() const;
    void decode(QByteArray luma, int width, int height);

    // The account found, for Authenticator::takeScan.
    CorePending takePending();
    // The complete import, for Authenticator::takeImport; null before.
    CoreImport takeImport();
    // Scans again after a find.
    Q_INVOKABLE void rearm();

signals:
    void foundChanged();
    void rejectionChanged();
    void unsupportedFramesChanged();
    void importModeChanged();
    void progressChanged();
    void codeFound();
    // An export code of another app came into view in account mode.
    void exportCodeFound();
    void importComplete();

private:
    Q_INVOKABLE void onDecoded(int status, qulonglong pending);
    Q_INVOKABLE void onImportDecoded(int status, int scanned, int size);
    Q_INVOKABLE void onUnsupportedFrame();
    void setRejection(int rejection);

    // One decode at a time; the destructor waits for it.
    QThreadPool m_pool;
    std::atomic<bool> m_paused{false};
    std::atomic<bool> m_decoding{false};
    CorePending m_pending;
    // Only a decode task touches it while scanning; the main thread takes
    // it once complete, when the scanner is paused.
    CoreImport m_import;
    // The import the render thread hands to decode tasks; null in account
    // mode and once the import is taken.
    std::atomic<StImport *> m_activeImport{nullptr};
    bool m_importMode = false;
    bool m_importComplete = false;
    int m_scanned = 0;
    int m_exportSize = 0;
    int m_rejection = 0;
    bool m_unsupportedFrames = false;
};

#endif // FRAMESCANNER_H
