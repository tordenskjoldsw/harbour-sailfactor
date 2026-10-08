#ifndef FRAMESCANNER_H
#define FRAMESCANNER_H

#include <QAbstractVideoFilter>
#include <QThreadPool>

#include <atomic>

#include "corebridge.h"

// Looks for a QR code with a TOTP account in the camera's viewfinder
// frames. The runnable maps each frame on the render thread and copies its
// brightness; a decode on a worker thread turns it into a pending account
// in the Rust core, and frames that arrive meanwhile are skipped. The QR
// payload never leaves the core. After a find the scanner pauses until
// rearm.
class FrameScanner : public QAbstractVideoFilter
{
    Q_OBJECT
    Q_PROPERTY(bool found READ found NOTIFY foundChanged)
    // The Authenticator::PendingStatus of the last code that is not a TOTP
    // account, PendingReady while none was seen.
    Q_PROPERTY(int rejection READ rejection NOTIFY rejectionChanged)
    Q_PROPERTY(bool unsupportedFrames READ unsupportedFrames NOTIFY unsupportedFramesChanged)

public:
    explicit FrameScanner(QObject *parent = nullptr);
    ~FrameScanner() override;

    QVideoFilterRunnable *createFilterRunnable() override;

    bool found() const;
    int rejection() const;
    bool unsupportedFrames() const;

    // Called on the render thread.
    bool accepting() const;
    void decode(QByteArray luma, int width, int height);

    // The account found, for Authenticator::takeScan.
    CorePending takePending();
    // Scans again after a find.
    Q_INVOKABLE void rearm();

signals:
    void foundChanged();
    void rejectionChanged();
    void unsupportedFramesChanged();
    void codeFound();

private:
    Q_INVOKABLE void onDecoded(int status, qulonglong pending);
    Q_INVOKABLE void onUnsupportedFrame();

    // One decode at a time; the destructor waits for it.
    QThreadPool m_pool;
    std::atomic<bool> m_paused{false};
    std::atomic<bool> m_decoding{false};
    CorePending m_pending;
    int m_rejection = 0;
    bool m_unsupportedFrames = false;
};

#endif // FRAMESCANNER_H
