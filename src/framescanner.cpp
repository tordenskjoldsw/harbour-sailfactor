#include "framescanner.h"

#include <QCoreApplication>
#include <QMetaObject>
#include <QRunnable>
#include <QVideoFrame>

#include <cstring>

#include "authenticator.h"

namespace {

// Where the brightness of the first pixel sits and how far apart pixels
// are. For 32-bit RGB the green channel stands in for luma, which is
// enough to tell the dark from the light modules.
struct LumaLayout {
    int offset;
    int pixelStep;
};

bool lumaLayout(QVideoFrame::PixelFormat format, LumaLayout *layout)
{
    switch (format) {
    case QVideoFrame::Format_NV12:
    case QVideoFrame::Format_NV21:
    case QVideoFrame::Format_YUV420P:
    case QVideoFrame::Format_YV12:
    case QVideoFrame::Format_IMC1:
    case QVideoFrame::Format_IMC2:
    case QVideoFrame::Format_IMC3:
    case QVideoFrame::Format_IMC4:
    case QVideoFrame::Format_Y8:
        *layout = {0, 1};
        return true;
    case QVideoFrame::Format_YUYV:
        *layout = {0, 2};
        return true;
    case QVideoFrame::Format_UYVY:
        *layout = {1, 2};
        return true;
    // 0xAARRGGBB words: green is the second byte in memory on a
    // little-endian CPU.
    case QVideoFrame::Format_ARGB32:
    case QVideoFrame::Format_ARGB32_Premultiplied:
    case QVideoFrame::Format_RGB32:
        *layout = {1, 4};
        return true;
    // 0xBBGGRRAA words: green is the third byte.
    case QVideoFrame::Format_BGRA32:
    case QVideoFrame::Format_BGRA32_Premultiplied:
    case QVideoFrame::Format_BGR32:
        *layout = {2, 4};
        return true;
    default:
        return false;
    }
}

// Copies the brightness of the frame's central square into one byte per
// pixel, so the frame can be unmapped before the slow decode. The square is
// where the guide on the scan page sits: decoding it at full resolution
// finds codes from farther away than the whole frame scaled down would,
// for the same decode time.
bool copyCentralLuma(const QVideoFrame &frame, QByteArray &luma, int &side)
{
    LumaLayout layout;
    if (!lumaLayout(frame.pixelFormat(), &layout))
        return false;
    const int width = frame.width();
    const int height = frame.height();
    const int stride = frame.bytesPerLine(0);
    if (width <= 0 || height <= 0 || stride < (width - 1) * layout.pixelStep + layout.offset + 1)
        return false;
    side = qMin(width, height);
    const int left = (width - side) / 2;
    const int top = (height - side) / 2;
    luma = QByteArray(side * side, Qt::Uninitialized);
    const uchar *source = frame.bits(0) + layout.offset + qint64(left) * layout.pixelStep;
    char *target = luma.data();
    for (int y = 0; y < side; ++y) {
        const uchar *row = source + qint64(top + y) * stride;
        char *out = target + qint64(y) * side;
        if (layout.pixelStep == 1) {
            std::memcpy(out, row, static_cast<size_t>(side));
        } else {
            for (int x = 0; x < side; ++x)
                out[x] = static_cast<char>(row[x * layout.pixelStep]);
        }
    }
    return true;
}

class DecodeTask : public QRunnable
{
public:
    DecodeTask(FrameScanner *scanner, QByteArray luma, int width, int height)
        : m_scanner(scanner), m_luma(std::move(luma)), m_width(width), m_height(height)
    {
    }

    ~DecodeTask() override { secureWipe(m_luma); }

    void run() override
    {
        SfPending *found = nullptr;
        const int status = sf_pending_from_frame(
            bytePointer(m_luma), static_cast<size_t>(m_luma.size()), uint32_t(m_width),
            uint32_t(m_height), uint32_t(m_width), 1, &found);
        CorePending pending(found);
        // The frame shows the code, secret included.
        secureWipe(m_luma);
        // The scanner waits for this task in its destructor and delivers
        // what was posted, so the pending account is always freed.
        if (QMetaObject::invokeMethod(m_scanner, "onDecoded", Qt::QueuedConnection,
                                      Q_ARG(int, status),
                                      Q_ARG(qulonglong, reinterpret_cast<qulonglong>(pending.get()))))
            pending.release();
    }

private:
    FrameScanner *m_scanner;
    QByteArray m_luma;
    int m_width;
    int m_height;
};

class FrameScannerRunnable : public QVideoFilterRunnable
{
public:
    explicit FrameScannerRunnable(FrameScanner *scanner) : m_scanner(scanner) {}

    QVideoFrame run(QVideoFrame *input, const QVideoSurfaceFormat &, RunFlags) override
    {
        if (!m_scanner->accepting() || !input->map(QAbstractVideoBuffer::ReadOnly))
            return *input;
        QByteArray luma;
        int side = 0;
        const bool copied = copyCentralLuma(*input, luma, side);
        input->unmap();
        if (copied)
            m_scanner->decode(std::move(luma), side, side);
        else
            QMetaObject::invokeMethod(m_scanner, "onUnsupportedFrame", Qt::QueuedConnection);
        return *input;
    }

private:
    FrameScanner *m_scanner;
};

} // namespace

FrameScanner::FrameScanner(QObject *parent)
    : QAbstractVideoFilter(parent)
{
    m_pool.setMaxThreadCount(1);
}

FrameScanner::~FrameScanner()
{
    m_paused.store(true);
    m_pool.waitForDone();
    // Delivers a result the last decode posted, which frees its account.
    QCoreApplication::sendPostedEvents(this, QEvent::MetaCall);
}

QVideoFilterRunnable *FrameScanner::createFilterRunnable()
{
    return new FrameScannerRunnable(this);
}

bool FrameScanner::found() const
{
    return static_cast<bool>(m_pending);
}

int FrameScanner::rejection() const
{
    return m_rejection;
}

bool FrameScanner::unsupportedFrames() const
{
    return m_unsupportedFrames;
}

bool FrameScanner::accepting() const
{
    return !m_paused.load() && !m_decoding.load();
}

void FrameScanner::decode(QByteArray luma, int width, int height)
{
    if (m_decoding.exchange(true))
        return;
    m_pool.start(new DecodeTask(this, std::move(luma), width, height));
}

CorePending FrameScanner::takePending()
{
    CorePending pending = std::move(m_pending);
    if (pending)
        emit foundChanged();
    return pending;
}

void FrameScanner::rearm()
{
    m_pending.reset();
    if (m_rejection != Authenticator::PendingReady) {
        m_rejection = Authenticator::PendingReady;
        emit rejectionChanged();
    }
    emit foundChanged();
    m_paused.store(false);
}

void FrameScanner::onDecoded(int status, qulonglong pending)
{
    CorePending account(reinterpret_cast<SfPending *>(pending));
    m_decoding.store(false);
    if (m_paused.load() || status == SF_NOT_FOUND || status == SF_CORRUPTED)
        return;
    const int rejection = Authenticator::pendingStatus(status);
    if (rejection != Authenticator::PendingReady) {
        // Scanning goes on: the next code in view may be the right one.
        if (m_rejection != rejection) {
            m_rejection = rejection;
            emit rejectionChanged();
        }
        return;
    }
    m_paused.store(true);
    m_pending = std::move(account);
    emit foundChanged();
    emit codeFound();
}

void FrameScanner::onUnsupportedFrame()
{
    if (m_unsupportedFrames)
        return;
    m_unsupportedFrames = true;
    emit unsupportedFramesChanged();
}
