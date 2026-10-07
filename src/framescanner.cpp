#include "framescanner.h"

#include <QDebug>
#include <QElapsedTimer>
#include <QMetaObject>
#include <QVideoFrame>

#include <cstring>

#include "sailfactor_core.h"

namespace {

const char totpPrefix[] = "otpauth://totp/";
// Reported in place of a core status when a frame cannot be mapped.
const int mapFailed = -1;

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

template <typename T>
QString debugText(T value)
{
    QString text;
    QDebug(&text).nospace().noquote() << value;
    return text;
}

class FrameScannerRunnable : public QVideoFilterRunnable
{
public:
    explicit FrameScannerRunnable(FrameScanner *scanner) : m_scanner(scanner)
    {
        m_fpsTimer.start();
    }

    QVideoFrame run(QVideoFrame *input, const QVideoSurfaceFormat &, RunFlags) override
    {
        countFrame();
        reportFrameInfo(*input);
        if (m_scanner->paused() || ++m_skipped < m_scanner->frameInterval())
            return *input;
        m_skipped = 0;
        scan(input);
        return *input;
    }

private:
    void countFrame()
    {
        ++m_frames;
        const qint64 elapsed = m_fpsTimer.elapsed();
        if (elapsed >= 1000) {
            QMetaObject::invokeMethod(m_scanner, "recordFramesPerSecond", Qt::QueuedConnection,
                                      Q_ARG(qreal, m_frames * 1000.0 / elapsed));
            m_frames = 0;
            m_fpsTimer.restart();
        }
    }

    void reportFrameInfo(const QVideoFrame &frame)
    {
        if (frame.pixelFormat() == m_reportedFormat && frame.size() == m_reportedSize
            && frame.handleType() == m_reportedHandle)
            return;
        m_reportedFormat = frame.pixelFormat();
        m_reportedSize = frame.size();
        m_reportedHandle = frame.handleType();
        // Bytes per line and planes are only known while mapped; scan()
        // reports them again with the real values.
        report(frame, 0, 0);
    }

    void report(const QVideoFrame &frame, int bytesPerLine, int planeCount)
    {
        QMetaObject::invokeMethod(m_scanner, "recordFrameInfo", Qt::QueuedConnection,
                                  Q_ARG(QString, debugText(frame.pixelFormat())),
                                  Q_ARG(QString, debugText(frame.handleType())),
                                  Q_ARG(QSize, frame.size()), Q_ARG(int, bytesPerLine),
                                  Q_ARG(int, planeCount));
    }

    void scan(QVideoFrame *frame)
    {
        LumaLayout layout;
        if (!lumaLayout(frame->pixelFormat(), &layout)) {
            fail(SF_INVALID_ARGUMENT);
            return;
        }
        if (!frame->map(QAbstractVideoBuffer::ReadOnly)) {
            fail(mapFailed);
            return;
        }
        const int bytesPerLine = frame->bytesPerLine(0);
        if (!m_mappedReported) {
            report(*frame, bytesPerLine, frame->planeCount());
            m_mappedReported = true;
        }
        const qint64 planeBytes = qint64(bytesPerLine) * frame->height() - layout.offset;
        SfString payload{nullptr, 0};
        QElapsedTimer timer;
        timer.start();
        const int32_t status = planeBytes > 0
            ? sf_qr_decode(frame->bits(0) + layout.offset, size_t(planeBytes),
                           uint32_t(frame->width()), uint32_t(frame->height()),
                           uint32_t(bytesPerLine), uint32_t(layout.pixelStep), &payload)
            : SF_INVALID_ARGUMENT;
        const int milliseconds = int(timer.elapsed());
        frame->unmap();

        QMetaObject::invokeMethod(m_scanner, "recordDecode", Qt::QueuedConnection,
                                  Q_ARG(int, milliseconds));
        if (status == SF_OK) {
            const bool totpUri = payload.length >= sizeof totpPrefix - 1
                && std::memcmp(payload.data, totpPrefix, sizeof totpPrefix - 1) == 0;
            const int length = int(payload.length);
            sf_string_free(payload);
            QMetaObject::invokeMethod(m_scanner, "recordCode", Qt::QueuedConnection,
                                      Q_ARG(bool, totpUri), Q_ARG(int, length));
        } else if (status != SF_NOT_FOUND) {
            fail(status);
        }
    }

    void fail(int status)
    {
        QMetaObject::invokeMethod(m_scanner, "recordFailure", Qt::QueuedConnection,
                                  Q_ARG(int, status));
    }

    FrameScanner *m_scanner;
    QElapsedTimer m_fpsTimer;
    int m_frames = 0;
    int m_skipped = 0;
    bool m_mappedReported = false;
    QVideoFrame::PixelFormat m_reportedFormat = QVideoFrame::Format_Invalid;
    QSize m_reportedSize;
    QAbstractVideoBuffer::HandleType m_reportedHandle = QAbstractVideoBuffer::NoHandle;
};

} // namespace

FrameScanner::FrameScanner(QObject *parent) : QAbstractVideoFilter(parent) {}

QVideoFilterRunnable *FrameScanner::createFilterRunnable()
{
    return new FrameScannerRunnable(this);
}

void FrameScanner::setFrameInterval(int interval)
{
    interval = qMax(1, interval);
    if (m_frameInterval.exchange(interval) != interval)
        emit frameIntervalChanged();
}

qreal FrameScanner::averageDecodeMs() const
{
    return m_decodeCount > 0 ? qreal(m_totalDecodeMs) / m_decodeCount : 0;
}

void FrameScanner::rearm()
{
    m_decodeCount = 0;
    m_lastDecodeMs = 0;
    m_maxDecodeMs = 0;
    m_totalDecodeMs = 0;
    m_totpUri = false;
    m_payloadLength = 0;
    emit decodeStatsChanged();
    setStatus(Waiting);
    m_paused.store(false);
}

void FrameScanner::recordFrameInfo(const QString &pixelFormat, const QString &handleType,
                                   const QSize &frameSize, int bytesPerLine, int planeCount)
{
    m_pixelFormat = pixelFormat;
    m_handleType = handleType;
    m_frameSize = frameSize;
    if (bytesPerLine > 0) {
        m_bytesPerLine = bytesPerLine;
        m_planeCount = planeCount;
    }
    emit frameInfoChanged();
}

void FrameScanner::recordFramesPerSecond(qreal framesPerSecond)
{
    m_framesPerSecond = framesPerSecond;
    emit framesPerSecondChanged();
}

void FrameScanner::recordDecode(int milliseconds)
{
    if (m_paused.load())
        return;
    ++m_decodeCount;
    m_lastDecodeMs = milliseconds;
    m_maxDecodeMs = qMax(m_maxDecodeMs, milliseconds);
    m_totalDecodeMs += milliseconds;
    emit decodeStatsChanged();
    if (m_status == Waiting)
        setStatus(Scanning);
}

void FrameScanner::recordFailure(int status)
{
    if (status == mapFailed)
        setStatus(Unmappable);
    else if (status == SF_INVALID_ARGUMENT)
        setStatus(UnsupportedFormat);
}

void FrameScanner::recordCode(bool totpUri, int payloadLength)
{
    if (m_paused.exchange(true))
        return;
    m_totpUri = totpUri;
    m_payloadLength = payloadLength;
    setStatus(Found);
    emit codeFound();
}

void FrameScanner::setStatus(Status status)
{
    if (m_status == status)
        return;
    m_status = status;
    emit statusChanged();
}
