#ifndef FRAMESCANNER_H
#define FRAMESCANNER_H

#include <QAbstractVideoFilter>
#include <QSize>
#include <QString>

#include <atomic>

// Looks for a QR code in the camera's viewfinder frames. The runnable maps
// each frame on the render thread and hands its luma to the Rust core; the
// results reach this object as queued calls. The payload never leaves C++:
// QML learns only whether a TOTP URI was found and how long it is.
class FrameScanner : public QAbstractVideoFilter
{
    Q_OBJECT
    Q_PROPERTY(int frameInterval READ frameInterval WRITE setFrameInterval NOTIFY frameIntervalChanged)
    Q_PROPERTY(Status status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString pixelFormat READ pixelFormat NOTIFY frameInfoChanged)
    Q_PROPERTY(QString handleType READ handleType NOTIFY frameInfoChanged)
    Q_PROPERTY(QSize frameSize READ frameSize NOTIFY frameInfoChanged)
    Q_PROPERTY(int bytesPerLine READ bytesPerLine NOTIFY frameInfoChanged)
    Q_PROPERTY(int planeCount READ planeCount NOTIFY frameInfoChanged)
    Q_PROPERTY(qreal framesPerSecond READ framesPerSecond NOTIFY framesPerSecondChanged)
    Q_PROPERTY(int decodeCount READ decodeCount NOTIFY decodeStatsChanged)
    Q_PROPERTY(int lastDecodeMs READ lastDecodeMs NOTIFY decodeStatsChanged)
    Q_PROPERTY(int maxDecodeMs READ maxDecodeMs NOTIFY decodeStatsChanged)
    Q_PROPERTY(qreal averageDecodeMs READ averageDecodeMs NOTIFY decodeStatsChanged)
    Q_PROPERTY(bool totpUri READ totpUri NOTIFY statusChanged)
    Q_PROPERTY(int payloadLength READ payloadLength NOTIFY statusChanged)

public:
    enum Status { Waiting, Scanning, Found, Unmappable, UnsupportedFormat };
    Q_ENUM(Status)

    explicit FrameScanner(QObject *parent = nullptr);

    QVideoFilterRunnable *createFilterRunnable() override;

    int frameInterval() const { return m_frameInterval.load(); }
    void setFrameInterval(int interval);
    Status status() const { return m_status; }
    QString pixelFormat() const { return m_pixelFormat; }
    QString handleType() const { return m_handleType; }
    QSize frameSize() const { return m_frameSize; }
    int bytesPerLine() const { return m_bytesPerLine; }
    int planeCount() const { return m_planeCount; }
    qreal framesPerSecond() const { return m_framesPerSecond; }
    int decodeCount() const { return m_decodeCount; }
    int lastDecodeMs() const { return m_lastDecodeMs; }
    int maxDecodeMs() const { return m_maxDecodeMs; }
    qreal averageDecodeMs() const;
    bool totpUri() const { return m_totpUri; }
    int payloadLength() const { return m_payloadLength; }

    bool paused() const { return m_paused.load(); }

    // Resumes scanning after a code was found and resets the statistics.
    Q_INVOKABLE void rearm();

    // Queued from the render thread.
    Q_INVOKABLE void recordFrameInfo(const QString &pixelFormat, const QString &handleType,
                                     const QSize &frameSize, int bytesPerLine, int planeCount);
    Q_INVOKABLE void recordFramesPerSecond(qreal framesPerSecond);
    Q_INVOKABLE void recordDecode(int milliseconds);
    Q_INVOKABLE void recordFailure(int status);
    Q_INVOKABLE void recordCode(bool totpUri, int payloadLength);

signals:
    void frameIntervalChanged();
    void statusChanged();
    void frameInfoChanged();
    void framesPerSecondChanged();
    void decodeStatsChanged();
    void codeFound();

private:
    void setStatus(Status status);

    std::atomic<int> m_frameInterval{4};
    std::atomic<bool> m_paused{false};
    Status m_status = Waiting;
    QString m_pixelFormat;
    QString m_handleType;
    QSize m_frameSize;
    int m_bytesPerLine = 0;
    int m_planeCount = 0;
    qreal m_framesPerSecond = 0;
    int m_decodeCount = 0;
    int m_lastDecodeMs = 0;
    int m_maxDecodeMs = 0;
    qint64 m_totalDecodeMs = 0;
    bool m_totpUri = false;
    int m_payloadLength = 0;
};

#endif // FRAMESCANNER_H
