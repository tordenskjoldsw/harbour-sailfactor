#ifndef CLIPBOARDGUARD_H
#define CLIPBOARDGUARD_H

#include <QObject>
#include <QString>
#include <QTimer>

#include <functional>

// Puts a value on the clipboard and removes it again after a deadline, on
// lock and on exit, but only while the clipboard still holds that value.
// The deadline is measured on CLOCK_BOOTTIME and checked by a watchdog and
// when the app becomes active, because Qt timers stop while the phone
// sleeps.
// To compare, it asks the source for the value again.
class ClipboardGuard : public QObject
{
    Q_OBJECT

public:
    using ValueSource = std::function<QString()>;
    static const int ClearAfterSeconds = 30;

    explicit ClipboardGuard(QObject *parent = nullptr);

    void copy(const QString &text, ValueSource source);
    void clear();
    // Clears the clipboard once the deadline has passed, counting sleep time.
    void enforceDeadline();

private:
    ValueSource m_source;
    long long m_deadlineMs = 0;
    QTimer m_watchdog;
};

#endif // CLIPBOARDGUARD_H
