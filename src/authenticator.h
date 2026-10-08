#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <memory>

#include "autolock.h"
#include "clipboardguard.h"
#include "corebridge.h"

class FrameScanner;

// Owns the unlocked file and the lock state, and the account waiting to be
// added. QML gets issuers, account names and codes; seeds stay in the Rust
// core.
//
// AutoLock and ClipboardGuard keep their deadlines, which are checked again
// before every access.
//
// An edit changes the file in memory and starts a save at once. While the
// save runs on a pool thread the handle is read-only for everyone, and a
// lock request waits for the save to finish.
class Authenticator : public QObject
{
    Q_OBJECT
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(Error error READ error NOTIFY errorChanged)
    Q_PROPERTY(bool saving READ saving NOTIFY savingChanged)
    Q_PROPERTY(bool dirty READ dirty NOTIFY dirtyChanged)
    Q_PROPERTY(bool hasFile READ hasFile NOTIFY hasFileChanged)
    Q_PROPERTY(int accountCount READ accountCount NOTIFY accountCountChanged)
    Q_PROPERTY(bool hasPending READ hasPending NOTIFY pendingChanged)
    Q_PROPERTY(QString pendingIssuer READ pendingIssuer NOTIFY pendingChanged)
    Q_PROPERTY(QString pendingName READ pendingName NOTIFY pendingChanged)
    Q_PROPERTY(int clipboardClearSeconds READ clipboardClearSeconds CONSTANT)

public:
    enum State {
        Locked,
        Unlocking,
        Unlocked
    };
    Q_ENUM(State)

    enum Error {
        NoError,
        WrongPassword,
        NotKdbx,
        UnsupportedFormat,
        Corrupted,
        TooLarge,
        FileUnreadable,
        FileUnwritable,
        SaveFailed,
        FileExists,
        // Changes that could not be saved were discarded by a lock.
        ChangesDiscarded
    };
    Q_ENUM(Error)

    // Key derivation levels of a new file, as SF_KDF_* in the core.
    enum KdfLevel {
        KdfStandard = SF_KDF_STANDARD,
        KdfHigh = SF_KDF_HIGH,
        KdfMaximum = SF_KDF_MAXIMUM
    };
    Q_ENUM(KdfLevel)

    // Why a scanned code or typed secret is not an account to add.
    enum PendingStatus {
        PendingReady,
        NotOtpauth,
        Hotp,
        UnsupportedType,
        InvalidSecret,
        InvalidSettings
    };
    Q_ENUM(PendingStatus)

    explicit Authenticator(QObject *parent = nullptr);
    ~Authenticator() override;

    static PendingStatus pendingStatus(int coreStatus);

    State state() const;
    Error error() const;
    bool saving() const;
    // Changes in memory that no save has written yet.
    bool dirty() const;
    bool hasFile() const;
    int accountCount() const;
    bool hasPending() const;
    QString pendingIssuer() const;
    QString pendingName() const;
    int clipboardClearSeconds() const;

    // Null when locked, when a lock deadline has passed or while a requested
    // lock waits for a save.
    const SfDatabase *database();
    // The code of an account at now and the seconds left; empty when it has
    // none. Checks no deadline, so a lock cannot happen in between: call
    // database() first.
    QString code(const QByteArray &uuid, qint64 now, uint32_t &remaining) const;

    Q_INVOKABLE void unlock(const QString &password);
    // Creates the file, protected by password with the key derivation
    // kdfLevel, and unlocks it; an existing file is never replaced.
    Q_INVOKABLE void createFile(const QString &password, int kdfLevel);
    Q_INVOKABLE void lock();
    Q_INVOKABLE void clearError();

    Q_INVOKABLE bool copyCode(const QString &accountId);
    Q_INVOKABLE bool rename(const QString &accountId, const QString &issuer, const QString &name);
    // True when deleteAccount would remove the account for good instead of
    // moving it to the recycle bin.
    Q_INVOKABLE bool deletesPermanently(const QString &accountId);
    Q_INVOKABLE bool deleteAccount(const QString &accountId);

    // Makes a typed secret the pending account; returns a PendingStatus.
    Q_INVOKABLE int preparePending(const QString &secret, int algorithm, int digits, int period,
                                   bool steam);
    // Takes the account the scanner found.
    Q_INVOKABLE bool takeScan(FrameScanner *scanner);
    // The pending account's code now, as "code" and "remaining".
    Q_INVOKABLE QVariantMap pendingCode() const;
    Q_INVOKABLE void clearPending();
    // Adds the pending account with the issuer and name the user confirmed.
    Q_INVOKABLE bool addPending(const QString &issuer, const QString &name);

signals:
    void stateChanged();
    void errorChanged();
    void savingChanged();
    void dirtyChanged();
    void hasFileChanged();
    void accountCountChanged();
    void pendingChanged();
    void lockedAutomatically();
    // The accounts changed; lists reload.
    void contentChanged();
    void saveFailed();
    // The file had been changed by another program since it was unlocked;
    // that version is kept in the backups.
    void savedOverChangedFile();

private slots:
    void onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest);
    void onSaveFinished(int attempt, int status, const QByteArray &digest,
                        bool replacedChangedFile);

private:
    // One edit of the file; sets changed when it changed anything.
    using Edit = std::function<int(SfDatabase *database, int64_t now, bool &changed)>;

    // Runs an edit and saves when it changed anything; refused while a save
    // runs or when locked.
    bool change(const Edit &edit);
    int startUnlocking();
    void save();
    void setPending(CorePending pending);
    void updateAccountCount();
    void lockAutomatically();
    // Clears the clipboard and locks when their deadlines have passed.
    void enforceDeadlines();
    void cancelPendingUnlock();
    // A lock requested during a save waits for it.
    enum class PendingLock { None, Manual, Automatic };
    // Does what a lock can do while the save still reads the handle, and
    // leaves the rest to the save's result handler.
    void deferLock(PendingLock kind);
    // Runs a lock requested while saving.
    void resumePendingLock();
    void setState(State state);
    void setError(Error error);
    void setSaving(bool saving);
    void setDirty(bool dirty);
    QString pendingText(uint32_t column) const;
    const SfDatabase *readableDatabase() const;

    CoreDatabase m_database;
    CorePending m_pending;
    int m_attempt = 0;
    std::shared_ptr<std::atomic_bool> m_unlockCancelled;
    State m_state = Locked;
    Error m_error = NoError;
    bool m_saving = false;
    bool m_dirty = false;
    bool m_hasFile = false;
    int m_accountCount = 0;
    PendingLock m_pendingLock = PendingLock::None;
    // SHA-256 of the file as it was unlocked or last saved.
    QByteArray m_fileDigest;
    AutoLock m_autoLock;
    ClipboardGuard m_clipboard;
};

#endif // AUTHENTICATOR_H
