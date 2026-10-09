#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <memory>

#include "autolock.h"
#include "clipboardguard.h"
#include "corebridge.h"

class FrameScanner;
class MergeTask;

// Owns the unlocked file and the lock state, and the account waiting to be
// added. QML gets issuers, account names and codes; seeds stay in the Rust
// core.
//
// AutoLock and ClipboardGuard keep their deadlines, which are checked again
// before every access.
//
// An edit changes the file in memory and starts a save at once. While a
// save or the opening of a copy to merge runs on a pool thread the handle
// is read-only for everyone, and a lock request waits for it to finish.
class Authenticator : public QObject
{
    Q_OBJECT
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(Error error READ error NOTIFY errorChanged)
    Q_PROPERTY(bool saving READ saving NOTIFY savingChanged)
    Q_PROPERTY(bool merging READ merging NOTIFY mergingChanged)
    Q_PROPERTY(bool dirty READ dirty NOTIFY dirtyChanged)
    Q_PROPERTY(bool hasFile READ hasFile NOTIFY hasFileChanged)
    Q_PROPERTY(bool hasKeyFile READ hasKeyFile NOTIFY hasFileChanged)
    Q_PROPERTY(QString sourcePath READ sourcePath WRITE setSourcePath NOTIFY sourcePathChanged)
    Q_PROPERTY(QString sourceKeyFilePath READ sourceKeyFilePath WRITE setSourceKeyFilePath NOTIFY sourceKeyFilePathChanged)
    Q_PROPERTY(bool sourceFromKdbx3 READ sourceFromKdbx3 NOTIFY sourcePathChanged)
    Q_PROPERTY(QStringList addedOriginals READ addedOriginals NOTIFY addedOriginalsChanged)
    Q_PROPERTY(int accountCount READ accountCount NOTIFY accountCountChanged)
    // Entries and groups in the file's recycle bin, where deleted accounts
    // keep their secrets until it is emptied.
    Q_PROPERTY(int recycleBinItems READ recycleBinItems NOTIFY recycleBinItemsChanged)
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
        InvalidKeyFile,
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
    bool merging() const;
    // A save or a merge is running; edits wait.
    bool busy() const;
    // Changes in memory that no save has written yet.
    bool dirty() const;
    // The one file the app keeps (see Databases) exists, and has a key file.
    bool hasFile() const;
    bool hasKeyFile() const;
    // A file and key file outside the app that addFile stores.
    QString sourcePath() const;
    void setSourcePath(const QString &path);
    QString sourceKeyFilePath() const;
    void setSourceKeyFilePath(const QString &path);
    // The source is a KDBX 3.1 file, which addFile stores as KDBX 4.
    bool sourceFromKdbx3() const;
    // The source files of the file added by the last unlock, until it locks.
    QStringList addedOriginals() const;
    int accountCount() const;
    int recycleBinItems() const;
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
    // Unlocks the source files and stores copies as the app's file, only
    // while it has none; an existing file is never replaced. A KDBX 3.1
    // source is stored as KDBX 4 with the key derivation kdfLevel. Refused
    // without a password: the stored key file sits next to the stored file,
    // so only the password protects it.
    Q_INVOKABLE void addFile(const QString &password, int kdfLevel);
    // Creates the app's file, protected by password with the key derivation
    // kdfLevel, and unlocks it; an existing file is never replaced.
    Q_INVOKABLE void createFile(const QString &password, int kdfLevel);
    // Deletes the addedOriginals, and nothing else.
    Q_INVOKABLE bool removeAddedOriginals();
    // Locks and deletes the app's file with its key file and backups. Only
    // while unlocked, so nobody deletes the accounts without the password,
    // and refused while a save runs.
    Q_INVOKABLE bool removeFile();
    Q_INVOKABLE void lock();
    Q_INVOKABLE void clearError();

    Q_INVOKABLE bool copyCode(const QString &accountId);
    Q_INVOKABLE bool rename(const QString &accountId, const QString &issuer, const QString &name);
    // True when deleteAccount would remove the account for good instead of
    // moving it to the recycle bin.
    Q_INVOKABLE bool deletesPermanently(const QString &accountId);
    Q_INVOKABLE bool deleteAccount(const QString &accountId);
    // Moves the account in front of beforeId, or to the end when beforeId is
    // empty, and saves; the order is SailFactor's own, stored in the file.
    Q_INVOKABLE bool moveAccount(const QString &accountId, const QString &beforeId);
    // Removes the recycle bin's content for good and saves; the sync then
    // removes it on the other copies too.
    Q_INVOKABLE bool emptyRecycleBin();

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

    // Merges another copy of the file, such as the one from the computer,
    // opened with the credentials this file was unlocked with, and saves.
    // Reports mergeFinished, mergeNeedsPassword or mergeFailed.
    Q_INVOKABLE void mergeFile(const QString &path);
    // The same with the copy's own credentials: password, empty for none,
    // and the key file at keyFilePath, or the stored one of this file.
    Q_INVOKABLE void mergeFileWith(const QString &path, const QString &password,
                                   const QString &keyFilePath, bool useStoredKeyFile);
    // Deletes the file the last merge read, and nothing else.
    Q_INVOKABLE bool removeMergedFile();
    // A copy to merge that holds passwords without a one-time code waits
    // for one of these after mergeNeedsConfirmation; a lock drops it.
    Q_INVOKABLE void confirmMerge();
    Q_INVOKABLE void cancelMerge();
    // The open file's accounts with a password, as "withoutCode" (warned
    // about) and "withCode" (the usual KeePassXC login entry, only counted).
    Q_INVOKABLE QVariantMap passwordCounts();

    // For the sync: merges a downloaded copy, opened with the held
    // credentials, and saves; reports syncMergeFinished or syncMergeFailed.
    // Refused while busy.
    bool mergeData(const QByteArray &data);
    // SHA-256 of the file as unlocked or last saved.
    QByteArray fileDigest() const;
    // One SF_SYNC_* setting as UTF-8, empty without a sync entry. The caller
    // wipes it.
    QByteArray syncSetting(uint32_t setting);
    // Stores the sync settings in the file's sync entry and saves.
    bool storeSyncSettings(const QString &server, const QString &loginName,
                           const QByteArray &appPassword, const QString &path,
                           const QByteArray &certificate);

signals:
    void stateChanged();
    void errorChanged();
    void savingChanged();
    void mergingChanged();
    // Counted in accounts, not in entries and groups as the core counts.
    void mergeFinished(int newAccounts, int removedAccounts, bool changed);
    void mergeNeedsPassword();
    // The copy holds withoutCode passwords without a one-time code and
    // withCode passwords next to one; confirmMerge or cancelMerge decides.
    void mergeNeedsConfirmation(int withoutCode, int withCode);
    void mergeFailed(int error);
    void syncMergeFinished(bool changed);
    void syncMergeFailed(int error);
    // A save wrote the file.
    void saved();
    void dirtyChanged();
    void hasFileChanged();
    void sourcePathChanged();
    void sourceKeyFilePathChanged();
    void addedOriginalsChanged();
    void accountCountChanged();
    void recycleBinItemsChanged();
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
    void onMergeOpened(int attempt, int status, qulonglong handle);

private:
    // One edit of the file; sets changed when it changed anything.
    using Edit = std::function<int(SfDatabase *database, int64_t now, bool &changed)>;

    // Runs an edit and saves when it changed anything; refused while a save
    // runs or when locked.
    bool change(const Edit &edit);
    int startUnlocking(const QStringList &sources = QStringList());
    void save();
    void setPending(CorePending pending);
    // Also updates recycleBinItems.
    void updateAccountCount();
    void lockAutomatically();
    // Clears the clipboard and locks when their deadlines have passed.
    void enforceDeadlines();
    void cancelPendingUnlock();
    // A lock requested while busy waits for the task.
    enum class PendingLock { None, Manual, Automatic };
    // Does what a lock can do while a task still reads the handle, and
    // leaves the rest to the task's result handler.
    void deferLock(PendingLock kind);
    // Runs a lock requested while busy.
    void resumePendingLock();
    void setState(State state);
    void setError(Error error);
    void setSaving(bool saving);
    void setMerging(bool merging);
    void startMerge(const QString &path, MergeTask *task);
    // Merges the copy the user chose into the file and saves.
    void mergeChosenCopy(CoreDatabase source);
    // Marks an in-memory change and starts its save.
    void commitChange();
    void setDirty(bool dirty);
    QString pendingText(uint32_t column) const;
    const SfDatabase *readableDatabase() const;
    void setAddedOriginals(const QStringList &paths);
    void clearSource();
    void updateHasFile();

    CoreDatabase m_database;
    CorePending m_pending;
    int m_attempt = 0;
    std::shared_ptr<std::atomic_bool> m_unlockCancelled;
    State m_state = Locked;
    Error m_error = NoError;
    bool m_saving = false;
    bool m_merging = false;
    QString m_mergePath;
    bool m_mergeForSync = false;
    // The file the last merge read, until it is deleted or the app locks.
    QString m_mergedPath;
    // A copy waiting for the user to confirm its passwords.
    CoreDatabase m_mergeSource;
    bool m_dirty = false;
    bool m_hasFile = false;
    // The source files of the add that runs.
    QStringList m_unlockingSources;
    QStringList m_addedOriginals;
    QString m_sourcePath;
    bool m_sourceFromKdbx3 = false;
    QString m_sourceKeyFilePath;
    int m_accountCount = 0;
    int m_recycleBinItems = 0;
    PendingLock m_pendingLock = PendingLock::None;
    // SHA-256 of the file as it was unlocked or last saved.
    QByteArray m_fileDigest;
    AutoLock m_autoLock;
    ClipboardGuard m_clipboard;
};

#endif // AUTHENTICATOR_H
