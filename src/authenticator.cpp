#include "authenticator.h"

#include <QCoreApplication>
#include <QFile>
#include <QThreadPool>

#include "coretasks.h"
#include "databasefile.h"
#include "databases.h"
#include "framescanner.h"

namespace {

Authenticator::Error errorFor(int status)
{
    switch (status) {
    case ST_OK:
        return Authenticator::NoError;
    case ST_INVALID_CREDENTIALS:
        return Authenticator::WrongPassword;
    case ST_INVALID_KEY_FILE:
        return Authenticator::InvalidKeyFile;
    case ST_NOT_KDBX:
        return Authenticator::NotKdbx;
    case ST_UNSUPPORTED_FORMAT:
        return Authenticator::UnsupportedFormat;
    case ST_LIMIT_EXCEEDED:
    case StatusTooLarge:
        return Authenticator::TooLarge;
    case StatusFileUnreadable:
        return Authenticator::FileUnreadable;
    case StatusFileUnwritable:
        return Authenticator::FileUnwritable;
    case StatusFileExists:
        return Authenticator::FileExists;
    case ST_WRITE_FAILED:
    case ST_RANDOM_UNAVAILABLE:
        return Authenticator::SaveFailed;
    default:
        return Authenticator::Corrupted;
    }
}

bool isKdbx3File(const QString &path)
{
    QByteArray start;
    uint16_t major = 0;
    uint16_t minor = 0;
    return readFileStart(path, 12, start) == ST_OK
        && st_kdbx_version(bytePointer(start), static_cast<size_t>(start.size()), &major, &minor)
               == ST_OK
        && major == 3;
}

struct PasswordCounts {
    int withoutCode = 0;
    int withCode = 0;
};

// Counts the accounts with a password; the sync entry is not an account.
PasswordCounts passwordCountsOf(const StDatabase *database)
{
    PasswordCounts counts;
    StAccountList *found = nullptr;
    if (!database || st_account_list(database, &found) != ST_OK)
        return counts;
    const CoreAccountList list(found);
    for (size_t index = 0; index < st_account_list_length(list.get()); ++index) {
        bool hasPassword = false;
        uint32_t kind = 0, digits = 0, period = 0, encoder = 0;
        if (st_account_list_has_password(list.get(), index, &hasPassword) != ST_OK || !hasPassword
            || st_account_list_kind(list.get(), index, &kind, &digits, &period, &encoder) != ST_OK)
            continue;
        if (kind == ST_KIND_NO_CODE)
            ++counts.withoutCode;
        else
            ++counts.withCode;
    }
    return counts;
}

bool isKdfLevel(int level)
{
    return level == Authenticator::KdfStandard || level == Authenticator::KdfHigh
        || level == Authenticator::KdfMaximum;
}

// UTF-8 for the core, wiped when it goes out of scope. The QString it came
// from cannot be wiped (see the threat model).
class CoreText
{
public:
    explicit CoreText(const QString &text) : m_bytes(text.toUtf8()) {}
    CoreText(const CoreText &) = delete;
    CoreText &operator=(const CoreText &) = delete;
    ~CoreText() { secureWipe(m_bytes); }

    const uint8_t *data() const { return bytePointer(m_bytes); }
    size_t size() const { return static_cast<size_t>(m_bytes.size()); }

private:
    QByteArray m_bytes;
};

} // namespace

Authenticator::Authenticator(QObject *parent)
    : QObject(parent)
    , m_unlockCancelled(std::make_shared<std::atomic_bool>(false))
    , m_hasFile(Databases::exists(Databases::DefaultName))
{
    connect(&m_autoLock, &AutoLock::expired, this, &Authenticator::lockAutomatically);
    connect(qApp, &QCoreApplication::aboutToQuit, this, &Authenticator::lock);
}

Authenticator::~Authenticator()
{
    cancelPendingUnlock();
    // A running save finishes writing the file first.
    QThreadPool::globalInstance()->waitForDone();
    // A task may have posted its result before it saw the cancellation;
    // deliver it now so the slot frees or locks the handle.
    QCoreApplication::sendPostedEvents(this, QEvent::MetaCall);
    m_clipboard.clear();
    m_pending.reset();
    m_mergeSource.reset();
    m_database.reset();
}

Authenticator::PendingStatus Authenticator::pendingStatus(int coreStatus)
{
    switch (coreStatus) {
    case ST_OK:
        return PendingReady;
    case ST_HOTP:
        return Hotp;
    case ST_UNSUPPORTED_TYPE:
        return UnsupportedType;
    case ST_INVALID_SETTINGS:
        return InvalidSettings;
    case ST_INVALID_SECRET:
        return InvalidSecret;
    default:
        return NotOtpauth;
    }
}

Authenticator::State Authenticator::state() const
{
    return m_state;
}

Authenticator::Error Authenticator::error() const
{
    return m_error;
}

bool Authenticator::saving() const
{
    return m_saving;
}

bool Authenticator::merging() const
{
    return m_merging;
}

bool Authenticator::busy() const
{
    return m_saving || m_merging;
}

bool Authenticator::dirty() const
{
    return m_dirty;
}

bool Authenticator::hasFile() const
{
    return m_hasFile;
}

bool Authenticator::hasKeyFile() const
{
    return m_hasFile && Databases::hasKeyFile(Databases::DefaultName);
}

QString Authenticator::sourcePath() const
{
    return m_sourcePath;
}

void Authenticator::setSourcePath(const QString &path)
{
    if (m_state != Locked || m_sourcePath == path)
        return;
    m_sourcePath = path;
    m_sourceFromKdbx3 = !path.isEmpty() && isKdbx3File(path);
    setError(NoError);
    emit sourcePathChanged();
}

bool Authenticator::sourceFromKdbx3() const
{
    return m_sourceFromKdbx3;
}

QString Authenticator::sourceKeyFilePath() const
{
    return m_sourceKeyFilePath;
}

void Authenticator::setSourceKeyFilePath(const QString &path)
{
    if (m_state != Locked || m_sourceKeyFilePath == path)
        return;
    m_sourceKeyFilePath = path;
    setError(NoError);
    emit sourceKeyFilePathChanged();
}

QStringList Authenticator::addedOriginals() const
{
    return m_addedOriginals;
}

bool Authenticator::removeAddedOriginals()
{
    bool removed = true;
    for (const QString &path : m_addedOriginals)
        removed = QFile::remove(path) && removed;
    setAddedOriginals(QStringList());
    return removed;
}

bool Authenticator::removeFile()
{
    if (m_state != Unlocked || busy())
        return false;
    lock();
    const QString path = Databases::databasePath(Databases::DefaultName);
    const QString keyFile = Databases::keyFilePath(Databases::DefaultName);
    const bool removed = QFile::remove(path);
    const bool keyFileRemoved = !QFile::exists(keyFile) || QFile::remove(keyFile);
    const bool backupsRemoved = removeBackups(path, Databases::backupDirectory());
    // A failed or interrupted delete stays visible: the file is still there
    // or not, and the page shows what is.
    updateHasFile();
    return removed && keyFileRemoved && backupsRemoved;
}

int Authenticator::accountCount() const
{
    return m_accountCount;
}

bool Authenticator::hasPending() const
{
    return static_cast<bool>(m_pending);
}

QString Authenticator::pendingIssuer() const
{
    return pendingText(ST_TEXT_ISSUER);
}

QString Authenticator::pendingName() const
{
    return pendingText(ST_TEXT_NAME);
}

QString Authenticator::pendingText(uint32_t column) const
{
    StString text = emptyCoreString();
    return m_pending && st_pending_text(m_pending.get(), column, &text) == ST_OK
        ? takeCoreString(text)
        : QString();
}

int Authenticator::recycleBinItems() const
{
    return m_recycleBinItems;
}

int Authenticator::clipboardClearSeconds() const
{
    return ClipboardGuard::ClearAfterSeconds;
}

const StDatabase *Authenticator::database()
{
    enforceDeadlines();
    return readableDatabase();
}

const StDatabase *Authenticator::readableDatabase() const
{
    // A requested lock waits for the running save; nothing is read meanwhile.
    return m_pendingLock != PendingLock::None ? nullptr : m_database.get();
}

QString Authenticator::code(const QByteArray &uuid, qint64 now, uint32_t &remaining) const
{
    remaining = 0;
    StString code = emptyCoreString();
    const StDatabase *handle = readableDatabase();
    if (!handle || uuid.size() != ST_UUID_LENGTH
        || st_account_code(handle, bytePointer(uuid), now, &code, &remaining) != ST_OK)
        return QString();
    return takeCoreString(code);
}

void Authenticator::unlock(const QString &password)
{
    if (m_state != Locked || !m_hasFile)
        return;
    const QString keyFile = hasKeyFile() ? Databases::keyFilePath(Databases::DefaultName)
                                         : QString();
    const int attempt = startUnlocking();
    // The task owns the only copy of the password bytes and wipes it.
    QThreadPool::globalInstance()->start(
        new UnlockTask(this, m_unlockCancelled, attempt,
                       Databases::databasePath(Databases::DefaultName), keyFile,
                       password.toUtf8()));
}

void Authenticator::addFile(const QString &password, int kdfLevel)
{
    if (m_state != Locked || m_hasFile || m_sourcePath.isEmpty() || password.isEmpty()
        || !isKdfLevel(kdfLevel))
        return;
    QStringList sources(m_sourcePath);
    if (!m_sourceKeyFilePath.isEmpty())
        sources.append(m_sourceKeyFilePath);
    const int attempt = startUnlocking(sources);
    QThreadPool::globalInstance()->start(new AddTask(this, m_unlockCancelled, attempt,
                                                     m_sourcePath, m_sourceKeyFilePath,
                                                     Databases::DefaultName, password.toUtf8(),
                                                     static_cast<uint32_t>(kdfLevel)));
}

void Authenticator::createFile(const QString &password, int kdfLevel)
{
    if (m_state != Locked || m_hasFile || password.isEmpty() || !isKdfLevel(kdfLevel))
        return;
    const int attempt = startUnlocking();
    QThreadPool::globalInstance()->start(new CreateTask(this, m_unlockCancelled, attempt,
                                                        Databases::DefaultName, password.toUtf8(),
                                                        static_cast<uint32_t>(kdfLevel)));
}

int Authenticator::startUnlocking(const QStringList &sources)
{
    m_unlockingSources = sources;
    setError(NoError);
    setState(Unlocking);
    return ++m_attempt;
}

void Authenticator::onUnlockFinished(int attempt, int status, qulonglong handle,
                                     const QByteArray &digest)
{
    CoreDatabase database(reinterpret_cast<StDatabase *>(handle));
    if (m_state != Unlocking || attempt != m_attempt)
        return;
    if (status != ST_OK) {
        setError(errorFor(status));
        setState(Locked);
        return;
    }
    m_database = std::move(database);
    m_fileDigest = digest;
    updateHasFile();
    // An added file is stored now.
    clearSource();
    setAddedOriginals(m_unlockingSources);
    updateAccountCount();
    setState(Unlocked);
    // Starts the deadlines; an app that went to the background while the
    // KDF ran gets its background deadline from now.
    m_autoLock.start();
}

void Authenticator::lock()
{
    if (busy()) {
        deferLock(PendingLock::Manual);
        return;
    }
    m_autoLock.stop();
    m_clipboard.clear();
    clearPending();
    ++m_attempt;
    if (m_state == Unlocking) {
        setState(Locked);
        return;
    }
    if (!m_database)
        return;
    m_database.reset();
    m_mergeSource.reset();
    m_fileDigest.clear();
    m_mergedPath.clear();
    setAddedOriginals(QStringList());
    // An earlier save error no longer applies; changes it kept from being
    // written are gone now, which the unlock page reports.
    setError(m_dirty ? ChangesDiscarded : NoError);
    setDirty(false);
    updateAccountCount();
    setState(Locked);
}

void Authenticator::cancelPendingUnlock()
{
    m_unlockCancelled->store(true);
    m_unlockCancelled = std::make_shared<std::atomic_bool>(false);
    ++m_attempt;
}

void Authenticator::clearError()
{
    setError(NoError);
}

void Authenticator::lockAutomatically()
{
    if (m_state != Unlocked)
        return;
    if (busy()) {
        deferLock(PendingLock::Automatic);
        return;
    }
    lock();
    emit lockedAutomatically();
}

void Authenticator::deferLock(PendingLock kind)
{
    m_autoLock.stop();
    m_clipboard.clear();
    clearPending();
    const bool first = m_pendingLock == PendingLock::None;
    // A lock the user asked for is reported as such, even after a deadline
    // passed during the same save.
    if (first || kind == PendingLock::Manual)
        m_pendingLock = kind;
    // Nothing is readable until the lock completes; lists empty now instead
    // of showing the last codes for as long as the save takes.
    if (first)
        emit contentChanged();
}

void Authenticator::enforceDeadlines()
{
    m_clipboard.enforceDeadline();
    m_autoLock.check();
}

bool Authenticator::copyCode(const QString &accountId)
{
    if (!database())
        return false;
    uint32_t remaining = 0;
    const QString value = code(accountUuid(accountId), unixSeconds(), remaining);
    if (value.isEmpty())
        return false;
    // A code changes every period, so the guard compares against the copied
    // value itself; it is worthless once its step has passed.
    m_clipboard.copy(value, [value] { return value; });
    return true;
}

bool Authenticator::rename(const QString &accountId, const QString &issuer, const QString &name)
{
    const QByteArray uuid = accountUuid(accountId);
    const CoreText issuerText(issuer);
    const CoreText nameText(name);
    return !uuid.isEmpty() && change([&](StDatabase *database, int64_t now, bool &changed) {
        return st_account_rename(database, bytePointer(uuid), issuerText.data(),
                                 issuerText.size(), nameText.data(), nameText.size(), now,
                                 &changed);
    });
}

bool Authenticator::deletesPermanently(const QString &accountId)
{
    const QByteArray uuid = accountUuid(accountId);
    bool permanent = false;
    const StDatabase *handle = database();
    return handle && !uuid.isEmpty()
        && st_account_deletes_permanently(handle, bytePointer(uuid), &permanent) == ST_OK
        && permanent;
}

bool Authenticator::deleteAccount(const QString &accountId)
{
    const QByteArray uuid = accountUuid(accountId);
    return !uuid.isEmpty() && change([&](StDatabase *database, int64_t now, bool &changed) {
        changed = true;
        bool permanent = false;
        return st_account_delete(database, bytePointer(uuid), now, &permanent);
    });
}

bool Authenticator::moveAccount(const QString &accountId, const QString &beforeId)
{
    const QByteArray uuid = accountUuid(accountId);
    const QByteArray before = beforeId.isEmpty() ? QByteArray() : accountUuid(beforeId);
    if (uuid.isEmpty() || (!beforeId.isEmpty() && before.isEmpty()))
        return false;
    return change([&](StDatabase *database, int64_t, bool &changed) {
        return st_account_move(database, bytePointer(uuid),
                               before.isEmpty() ? nullptr : bytePointer(before), &changed);
    });
}

bool Authenticator::emptyRecycleBin()
{
    return change([](StDatabase *database, int64_t now, bool &changed) {
        return st_database_empty_recycle_bin(database, now, &changed);
    });
}

int Authenticator::preparePending(const QString &secret, int algorithm, int digits, int period,
                                  bool steam)
{
    clearPending();
    if (!readableDatabase() || digits < 0 || period < 0)
        return InvalidSettings;
    const CoreText secretText(secret);
    StPending *pending = nullptr;
    const int status = st_pending_from_secret(
        secretText.data(), secretText.size(), static_cast<uint32_t>(algorithm),
        static_cast<uint32_t>(digits), static_cast<uint32_t>(period),
        steam ? ST_ENCODER_STEAM : ST_ENCODER_DECIMAL, &pending);
    setPending(CorePending(pending));
    return status == ST_INVALID_ARGUMENT ? InvalidSettings : pendingStatus(status);
}

bool Authenticator::takeScan(FrameScanner *scanner)
{
    if (!scanner || !readableDatabase())
        return false;
    CorePending pending = scanner->takePending();
    if (!pending)
        return false;
    setPending(std::move(pending));
    return true;
}

QVariantMap Authenticator::pendingCode() const
{
    QVariantMap result;
    StString code = emptyCoreString();
    uint32_t remaining = 0;
    if (m_pending
        && st_pending_code(m_pending.get(), unixSeconds(), &code, &remaining) == ST_OK) {
        result.insert(QStringLiteral("code"), takeCoreString(code));
        result.insert(QStringLiteral("remaining"), remaining);
    }
    return result;
}

void Authenticator::clearPending()
{
    setPending(CorePending());
}

void Authenticator::setPending(CorePending pending)
{
    if (!m_pending && !pending)
        return;
    m_pending = std::move(pending);
    emit pendingChanged();
}

bool Authenticator::addPending(const QString &issuer, const QString &name)
{
    if (!m_pending)
        return false;
    const CoreText issuerText(issuer);
    const CoreText nameText(name);
    const StPending *pending = m_pending.get();
    const bool added = change([&](StDatabase *database, int64_t now, bool &changed) {
        changed = true;
        uint8_t uuid[ST_UUID_LENGTH];
        return st_account_add(database, pending, issuerText.data(), issuerText.size(),
                              nameText.data(), nameText.size(), now, uuid);
    });
    if (added)
        clearPending();
    return added;
}

bool Authenticator::change(const Edit &edit)
{
    if (busy() || !database())
        return false;
    bool changed = false;
    if (edit(m_database.get(), unixSeconds(), changed) != ST_OK)
        return false;
    if (changed)
        commitChange();
    return true;
}

void Authenticator::commitChange()
{
    setDirty(true);
    // The save starts before anyone reloads: a lock deadline met during the
    // reload then waits for the save instead of discarding the change.
    save();
    updateAccountCount();
    emit contentChanged();
}

void Authenticator::save()
{
    if (m_state != Unlocked || busy() || !m_dirty || !m_database)
        return;
    setSaving(true);
    QThreadPool::globalInstance()->start(
        new SaveTask(this, m_attempt, m_database.get(),
                     Databases::databasePath(Databases::DefaultName), m_fileDigest));
}

void Authenticator::onSaveFinished(int attempt, int status, const QByteArray &digest,
                                   bool replacedChangedFile)
{
    if (attempt == m_attempt && m_state == Unlocked) {
        if (status == ST_OK) {
            m_fileDigest = digest;
            setDirty(false);
            emit saved();
            if (replacedChangedFile)
                emit savedOverChangedFile();
        } else {
            setError(errorFor(status));
            emit saveFailed();
        }
    }
    setSaving(false);
    resumePendingLock();
}

void Authenticator::mergeFile(const QString &path)
{
    if (busy() || path.isEmpty() || !database())
        return;
    startMerge(path, new MergeTask(this, m_attempt, m_database.get(), path));
}

void Authenticator::mergeFileWith(const QString &path, const QString &password,
                                  const QString &keyFilePath, bool useStoredKeyFile)
{
    const QString keyFile = useStoredKeyFile && hasKeyFile()
        ? Databases::keyFilePath(Databases::DefaultName) : keyFilePath;
    if (busy() || path.isEmpty() || !database() || (password.isEmpty() && keyFile.isEmpty()))
        return;
    startMerge(path, new MergeTask(this, m_attempt, path, password.toUtf8(), keyFile));
}

void Authenticator::startMerge(const QString &path, MergeTask *task)
{
    m_mergeForSync = false;
    m_mergePath = path;
    m_mergedPath.clear();
    setMerging(true);
    QThreadPool::globalInstance()->start(task);
}

bool Authenticator::mergeData(const QByteArray &data)
{
    if (busy() || !database())
        return false;
    m_mergeForSync = true;
    setMerging(true);
    QThreadPool::globalInstance()->start(new MergeTask(this, m_attempt, m_database.get(), data));
    return true;
}

void Authenticator::onMergeOpened(int attempt, int status, qulonglong handle)
{
    CoreDatabase source(reinterpret_cast<StDatabase *>(handle));
    setMerging(false);
    // A lock requested meanwhile wins over the merge.
    if (attempt == m_attempt && m_state == Unlocked && m_pendingLock == PendingLock::None) {
        if (m_mergeForSync) {
            StMergeChanges changes{0, 0, 0, 0, false};
            if (status == ST_OK)
                status = st_database_merge(m_database.get(), source.get(), &changes);
            if (status != ST_OK) {
                emit syncMergeFailed(errorFor(status));
            } else {
                const bool changed = changes.added || changes.modified || changes.moved
                    || changes.deleted || changes.metadata;
                if (changed)
                    commitChange();
                emit syncMergeFinished(changed);
            }
        } else if (status == ST_INVALID_CREDENTIALS) {
            emit mergeNeedsPassword();
        } else if (status != ST_OK) {
            emit mergeFailed(errorFor(status));
        } else {
            // Passwords without a code would land next to the second
            // factor; the user decides first (PLAN.md section 14).
            const PasswordCounts counts = passwordCountsOf(source.get());
            if (counts.withoutCode > 0) {
                m_mergeSource = std::move(source);
                emit mergeNeedsConfirmation(counts.withoutCode, counts.withCode);
            } else {
                mergeChosenCopy(std::move(source));
            }
        }
    }
    source.reset();
    resumePendingLock();
}

void Authenticator::mergeChosenCopy(CoreDatabase source)
{
    updateAccountCount();
    const int before = m_accountCount;
    StMergeChanges changes{0, 0, 0, 0, false};
    const int status = st_database_merge(m_database.get(), source.get(), &changes);
    if (status != ST_OK) {
        emit mergeFailed(errorFor(status));
        return;
    }
    m_mergedPath = m_mergePath;
    const bool changed = changes.added || changes.modified || changes.moved || changes.deleted
        || changes.metadata;
    if (changed)
        commitChange();
    // The core counts entries and groups alike; the page talks of accounts.
    const int after = m_accountCount;
    emit mergeFinished(qMax(0, after - before), qMax(0, before - after), changed);
}

void Authenticator::confirmMerge()
{
    if (!m_mergeSource || busy() || !database())
        return;
    mergeChosenCopy(std::move(m_mergeSource));
}

void Authenticator::cancelMerge()
{
    m_mergeSource.reset();
}

QVariantMap Authenticator::passwordCounts()
{
    const PasswordCounts counts = passwordCountsOf(database());
    QVariantMap result;
    result.insert(QStringLiteral("withoutCode"), counts.withoutCode);
    result.insert(QStringLiteral("withCode"), counts.withCode);
    return result;
}

bool Authenticator::removeMergedFile()
{
    const bool removed = !m_mergedPath.isEmpty() && QFile::remove(m_mergedPath);
    m_mergedPath.clear();
    return removed;
}

QByteArray Authenticator::fileDigest() const
{
    return m_fileDigest;
}

QByteArray Authenticator::syncSetting(uint32_t setting)
{
    const StDatabase *handle = database();
    StString value = emptyCoreString();
    if (!handle || st_database_sync_setting(handle, setting, &value) != ST_OK)
        return QByteArray();
    return takeCoreBytes(value);
}

bool Authenticator::storeSyncSettings(const QString &server, const QString &loginName,
                                      const QByteArray &appPassword, const QString &path,
                                      const QByteArray &certificate)
{
    const QByteArray serverText = server.toUtf8();
    const QByteArray loginText = loginName.toUtf8();
    const QByteArray pathText = path.toUtf8();
    return change([&](StDatabase *database, int64_t now, bool &changed) {
        uint8_t uuid[ST_UUID_LENGTH];
        changed = true;
        return st_database_set_sync_settings(
            database, bytePointer(serverText), static_cast<size_t>(serverText.size()),
            bytePointer(loginText), static_cast<size_t>(loginText.size()),
            bytePointer(appPassword), static_cast<size_t>(appPassword.size()),
            bytePointer(pathText), static_cast<size_t>(pathText.size()),
            bytePointer(certificate), static_cast<size_t>(certificate.size()), now, uuid);
    });
}

void Authenticator::resumePendingLock()
{
    // A save the merge started handles the lock when it finishes.
    if (busy())
        return;
    const PendingLock pending = m_pendingLock;
    m_pendingLock = PendingLock::None;
    switch (pending) {
    case PendingLock::Automatic:
        lockAutomatically();
        break;
    case PendingLock::Manual:
        lock();
        break;
    case PendingLock::None:
        // A deadline that passed during the save has no timer left.
        enforceDeadlines();
        break;
    }
}

void Authenticator::updateAccountCount()
{
    int count = 0;
    StAccountList *list = nullptr;
    if (m_database && st_account_list(m_database.get(), &list) == ST_OK) {
        const CoreAccountList accounts(list);
        count = static_cast<int>(st_account_list_length(accounts.get()));
    }
    size_t binItems = 0;
    if (!m_database || st_database_recycle_bin_items(m_database.get(), &binItems) != ST_OK)
        binItems = 0;
    const int items = static_cast<int>(binItems);
    if (m_recycleBinItems != items) {
        m_recycleBinItems = items;
        emit recycleBinItemsChanged();
    }
    if (m_accountCount == count)
        return;
    m_accountCount = count;
    emit accountCountChanged();
}

void Authenticator::setState(State state)
{
    if (m_state == state)
        return;
    m_state = state;
    emit stateChanged();
}

void Authenticator::setError(Error error)
{
    if (m_error == error)
        return;
    m_error = error;
    emit errorChanged();
}

void Authenticator::setSaving(bool saving)
{
    if (m_saving == saving)
        return;
    m_saving = saving;
    emit savingChanged();
}

void Authenticator::setDirty(bool dirty)
{
    if (m_dirty == dirty)
        return;
    m_dirty = dirty;
    emit dirtyChanged();
}

void Authenticator::setAddedOriginals(const QStringList &paths)
{
    if (m_addedOriginals == paths)
        return;
    m_addedOriginals = paths;
    emit addedOriginalsChanged();
}

void Authenticator::clearSource()
{
    if (!m_sourcePath.isEmpty()) {
        m_sourcePath.clear();
        m_sourceFromKdbx3 = false;
        emit sourcePathChanged();
    }
    if (!m_sourceKeyFilePath.isEmpty()) {
        m_sourceKeyFilePath.clear();
        emit sourceKeyFilePathChanged();
    }
}

void Authenticator::updateHasFile()
{
    const bool hasFile = Databases::exists(Databases::DefaultName);
    if (m_hasFile == hasFile)
        return;
    m_hasFile = hasFile;
    emit hasFileChanged();
}

void Authenticator::setMerging(bool merging)
{
    if (m_merging == merging)
        return;
    m_merging = merging;
    emit mergingChanged();
}
