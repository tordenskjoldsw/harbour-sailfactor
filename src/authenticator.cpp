#include "authenticator.h"

#include <QCoreApplication>
#include <QThreadPool>

#include "coretasks.h"
#include "databasefile.h"
#include "databases.h"
#include "framescanner.h"

namespace {

Authenticator::Error errorFor(int status)
{
    switch (status) {
    case SF_OK:
        return Authenticator::NoError;
    case SF_INVALID_CREDENTIALS:
    case SF_INVALID_KEY_FILE:
        return Authenticator::WrongPassword;
    case SF_NOT_KDBX:
        return Authenticator::NotKdbx;
    case SF_UNSUPPORTED_FORMAT:
        return Authenticator::UnsupportedFormat;
    case SF_LIMIT_EXCEEDED:
    case StatusTooLarge:
        return Authenticator::TooLarge;
    case StatusFileUnreadable:
        return Authenticator::FileUnreadable;
    case StatusFileUnwritable:
        return Authenticator::FileUnwritable;
    case StatusFileExists:
        return Authenticator::FileExists;
    case SF_WRITE_FAILED:
    case SF_RANDOM_UNAVAILABLE:
        return Authenticator::SaveFailed;
    default:
        return Authenticator::Corrupted;
    }
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
    m_database.reset();
}

Authenticator::PendingStatus Authenticator::pendingStatus(int coreStatus)
{
    switch (coreStatus) {
    case SF_OK:
        return PendingReady;
    case SF_HOTP:
        return Hotp;
    case SF_UNSUPPORTED_TYPE:
        return UnsupportedType;
    case SF_INVALID_SETTINGS:
        return InvalidSettings;
    case SF_INVALID_SECRET:
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

bool Authenticator::dirty() const
{
    return m_dirty;
}

bool Authenticator::hasFile() const
{
    return m_hasFile;
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
    return pendingText(SF_TEXT_ISSUER);
}

QString Authenticator::pendingName() const
{
    return pendingText(SF_TEXT_NAME);
}

QString Authenticator::pendingText(uint32_t column) const
{
    SfString text = emptyCoreString();
    return m_pending && sf_pending_text(m_pending.get(), column, &text) == SF_OK
        ? takeCoreString(text)
        : QString();
}

int Authenticator::clipboardClearSeconds() const
{
    return ClipboardGuard::ClearAfterSeconds;
}

const SfDatabase *Authenticator::database()
{
    enforceDeadlines();
    return readableDatabase();
}

const SfDatabase *Authenticator::readableDatabase() const
{
    // A requested lock waits for the running save; nothing is read meanwhile.
    return m_pendingLock != PendingLock::None ? nullptr : m_database.get();
}

QString Authenticator::code(const QByteArray &uuid, qint64 now, uint32_t &remaining) const
{
    remaining = 0;
    SfString code = emptyCoreString();
    const SfDatabase *handle = readableDatabase();
    if (!handle || uuid.size() != SF_UUID_LENGTH
        || sf_account_code(handle, bytePointer(uuid), now, &code, &remaining) != SF_OK)
        return QString();
    return takeCoreString(code);
}

void Authenticator::unlock(const QString &password)
{
    if (m_state != Locked || !m_hasFile)
        return;
    const int attempt = startUnlocking();
    // The task owns the only copy of the password bytes and wipes it.
    QThreadPool::globalInstance()->start(
        new UnlockTask(this, m_unlockCancelled, attempt,
                       Databases::databasePath(Databases::DefaultName), password.toUtf8()));
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

int Authenticator::startUnlocking()
{
    setError(NoError);
    setState(Unlocking);
    return ++m_attempt;
}

void Authenticator::onUnlockFinished(int attempt, int status, qulonglong handle,
                                     const QByteArray &digest)
{
    CoreDatabase database(reinterpret_cast<SfDatabase *>(handle));
    if (m_state != Unlocking || attempt != m_attempt)
        return;
    if (status != SF_OK) {
        setError(errorFor(status));
        setState(Locked);
        return;
    }
    m_database = std::move(database);
    m_fileDigest = digest;
    if (!m_hasFile) {
        m_hasFile = true;
        emit hasFileChanged();
    }
    updateAccountCount();
    setState(Unlocked);
    // Starts the deadlines, and locks at once when the app went to the
    // background while the KDF ran and that time is already up.
    m_autoLock.start();
}

void Authenticator::lock()
{
    m_autoLock.stop();
    m_clipboard.clear();
    clearPending();
    if (m_saving) {
        // The save still reads the handle; its result handler locks.
        if (m_pendingLock == PendingLock::None)
            m_pendingLock = PendingLock::Manual;
        return;
    }
    ++m_attempt;
    if (m_state == Unlocking) {
        setState(Locked);
        return;
    }
    if (!m_database)
        return;
    m_database.reset();
    m_fileDigest.clear();
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
    if (m_saving) {
        m_pendingLock = PendingLock::Automatic;
        return;
    }
    lock();
    emit lockedAutomatically();
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
    return !uuid.isEmpty() && change([&](SfDatabase *database, int64_t now, bool &changed) {
        return sf_account_rename(database, bytePointer(uuid), issuerText.data(),
                                 issuerText.size(), nameText.data(), nameText.size(), now,
                                 &changed);
    });
}

bool Authenticator::deletesPermanently(const QString &accountId)
{
    const QByteArray uuid = accountUuid(accountId);
    bool permanent = false;
    const SfDatabase *handle = database();
    return handle && !uuid.isEmpty()
        && sf_account_deletes_permanently(handle, bytePointer(uuid), &permanent) == SF_OK
        && permanent;
}

bool Authenticator::deleteAccount(const QString &accountId)
{
    const QByteArray uuid = accountUuid(accountId);
    return !uuid.isEmpty() && change([&](SfDatabase *database, int64_t now, bool &changed) {
        changed = true;
        bool permanent = false;
        return sf_account_delete(database, bytePointer(uuid), now, &permanent);
    });
}

int Authenticator::preparePending(const QString &secret, int algorithm, int digits, int period,
                                  bool steam)
{
    clearPending();
    if (m_state != Unlocked || digits < 0 || period < 0)
        return InvalidSettings;
    const CoreText secretText(secret);
    SfPending *pending = nullptr;
    const int status = sf_pending_from_secret(
        secretText.data(), secretText.size(), static_cast<uint32_t>(algorithm),
        static_cast<uint32_t>(digits), static_cast<uint32_t>(period),
        steam ? SF_ENCODER_STEAM : SF_ENCODER_DECIMAL, &pending);
    setPending(CorePending(pending));
    return status == SF_INVALID_ARGUMENT ? InvalidSettings : pendingStatus(status);
}

bool Authenticator::takeScan(FrameScanner *scanner)
{
    if (!scanner || m_state != Unlocked)
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
    SfString code = emptyCoreString();
    uint32_t remaining = 0;
    if (m_pending
        && sf_pending_code(m_pending.get(), unixSeconds(), &code, &remaining) == SF_OK) {
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
    const SfPending *pending = m_pending.get();
    const bool added = change([&](SfDatabase *database, int64_t now, bool &changed) {
        changed = true;
        uint8_t uuid[SF_UUID_LENGTH];
        return sf_account_add(database, pending, issuerText.data(), issuerText.size(),
                              nameText.data(), nameText.size(), now, uuid);
    });
    if (added)
        clearPending();
    return added;
}

bool Authenticator::change(const Edit &edit)
{
    if (m_saving || !database())
        return false;
    bool changed = false;
    if (edit(m_database.get(), unixSeconds(), changed) != SF_OK)
        return false;
    if (changed) {
        setDirty(true);
        updateAccountCount();
        emit contentChanged();
        save();
    }
    return true;
}

void Authenticator::save()
{
    if (m_state != Unlocked || m_saving || !m_dirty || !m_database)
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
        if (status == SF_OK) {
            m_fileDigest = digest;
            setDirty(false);
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

void Authenticator::resumePendingLock()
{
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
    SfAccountList *list = nullptr;
    if (m_database && sf_account_list(m_database.get(), &list) == SF_OK) {
        const CoreAccountList accounts(list);
        count = static_cast<int>(sf_account_list_length(accounts.get()));
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
