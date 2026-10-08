#include "coretasks.h"

#include <QMetaObject>

#include "authenticator.h"
#include "corebridge.h"
#include "databasefile.h"
#include "databases.h"

namespace {

int openWith(const QByteArray &data, const QByteArray &password, bool hasPassword,
             SfDatabase **database)
{
    return sf_database_open(bytePointer(data), static_cast<size_t>(data.size()),
                            bytePointer(password), static_cast<size_t>(password.size()),
                            hasPassword, nullptr, 0, database);
}

// Hands the unlocked handle to the authenticator, or frees it when the
// result is no longer wanted. A later save compares the file against
// digest to notice changes by other programs.
void deliver(Authenticator *authenticator, const std::atomic_bool &cancelled, int attempt,
             int status, CoreDatabase database, const QByteArray &digest)
{
    if (status != SF_OK)
        database.reset();
    const bool delivered = !cancelled
        && QMetaObject::invokeMethod(authenticator, "onUnlockFinished", Qt::QueuedConnection,
                                     Q_ARG(int, attempt), Q_ARG(int, status),
                                     Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database.get())),
                                     Q_ARG(QByteArray, status == SF_OK ? digest : QByteArray()));
    if (delivered)
        database.release();
}

} // namespace

UnlockTask::UnlockTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
                       int attempt, const QString &databasePath, QByteArray password)
    : m_authenticator(authenticator)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_databasePath(databasePath)
    , m_password(std::move(password))
{
}

UnlockTask::~UnlockTask()
{
    secureWipe(m_password);
}

void UnlockTask::run()
{
    QByteArray data;
    SfDatabase *opened = nullptr;
    // Tightens the directories of an installation that made them before
    // they were private; the file itself has been owner-only from the start.
    Databases::makeStoragePrivate();
    int status = readBoundedFile(m_databasePath, MaxDatabaseBytes, data);
    // KDBX distinguishes "no password" from an empty one. Like KeePassXC,
    // an empty field means no password, and a failed attempt is retried
    // with an empty password.
    if (status == SF_OK)
        status = openWith(data, m_password, !m_password.isEmpty(), &opened);
    if (status == SF_INVALID_CREDENTIALS && m_password.isEmpty())
        status = openWith(data, m_password, true, &opened);
    CoreDatabase database(opened);
    secureWipe(m_password);
    deliver(m_authenticator, *m_cancelled, m_attempt, status, std::move(database),
            fileDigest(data));
}

CreateTask::CreateTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
                       int attempt, const QString &name, QByteArray password, uint32_t kdfLevel)
    : m_authenticator(authenticator)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_name(name)
    , m_password(std::move(password))
    , m_kdfLevel(kdfLevel)
{
}

CreateTask::~CreateTask()
{
    secureWipe(m_password);
}

void CreateTask::run()
{
    SfDatabase *created = nullptr;
    CoreBytes file;
    const QByteArray name = m_name.toUtf8();
    int status = sf_database_create(bytePointer(m_password), static_cast<size_t>(m_password.size()),
                                    bytePointer(name), static_cast<size_t>(name.size()),
                                    m_kdfLevel, unixSeconds(), &created, file.out());
    CoreDatabase database(created);
    secureWipe(m_password);
    if (status == SF_OK)
        status = Databases::claim(m_name);
    if (status == SF_OK)
        status = createNewFile(Databases::databasePath(m_name), file.view());
    deliver(m_authenticator, *m_cancelled, m_attempt, status, std::move(database),
            fileDigest(file.view()));
}

SaveTask::SaveTask(Authenticator *authenticator, int attempt, const SfDatabase *database,
                   const QString &databasePath, const QByteArray &expectedDigest)
    : m_authenticator(authenticator)
    , m_attempt(attempt)
    , m_database(database)
    , m_databasePath(databasePath)
    , m_expectedDigest(expectedDigest)
{
}

void SaveTask::run()
{
    CoreBytes file;
    int status = sf_database_save(m_database, file.out());
    QByteArray digest;
    bool replacedChangedFile = false;
    if (status == SF_OK) {
        status = writeDatabaseFile(m_databasePath, file.view(), Databases::backupDirectory(),
                                   m_expectedDigest, replacedChangedFile);
        digest = fileDigest(file.view());
    }
    QMetaObject::invokeMethod(m_authenticator, "onSaveFinished", Qt::QueuedConnection,
                              Q_ARG(int, m_attempt), Q_ARG(int, status),
                              Q_ARG(QByteArray, digest), Q_ARG(bool, replacedChangedFile));
}
