#ifndef CORETASKS_H
#define CORETASKS_H

#include <QByteArray>
#include <QRunnable>
#include <QString>

#include <atomic>
#include <memory>

#include "sailtoken_core.h"

class Authenticator;

// The authenticator's work on pool threads. Each task hands its result to
// a private slot of the authenticator through a queued call. A task whose
// result is no longer wanted frees it itself. The authenticator outlives
// every task: its destructor cancels and waits for the pool.

// Reads the file and its key file, if it has one, and runs the KDF.
class UnlockTask : public QRunnable
{
public:
    UnlockTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
               int attempt, const QString &databasePath, const QString &keyFilePath,
               QByteArray password);
    ~UnlockTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QString m_keyFilePath;
    QByteArray m_password;
};

// Reads a file and its key file from outside the app, unlocks them and
// stores copies under name; a KDBX 3.1 file is stored as the KDBX 4 file it
// becomes, with Argon2id at kdfLevel. The unlocked handle is handed over
// like an unlock does.
class AddTask : public QRunnable
{
public:
    AddTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
            int attempt, const QString &databasePath, const QString &keyFilePath,
            const QString &name, QByteArray password, uint32_t kdfLevel);
    ~AddTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QString m_keyFilePath;
    QString m_name;
    QByteArray m_password;
    uint32_t m_kdfLevel;
};

// Creates the file and stores it under name, then hands over the unlocked
// handle like an unlock does.
class CreateTask : public QRunnable
{
public:
    CreateTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
               int attempt, const QString &name, QByteArray password, uint32_t kdfLevel);
    ~CreateTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_name;
    QByteArray m_password;
    uint32_t m_kdfLevel;
};

// Opens another copy of the file for a merge: with the credentials the
// open file holds, which keeps its handle alive and read-only until the
// result arrives, or with the copy's own password and key file.
class MergeTask : public QRunnable
{
public:
    MergeTask(Authenticator *authenticator, int attempt, const StDatabase *database,
              const QString &path);
    // A copy already read, such as a download.
    MergeTask(Authenticator *authenticator, int attempt, const StDatabase *database,
              QByteArray data);
    MergeTask(Authenticator *authenticator, int attempt, const QString &path, QByteArray password,
              const QString &keyFilePath);
    ~MergeTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    int m_attempt;
    const StDatabase *m_database;
    QString m_path;
    QByteArray m_password;
    QString m_keyFilePath;
    QByteArray m_data;
};

// Reads an export file of another app, an Aegis vault, into a new import;
// an encrypted vault runs scrypt with the password. Without a password,
// an encrypted vault reports ST_PASSWORD_REQUIRED at once.
class ImportFileTask : public QRunnable
{
public:
    ImportFileTask(Authenticator *authenticator, int attempt, const QString &path,
                   QByteArray password, bool withPassword);
    ~ImportFileTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    int m_attempt;
    QString m_path;
    QByteArray m_password;
    bool m_withPassword;
};

// Serializes the file, which runs the KDF, and replaces it with backups.
// The authenticator keeps the handle alive and read-only until the result
// arrives.
class SaveTask : public QRunnable
{
public:
    SaveTask(Authenticator *authenticator, int attempt, const StDatabase *database,
             const QString &databasePath, const QByteArray &expectedDigest);

    void run() override;

private:
    Authenticator *m_authenticator;
    int m_attempt;
    const StDatabase *m_database;
    QString m_databasePath;
    QByteArray m_expectedDigest;
};

#endif // CORETASKS_H
