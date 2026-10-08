#ifndef CORETASKS_H
#define CORETASKS_H

#include <QByteArray>
#include <QRunnable>
#include <QString>

#include <atomic>
#include <memory>

#include "sailfactor_core.h"

class Authenticator;

// The authenticator's work on pool threads. Each task hands its result to
// a private slot of the authenticator through a queued call. A task whose
// result is no longer wanted frees it itself. The authenticator outlives
// every task: its destructor cancels and waits for the pool.

// Reads the file and runs the KDF.
class UnlockTask : public QRunnable
{
public:
    UnlockTask(Authenticator *authenticator, std::shared_ptr<std::atomic_bool> cancelled,
               int attempt, const QString &databasePath, QByteArray password);
    ~UnlockTask() override;

    void run() override;

private:
    Authenticator *m_authenticator;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QByteArray m_password;
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

// Serializes the file, which runs the KDF, and replaces it with backups.
// The authenticator keeps the handle alive and read-only until the result
// arrives.
class SaveTask : public QRunnable
{
public:
    SaveTask(Authenticator *authenticator, int attempt, const SfDatabase *database,
             const QString &databasePath, const QByteArray &expectedDigest);

    void run() override;

private:
    Authenticator *m_authenticator;
    int m_attempt;
    const SfDatabase *m_database;
    QString m_databasePath;
    QByteArray m_expectedDigest;
};

#endif // CORETASKS_H
