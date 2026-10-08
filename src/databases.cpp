#include "databases.h"

#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

#include "corebridge.h"
#include "databasefile.h"
#include "sailfactor_core.h"

namespace {

const QString DatabaseSuffix = QStringLiteral(".kdbx");
const QString KeyFileSuffix = QStringLiteral(".key");

QString dataRoot()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
}

QString dataDirectory(const QString &name)
{
    return dataRoot() + QLatin1Char('/') + name;
}

QString databaseDirectory()
{
    return dataDirectory(QStringLiteral("databases"));
}

QString keyFileDirectory()
{
    return dataDirectory(QStringLiteral("keyfiles"));
}

QString copyKeyFilePath(const QString &copyPath)
{
    return copyPath.left(copyPath.size() - DatabaseSuffix.size()) + KeyFileSuffix;
}

int copyFile(const QString &from, const QString &to, qint64 maxBytes)
{
    QByteArray data;
    int status = readBoundedFile(from, maxBytes, data);
    if (status == SF_OK)
        status = createNewFile(to, data);
    secureWipe(data);
    return status;
}

} // namespace

// Also the database name inside a file created here, which KeePassXC
// shows.
const QString Databases::DefaultName = QStringLiteral("SailFactor");

Databases::Databases(QObject *parent)
    : QObject(parent)
{
}

QString Databases::defaultName() const
{
    return DefaultName;
}

QString Databases::databasePath(const QString &name)
{
    return isValidName(name) ? databaseDirectory() + QLatin1Char('/') + name + DatabaseSuffix
                             : QString();
}

QString Databases::keyFilePath(const QString &name)
{
    return isValidName(name) ? keyFileDirectory() + QLatin1Char('/') + name + KeyFileSuffix
                             : QString();
}

QString Databases::backupDirectory()
{
    return dataDirectory(QStringLiteral("backups"));
}

// The backups directory is made private the same way when a backup is
// written.
bool Databases::makeStoragePrivate()
{
    return makePrivateDirectory(dataRoot()) && makePrivateDirectory(databaseDirectory())
        && makePrivateDirectory(keyFileDirectory());
}

int Databases::claim(const QString &name)
{
    if (!isValidName(name) || !makeStoragePrivate())
        return StatusFileUnwritable;
    if (exists(name))
        return StatusFileExists;
    const QString keyFile = keyFilePath(name);
    if (QFileInfo::exists(keyFile) && !QFile::remove(keyFile))
        return StatusFileUnwritable;
    return SF_OK;
}

bool Databases::isValidName(const QString &name)
{
    return !name.isEmpty() && name.size() <= 100 && name == name.trimmed()
        && !name.startsWith(QLatin1Char('.')) && !name.contains(QLatin1Char('/'))
        && !name.contains(QChar::Null);
}

bool Databases::exists(const QString &name)
{
    return isValidName(name) && QFileInfo::exists(databasePath(name));
}

bool Databases::hasKeyFile(const QString &name)
{
    return isValidName(name) && QFileInfo::exists(keyFilePath(name));
}

QString Databases::copyPath(int location, const QString &fileName)
{
    if (!isValidName(fileName))
        return QString();
    const QString folder = QStandardPaths::writableLocation(
        location == Downloads ? QStandardPaths::DownloadLocation
                              : QStandardPaths::DocumentsLocation);
    return folder + QLatin1Char('/') + fileName + DatabaseSuffix;
}

bool Databases::copyExists(int location, const QString &fileName, bool withKeyFile)
{
    const QString path = copyPath(location, fileName);
    return !path.isEmpty()
        && (QFileInfo::exists(path) || (withKeyFile && QFileInfo::exists(copyKeyFilePath(path))));
}

Databases::CopyResult Databases::saveCopy(const QString &name, int location,
                                          const QString &fileName, bool withKeyFile)
{
    const QString path = copyPath(location, fileName);
    if (!exists(name) || path.isEmpty() || (withKeyFile && !hasKeyFile(name)))
        return CopyFailed;
    if (copyExists(location, fileName, withKeyFile))
        return CopyExists;
    int status = copyFile(databasePath(name), path, MaxDatabaseBytes);
    // Half a copy is no use: a file without the key file it was saved with
    // cannot be opened.
    if (status == SF_OK && withKeyFile) {
        status = copyFile(keyFilePath(name), copyKeyFilePath(path), MaxKeyFileBytes);
        if (status != SF_OK)
            QFile::remove(path);
    }
    switch (status) {
    case SF_OK:
        return CopySaved;
    case StatusFileExists:
        return CopyExists;
    default:
        return CopyFailed;
    }
}
