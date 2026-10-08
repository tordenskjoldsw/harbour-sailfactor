#include "databases.h"

#include <QFileInfo>
#include <QStandardPaths>

#include "databasefile.h"
#include "sailfactor_core.h"

namespace {

const QString DatabaseSuffix = QStringLiteral(".kdbx");

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

} // namespace

namespace Databases {

// Also the database name inside the file, which KeePassXC shows.
const QString DefaultName = QStringLiteral("SailFactor");

QString databasePath(const QString &name)
{
    return isValidName(name) ? databaseDirectory() + QLatin1Char('/') + name + DatabaseSuffix
                             : QString();
}

QString backupDirectory()
{
    return dataDirectory(QStringLiteral("backups"));
}

// The backups directory is made private the same way when a backup is
// written.
bool makeStoragePrivate()
{
    return makePrivateDirectory(dataRoot()) && makePrivateDirectory(databaseDirectory());
}

int claim(const QString &name)
{
    if (!isValidName(name) || !makeStoragePrivate())
        return StatusFileUnwritable;
    return exists(name) ? StatusFileExists : SF_OK;
}

bool isValidName(const QString &name)
{
    return !name.isEmpty() && name.size() <= 100 && name == name.trimmed()
        && !name.startsWith(QLatin1Char('.')) && !name.contains(QLatin1Char('/'))
        && !name.contains(QChar::Null);
}

bool exists(const QString &name)
{
    return isValidName(name) && QFileInfo::exists(databasePath(name));
}

} // namespace Databases
