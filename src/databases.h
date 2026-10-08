#ifndef DATABASES_H
#define DATABASES_H

#include <QString>

// The authenticator file in the app's private data directory, which
// Sailjail keeps from other sandboxed apps: databases/<name>.kdbx, with its
// backups in backups/. The first release keeps one file under a fixed
// name; several files come later (PLAN.md, Phase 4).
namespace Databases {

extern const QString DefaultName;

// Empty when the name is not valid.
QString databasePath(const QString &name);
QString backupDirectory();
// Prepares storing a new file under name: creates the private
// directories. Returns StatusFileExists when the name is taken.
int claim(const QString &name);
// Names that are not empty, have no surrounding spaces, do not start with
// a dot, contain no slash and have at most 100 characters.
bool isValidName(const QString &name);
bool exists(const QString &name);

} // namespace Databases

#endif // DATABASES_H
