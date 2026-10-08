#ifndef DATABASES_H
#define DATABASES_H

#include <QObject>
#include <QString>

// The authenticator file in the app's private data directory, which
// Sailjail keeps from other sandboxed apps: databases/<name>.kdbx, its key
// file, if it has one, keyfiles/<name>.key, and its backups in backups/.
// The app keeps one file, under DefaultName; the paths take a name so the
// layout stays SailVault's.
class Databases : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString defaultName READ defaultName CONSTANT)

public:
    // Where saveCopy writes.
    enum Location {
        Documents,
        Downloads
    };
    Q_ENUM(Location)

    // Results of saveCopy.
    enum CopyResult {
        CopySaved,
        CopyExists,
        CopyFailed
    };
    Q_ENUM(CopyResult)

    explicit Databases(QObject *parent = nullptr);

    // The name of the app's one file, as in 0.1.0.
    static const QString DefaultName;
    QString defaultName() const;

    // Empty when the name is not valid.
    static QString databasePath(const QString &name);
    static QString keyFilePath(const QString &name);
    static QString backupDirectory();
    // Creates the data directory, the files' directory and the key files'
    // directory if needed and limits them to the owner; also run before an
    // unlock, so an installation made before the directories were private
    // gets them tightened.
    static bool makeStoragePrivate();
    // Prepares storing a new file under name: creates the private
    // directories and removes a key file an interrupted add left without
    // its file. Returns StatusFileExists when the name is taken.
    static int claim(const QString &name);

    // Names that are not empty, have no surrounding spaces, do not start
    // with a dot, contain no slash and have at most 100 characters.
    Q_INVOKABLE static bool isValidName(const QString &name);
    Q_INVOKABLE static bool exists(const QString &name);
    Q_INVOKABLE static bool hasKeyFile(const QString &name);

    // The path of a copy named fileName.kdbx in location, or empty when
    // fileName is not a valid name. Its key file goes next to it as
    // fileName.key.
    Q_INVOKABLE static QString copyPath(int location, const QString &fileName);
    Q_INVOKABLE static bool copyExists(int location, const QString &fileName, bool withKeyFile);
    // Copies the stored file, and its key file when withKeyFile is set, to
    // location; existing files are never replaced.
    Q_INVOKABLE static CopyResult saveCopy(const QString &name, int location,
                                           const QString &fileName, bool withKeyFile);
};

#endif // DATABASES_H
