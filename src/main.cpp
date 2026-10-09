#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>
#include <qqml.h>

#include <cstdio>
#include <memory>

#include <sailfishapp.h>

#include "accountlistmodel.h"
#include "authenticator.h"
#include "boottime.h"
#include "databases.h"
#include "framescanner.h"
#include "sailtoken_core.h"
#include "sync.h"

namespace {

void printFirstFrameTimestamp(QQuickWindow *window)
{
    auto connection = std::make_shared<QMetaObject::Connection>();
    *connection = QObject::connect(window, &QQuickWindow::frameSwapped, [connection] {
        QObject::disconnect(*connection);
        std::printf("first-frame-boottime-ms=%lld\n", bootTimeMs());
        std::fflush(stdout);
    });
}

} // namespace

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));
    // Must match the Sailjail OrganizationName and ApplicationName, which
    // decide the writable data and config directories.
    QCoreApplication::setOrganizationName(QStringLiteral("de.tordenskjold"));
    QCoreApplication::setApplicationName(QStringLiteral("sailtoken"));

    qmlRegisterType<AccountListModel>("harbour.sailtoken", 1, 0, "AccountListModel");
    qmlRegisterType<FrameScanner>("harbour.sailtoken", 1, 0, "FrameScanner");
    qmlRegisterUncreatableType<Authenticator>("harbour.sailtoken", 1, 0, "Authenticator",
                                              QStringLiteral("Use the authenticator context property"));
    qmlRegisterUncreatableType<Databases>("harbour.sailtoken", 1, 0, "Databases",
                                          QStringLiteral("Use the databases context property"));
    qmlRegisterUncreatableType<Sync>("harbour.sailtoken", 1, 0, "Sync",
                                     QStringLiteral("Use the sync context property"));

    Databases databases;
    Authenticator authenticator;
    Sync sync(&authenticator);
    QScopedPointer<QQuickView> view(SailfishApp::createView());
    // Development builds carry SemVer build metadata after "+" (branch, time
    // and commit); the About page shows it apart from the release number.
    const QString version = QStringLiteral(APP_VERSION);
    QCoreApplication::setApplicationVersion(version);
    QQmlContext *context = view->rootContext();
    context->setContextProperty(QStringLiteral("authenticator"), &authenticator);
    context->setContextProperty(QStringLiteral("databases"), &databases);
    context->setContextProperty(QStringLiteral("sync"), &sync);
    context->setContextProperty(QStringLiteral("appVersion"),
                                version.section(QLatin1Char('+'), 0, 0));
    context->setContextProperty(QStringLiteral("appBuild"), version.section(QLatin1Char('+'), 1));
    context->setContextProperty(QStringLiteral("coreVersion"),
                                QString::fromLatin1(st_core_version()));

    if (app->arguments().contains(QStringLiteral("--startup-trace")))
        printFirstFrameTimestamp(view.data());

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
