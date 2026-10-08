#ifndef ACCOUNTLISTMODEL_H
#define ACCOUNTLISTMODEL_H

#include <QAbstractListModel>
#include <QByteArray>
#include <QPointer>
#include <QQmlParserStatus>
#include <QString>
#include <QTimer>
#include <QVector>

#include "authenticator.h"

// The accounts of the unlocked file, filtered by query, with their current
// codes. Codes and the seconds left are recomputed from the wall clock at
// every second boundary, never counted down, and only while the app is in
// the foreground. It loads once its QML properties are all set, then on
// every change.
class AccountListModel : public QAbstractListModel, public QQmlParserStatus
{
    Q_OBJECT
    Q_INTERFACES(QQmlParserStatus)
    Q_PROPERTY(Authenticator *source READ source WRITE setSource NOTIFY sourceChanged)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY queryChanged)

public:
    enum Kind {
        Totp,
        Hotp,
        Unreadable,
        NoCode
    };
    Q_ENUM(Kind)

    enum Role {
        IdRole = Qt::UserRole + 1,
        IssuerRole,
        NameRole,
        KindRole,
        DigitsRole,
        PeriodRole,
        SteamRole,
        CodeRole,
        RemainingRole
    };

    explicit AccountListModel(QObject *parent = nullptr);

    Authenticator *source() const;
    void setSource(Authenticator *source);
    QString query() const;
    void setQuery(const QString &query);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    void classBegin() override;
    void componentComplete() override;

signals:
    void sourceChanged();
    void queryChanged();

private:
    struct Item {
        QByteArray uuid;
        QString issuer;
        QString name;
        Kind kind;
        int digits;
        int period;
        bool steam;
        QString code;
        int remaining;
    };

    void reload();
    void refreshCodes();
    void updateTicking();
    void scheduleTick();

    bool m_complete = false;
    QPointer<Authenticator> m_authenticator;
    QString m_query;
    QVector<Item> m_items;
    QTimer m_tick;
};

#endif // ACCOUNTLISTMODEL_H
