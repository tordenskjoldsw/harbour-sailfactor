#include "accountlistmodel.h"

#include <QDateTime>
#include <QGuiApplication>

#include "corebridge.h"

namespace {

QString listText(const SfAccountList *list, size_t index, uint32_t column)
{
    SfString text = emptyCoreString();
    return sf_account_list_text(list, index, column, &text) == SF_OK ? takeCoreString(text)
                                                                     : QString();
}

AccountListModel::Kind kindFor(uint32_t kind)
{
    switch (kind) {
    case SF_KIND_TOTP:
        return AccountListModel::Totp;
    case SF_KIND_HOTP:
        return AccountListModel::Hotp;
    case SF_KIND_UNREADABLE:
        return AccountListModel::Unreadable;
    default:
        return AccountListModel::NoCode;
    }
}

} // namespace

AccountListModel::AccountListModel(QObject *parent)
    : QAbstractListModel(parent)
{
    m_tick.setSingleShot(true);
    connect(&m_tick, &QTimer::timeout, this, [this] {
        refreshCodes();
        updateTicking();
    });
    connect(qApp, &QGuiApplication::applicationStateChanged, this, [this] {
        // Codes went stale while the app was in the background.
        refreshCodes();
        updateTicking();
    });
}

Authenticator *AccountListModel::source() const
{
    return m_authenticator;
}

void AccountListModel::setSource(Authenticator *source)
{
    if (m_authenticator == source)
        return;
    if (m_authenticator)
        disconnect(m_authenticator, nullptr, this, nullptr);
    m_authenticator = source;
    if (m_authenticator) {
        connect(m_authenticator, &Authenticator::stateChanged, this, &AccountListModel::reload);
        connect(m_authenticator, &Authenticator::contentChanged, this, &AccountListModel::reload);
    }
    emit sourceChanged();
    reload();
}

QString AccountListModel::query() const
{
    return m_query;
}

void AccountListModel::setQuery(const QString &query)
{
    if (m_query == query)
        return;
    m_query = query;
    emit queryChanged();
    reload();
}

int AccountListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_items.size();
}

QVariant AccountListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_items.size())
        return QVariant();
    const Item &item = m_items.at(index.row());
    switch (role) {
    case IdRole:
        return QString::fromLatin1(item.uuid.toHex());
    case IssuerRole:
        return item.issuer;
    case NameRole:
        return item.name;
    case KindRole:
        return item.kind;
    case DigitsRole:
        return item.digits;
    case PeriodRole:
        return item.period;
    case SteamRole:
        return item.steam;
    case CodeRole:
        return item.code;
    case RemainingRole:
        return item.remaining;
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> AccountListModel::roleNames() const
{
    return {
        {IdRole, "accountId"},
        {IssuerRole, "issuer"},
        {NameRole, "name"},
        {KindRole, "kind"},
        {DigitsRole, "digits"},
        {PeriodRole, "period"},
        {SteamRole, "steam"},
        {CodeRole, "code"},
        {RemainingRole, "remaining"},
    };
}

void AccountListModel::classBegin()
{
}

void AccountListModel::componentComplete()
{
    m_complete = true;
    reload();
}

// Every change goes through here: the list is rebuilt from the core, so an
// edit, a lock or a new search all show the same state.
void AccountListModel::reload()
{
    if (!m_complete)
        return;
    beginResetModel();
    m_items.clear();
    const SfDatabase *database = m_authenticator ? m_authenticator->database() : nullptr;
    SfAccountList *found = nullptr;
    if (database && sf_account_list(database, &found) == SF_OK) {
        const CoreAccountList list(found);
        const QString query = m_query.trimmed();
        for (size_t index = 0; index < sf_account_list_length(list.get()); ++index) {
            Item item;
            item.uuid = QByteArray(SF_UUID_LENGTH, Qt::Uninitialized);
            uint32_t kind = 0, digits = 0, period = 0, encoder = 0;
            if (sf_account_list_uuid(list.get(), index, reinterpret_cast<uint8_t *>(item.uuid.data()))
                    != SF_OK
                || sf_account_list_kind(list.get(), index, &kind, &digits, &period, &encoder)
                    != SF_OK)
                continue;
            item.issuer = listText(list.get(), index, SF_TEXT_ISSUER);
            item.name = listText(list.get(), index, SF_TEXT_NAME);
            if (!query.isEmpty() && !item.issuer.contains(query, Qt::CaseInsensitive)
                && !item.name.contains(query, Qt::CaseInsensitive))
                continue;
            item.kind = kindFor(kind);
            item.digits = static_cast<int>(digits);
            item.period = static_cast<int>(period);
            item.steam = encoder == SF_ENCODER_STEAM;
            item.remaining = 0;
            m_items.append(item);
        }
    }
    endResetModel();
    refreshCodes();
    updateTicking();
}

void AccountListModel::refreshCodes()
{
    // Checks the lock deadlines once, before the loop: a lock reloads the
    // list, which must not happen while it is walked.
    if (m_items.isEmpty() || !m_authenticator || !m_authenticator->database())
        return;
    const qint64 now = unixSeconds();
    for (Item &item : m_items) {
        if (item.kind != Totp)
            continue;
        uint32_t remaining = 0;
        item.code = m_authenticator->code(item.uuid, now, remaining);
        item.remaining = static_cast<int>(remaining);
    }
    emit dataChanged(index(0), index(m_items.size() - 1), {CodeRole, RemainingRole});
}

void AccountListModel::updateTicking()
{
    const bool wanted = !m_items.isEmpty()
        && QGuiApplication::applicationState() == Qt::ApplicationActive;
    if (wanted && !m_tick.isActive())
        scheduleTick();
    else if (!wanted)
        m_tick.stop();
}

// Ticks just after each full second, when codes and countdowns change.
void AccountListModel::scheduleTick()
{
    const qint64 msIntoSecond = QDateTime::currentMSecsSinceEpoch() % 1000;
    m_tick.start(static_cast<int>(1000 - msIntoSecond) + 5);
}
