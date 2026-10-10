#ifndef COREBRIDGE_H
#define COREBRIDGE_H

#include <QByteArray>
#include <QDateTime>
#include <QString>

#include <memory>
#include <string.h>

#include "sailtoken_core.h"

// Helpers for calling the Rust core: buffers, UUIDs, strings and handles.

// Overwrites the buffer before releasing it. A copy that still shares the
// data with another QByteArray is detached first, so only this copy is
// wiped; callers keep secrets in a single, unshared buffer.
inline void secureWipe(QByteArray &bytes)
{
    if (!bytes.isEmpty()) {
        bytes.detach();
        explicit_bzero(bytes.data(), static_cast<size_t>(bytes.size()));
    }
    bytes.clear();
}

inline const uint8_t *bytePointer(const QByteArray &bytes)
{
    return reinterpret_cast<const uint8_t *>(bytes.constData());
}

// The 16 bytes of the account with the hex id QML uses, or empty for
// anything else.
inline QByteArray accountUuid(const QString &accountId)
{
    const QByteArray uuid = QByteArray::fromHex(accountId.toLatin1());
    return uuid.size() == ST_UUID_LENGTH ? uuid : QByteArray();
}

// Converts a core string and releases it; the core wipes its copy.
inline QString takeCoreString(StString string)
{
    const QString text = QString::fromUtf8(reinterpret_cast<const char *>(string.data),
                                           static_cast<int>(string.length));
    st_string_free(string);
    return text;
}

// The same as bytes, for values such as an app password that go on to
// another library; the caller wipes them.
inline QByteArray takeCoreBytes(StString string)
{
    const QByteArray bytes(reinterpret_cast<const char *>(string.data),
                           static_cast<int>(string.length));
    st_string_free(string);
    return bytes;
}

inline StString emptyCoreString()
{
    return StString{nullptr, 0};
}

// The core takes times in seconds since the Unix epoch.
inline qint64 unixSeconds()
{
    return QDateTime::currentMSecsSinceEpoch() / 1000;
}

// Owners of core handles, which free them with the core's own function.
template <typename Handle, void (*Free)(Handle *)>
struct CoreFree {
    void operator()(Handle *handle) const { Free(handle); }
};
using CoreDatabase = std::unique_ptr<StDatabase, CoreFree<StDatabase, st_database_free>>;
using CorePending = std::unique_ptr<StPending, CoreFree<StPending, st_pending_free>>;
using CoreAccountList =
    std::unique_ptr<StAccountList, CoreFree<StAccountList, st_account_list_free>>;
using CoreImport = std::unique_ptr<StImport, CoreFree<StImport, st_import_free>>;

// A file from the core, released when it goes out of scope.
class CoreBytes
{
public:
    CoreBytes() = default;
    CoreBytes(const CoreBytes &) = delete;
    CoreBytes &operator=(const CoreBytes &) = delete;
    ~CoreBytes() { st_bytes_free(m_bytes); }

    StBytes *out() { return &m_bytes; }
    // Valid while this object lives.
    QByteArray view() const
    {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(m_bytes.data),
                                       static_cast<int>(m_bytes.length));
    }

private:
    StBytes m_bytes{nullptr, 0};
};

#endif // COREBRIDGE_H
