#pragma once

#include "core/Result.h"
#include "core/security/EncryptionSnapshot.h"

#include <functional>
#include <optional>
#include <string>
#include <cstdint>

namespace sentinel::collectors {

class EncryptionCollector {
public:
    enum class QueryStatus {
        Encrypted,
        NotEncrypted,
        AccessDenied,
        NotSupported,
        Unavailable,
        Error
    };

    struct QueryResult {
        QueryStatus status{QueryStatus::Unavailable};
        std::optional<std::uint32_t> encryptionPercentage;
        std::optional<std::string> encryptionMethod;
        std::optional<bool> protectionEnabled;
        std::string diagnostic;
    };

    using Query = std::function<QueryResult()>;

    explicit EncryptionCollector(Query query = {});
    ~EncryptionCollector() = default;

    [[nodiscard]] core::CollectionResult<core::EncryptionSnapshot> collect();

private:
    static QueryResult querySystemVolume();
    Query m_query;
};

} // namespace sentinel::collectors
