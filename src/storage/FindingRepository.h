#pragma once

#include "core/Finding.h"
#include "core/Result.h"
#include <sqlite3.h>
#include <vector>

namespace sentinel::storage {

class FindingRepository {
public:
    explicit FindingRepository(sqlite3* db);

    [[nodiscard]] core::Result<bool> insertFindings(const std::string& scanId, const std::vector<core::Finding>& findings);
    [[nodiscard]] core::Result<std::vector<core::Finding>> getFindingsForScan(const std::string& scanId);

private:
    sqlite3* m_db{nullptr};
};

} // namespace sentinel::storage
