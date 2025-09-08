/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

#pragma once

#include <condition_variable>
#include <string>
#include <mutex>

// Forward declarations
struct sqlite3;
namespace XrdCl {
    class Log;
}

namespace Pelican {

// A class to persist the information about the writeback cache to the
// on-disk SQLite database
class WritebackDB {
public:
    enum class TransferState {
        PENDING,
        ACTIVE,
        SUCCESS,
        FAILED
    };

    // Get the string representation of a transfer state
    static std::string GetStateString(TransferState state) {
        switch (state) {
        case TransferState::PENDING:
            return "PENDING";
        case TransferState::ACTIVE:
            return "ACTIVE";
        case TransferState::SUCCESS:
            return "SUCCESS";
        case TransferState::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
        }
    }

    // Initialize (and possibly create) the database; throws a std::runtime_error
    // if the initialization failed.
    WritebackDB(const std::string &db_location, XrdCl::Log &logger);

    // Initialize the database's schema
    bool InitializeSchema(sqlite3 *db, std::string &errmsg);

    // Create a transfer object in the database
    static bool CreateTransfer(const std::string &id, const std::string &dest, uint64_t upload_size, std::string &err);

    // Update a transfer state
    static bool UpdateTransfer(TransferState state, const std::string &id, uint64_t upload_size, std::string &err);

    // Get the transfer status
    static bool GetTransferStatus(const std::string &id, TransferState &state, uint64_t &bytes_transferred, std::string &msg, std::string &err);

    // Finalize the transfer, potentially recording an error message.
    static bool FinalizeTransfer(TransferState state, const std::string &id, const std::string &result, uint64_t bytes_transferred, std::string &err);

    // Get the database location
    static std::string GetDBLocation() { std::unique_lock lock(m_db_location_lock); return m_db_location; }

    // Perform maintenance on the DB (e.g., rotate out old transfers)
    static void Maintenance();

private:
    // Iterate through all known transfers; updating the status in the DB.
    static void UpdateAllTransfers();

    // Expire old transfers
    static void ExpireOldTransfers();

    // Return a database handle instance
    sqlite3 *GetHandle();

    // Database handle tracking
    class DatabaseRef final {
    public:
        ~DatabaseRef();
        sqlite3 *GetHandle();
    private:
        sqlite3 *handle{nullptr};
    };
    // Current thread's database handle (possibly uninitialized)
    static thread_local DatabaseRef m_handle;

    static std::string m_db_location;
    static XrdCl::Log *m_logger;

    // Mutex for access to m_db_location
    static std::mutex m_db_location_lock;

    // Flag managing one-time initialization of the database.
    static std::once_flag m_init_db;
};

}
