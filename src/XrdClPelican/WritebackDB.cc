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

#include "PelicanFile.hh"
#include "PelicanFilesystem.hh"
#include "WritebackDB.hh"

#include <sqlite3.h>
#include <XrdCl/XrdClLog.hh>

#include <stdexcept>
#include <thread>

XrdCl::Log *Pelican::WritebackDB::m_logger = nullptr;
std::string Pelican::WritebackDB::m_db_location;
std::mutex Pelican::WritebackDB::m_db_location_lock;
std::once_flag Pelican::WritebackDB::m_init_db;

using namespace Pelican;

WritebackDB::WritebackDB(const std::string &db_location, XrdCl::Log &logger)
{
    if (db_location.empty()) {
        throw std::runtime_error("Database location is an empty string");
    }
    std::call_once(m_init_db, [&]{
        {
            std::unique_lock lock(m_db_location_lock);
            m_db_location = db_location;
        }

        sqlite3 *db{nullptr};
        auto ec = sqlite3_open_v2(db_location.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
        if (ec != SQLITE_OK) {
            m_logger->Error(kLogXrdClPelican, "Failed to open database (%s): %s", db_location.c_str(), sqlite3_errstr(ec));
            throw std::runtime_error("Failed to open database (" + db_location + "): " + sqlite3_errstr(ec));
        }

        std::string errmsg;
        if (!InitializeSchema(db, errmsg)) {
            sqlite3_close_v2(db);
            m_logger->Error(kLogXrdClPelican, "Failed to initialize database schema: %s", errmsg.c_str());
            throw std::runtime_error(errmsg);
        }
    });
}

bool
WritebackDB::InitializeSchema(sqlite3 *db, std::string &err)
{
    // Begin transaction
    char *errmsg = nullptr;
    auto rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = std::string("Failed to begin transaction: ") + (errmsg ? errmsg : "Unknown error");
        sqlite3_free(errmsg);
        return false;
    }

    bool success = false;
    try {
        // 1. Create schema_version table if not exists
        const char *create_version_table_sql =
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "version INTEGER NOT NULL"
            ");";
        rc = sqlite3_exec(db, create_version_table_sql, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to create schema_version table: " + err);
        }

        // Check current schema version
        int version = 0;
        const char *select_version_sql = "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1;";
        sqlite3_stmt *stmt = nullptr;
        rc = sqlite3_prepare_v2(db, select_version_sql, -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                version = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        } else {
            throw std::runtime_error("Failed to query schema_version table: " + std::string(sqlite3_errmsg(db)));
        }

        if (version == 0) {
            // Insert version 1 if not present
            const char *insert_version_sql = "INSERT INTO schema_version (version) VALUES (1);";
            rc = sqlite3_exec(db, insert_version_sql, nullptr, nullptr, &errmsg);
            if (rc != SQLITE_OK) {
                std::string err = errmsg ? errmsg : "Unknown error";
                sqlite3_free(errmsg);
                throw std::runtime_error("Failed to insert schema version: " + err);
            }
            version = 1;
        } else if (version > 1) {
            throw std::runtime_error("Unsupported schema version: " + std::to_string(version));
        }

        // 2. Create transfers table
        const char *create_transfers_sql =
            "CREATE TABLE IF NOT EXISTS transfers ("
            "transfer_id TEXT PRIMARY KEY," // UUID as TEXT
            "destination_url TEXT NOT NULL,"
            "created_at INTEGER NOT NULL," // Unix timestamp
            "updated_at INTEGER NOT NULL," // Unix timestamp
            "bytes_transferred INTEGER NOT NULL," // Bytes transferred so far
            "upload_size INTEGER NOT NULL," // Total size to upload
            "status INTEGER NOT NULL"
            ");";
        rc = sqlite3_exec(db, create_transfers_sql, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to create transfers table: " + err);
        }

        const char *create_transfer_messages_sql =
            "CREATE TABLE IF NOT EXISTS transfer_messages ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "transfer_id TEXT NOT NULL,"
            "message TEXT NOT NULL,"
            "FOREIGN KEY(transfer_id) REFERENCES transfers(transfer_id) ON DELETE CASCADE"
            ");";
        rc = sqlite3_exec(db, create_transfer_messages_sql, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to create transfer_messages table: " + err);
        }

        // 3. Create indexes for efficient queries
        // Index for status and updated_at for efficient queries by status and last update
        const char *create_status_updated_index_sql =
            "CREATE INDEX IF NOT EXISTS idx_transfers_status_updated_at ON transfers(status, updated_at);";
        rc = sqlite3_exec(db, create_status_updated_index_sql, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to create status/updated_at index: " + err);
        }

        const char *create_transfer_messages_transfer_id_index_sql =
            "CREATE INDEX IF NOT EXISTS idx_transfer_messages_transfer_id ON transfer_messages(transfer_id);";
        rc = sqlite3_exec(db, create_transfer_messages_transfer_id_index_sql, nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to create transfer_messages(transfer_id) index: " + err);
        }

        // Commit transaction
        rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "Unknown error";
            sqlite3_free(errmsg);
            throw std::runtime_error("Failed to commit transaction: " + err);
        }
        success = true;
    } catch (std::exception &exc) {
        // Rollback transaction on error
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        err = exc.what();
    }

    return success;
}

void
WritebackDB::ExpireOldTransfers()
{
    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        // Could not open database, nothing to do
        return;
    }

    auto now = static_cast<sqlite3_int64>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    const sqlite3_int64 six_hours_ago = now - 6 * 3600;
    const sqlite3_int64 ten_minutes_ago = now - 10 * 60;

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        return;
    }

    // Remove SUCCESS or FAILED older than 6 hours
    const char *delete_success_failed_sql =
        "DELETE FROM transfers "
        "WHERE (status = ? OR status = ?) AND updated_at < ?;";
    sqlite3_stmt *stmt1 = nullptr;
    rc = sqlite3_prepare_v2(db, delete_success_failed_sql, -1, &stmt1, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt1, 1, static_cast<int>(TransferState::SUCCESS));
        sqlite3_bind_int(stmt1, 2, static_cast<int>(TransferState::FAILED));
        sqlite3_bind_int64(stmt1, 3, six_hours_ago);
        sqlite3_step(stmt1);
        sqlite3_finalize(stmt1);
    }

    // Remove other states older than 10 minutes
    const char *delete_other_sql =
        "DELETE FROM transfers "
        "WHERE status != ? AND status != ? AND updated_at < ?;";
    sqlite3_stmt *stmt2 = nullptr;
    rc = sqlite3_prepare_v2(db, delete_other_sql, -1, &stmt2, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(stmt2, 1, static_cast<int>(TransferState::SUCCESS));
        sqlite3_bind_int(stmt2, 2, static_cast<int>(TransferState::FAILED));
        sqlite3_bind_int64(stmt2, 3, ten_minutes_ago);
        sqlite3_step(stmt2);
        sqlite3_finalize(stmt2);
    }

    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
}

void
WritebackDB::Maintenance()
{
    UpdateAllTransfers();
    ExpireOldTransfers();
}

WritebackDB::DatabaseRef::~DatabaseRef()
{
    if (handle != nullptr) {
        sqlite3_close_v2(handle);
        handle = nullptr;
    }
}

sqlite3 *
WritebackDB::DatabaseRef::GetHandle()
{
    std::string db_location;
    {
        std::lock_guard<std::mutex> lock(m_db_location_lock);
        db_location = m_db_location;
    }
    if (db_location.empty()) {
        return nullptr;
    }
    if (handle == nullptr) {
        auto ec = sqlite3_open_v2(db_location.c_str(), &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, nullptr);
        if (ec != SQLITE_OK) {
            return nullptr;
        }
    }
    return handle;
}

void
WritebackDB::UpdateAllTransfers()
{
    fprintf(stderr, "WritebackDB::UpdateAllTransfers invoked\n");
    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        // Could not open database, nothing to do
        return;
    }

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        return;
    }

    sqlite3_stmt *select_stmt = nullptr;
    const char *select_sql =
        "SELECT bytes_transferred, status FROM transfers WHERE transfer_id = ?;";
    rc = sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, nullptr);
    if (rc != SQLITE_OK) {
        if (select_stmt) sqlite3_finalize(select_stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return;
    }

    sqlite3_stmt *stmt = nullptr;
    const char *update_sql =
        "UPDATE transfers SET bytes_transferred = ?, updated_at = ? WHERE transfer_id = ?;";
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        if (stmt) sqlite3_finalize(stmt);
        sqlite3_finalize(select_stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return;
    }

    auto now = static_cast<sqlite3_int64>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    auto xfer = File::GetWritebackActiveStatuses();
    for (const auto &entry : xfer) {
        // Check current status and bytes_transferred
        sqlite3_reset(select_stmt);
        sqlite3_clear_bindings(select_stmt);
        sqlite3_bind_text(select_stmt, 1, entry.first.c_str(), -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(select_stmt);
        if (rc == SQLITE_ROW) {
            sqlite3_int64 current_bytes = sqlite3_column_int64(select_stmt, 0);
            int current_status = sqlite3_column_int(select_stmt, 1);
            if (current_status != static_cast<int>(TransferState::ACTIVE) ||
                entry.second <= static_cast<uint64_t>(current_bytes)) {
                // Skip update if not active or not increasing
                continue;
            }
        } else {
            // Transfer not found, skip
            continue;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
        sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(entry.second));
        sqlite3_bind_int64(stmt, 2, now);
        sqlite3_bind_text(stmt, 3, entry.first.c_str(), -1, SQLITE_TRANSIENT);
        int step_rc = sqlite3_step(stmt);
        if (step_rc == SQLITE_DONE && sqlite3_changes(db) == 0) {
            // No rows updated for this transfer_id
            m_logger->Debug(kLogXrdClPelican, "WritebackDB: No rows updated for transfer_id: %s\n", entry.first.c_str());
        } else if (step_rc != SQLITE_DONE) {
            // Update failed, rollback and return
            sqlite3_finalize(stmt);
            sqlite3_finalize(select_stmt);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return;
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_finalize(select_stmt);

    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
}

bool
WritebackDB::CreateTransfer(const std::string &transfer_id,
                            const std::string &destination_url,
                            uint64_t upload_bytes,
                            std::string &err)
{
    auto created_at = static_cast<sqlite3_uint64>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    auto updated_at = created_at;
    sqlite3_uint64 bytes_transferred = 0;
    auto status = static_cast<int>(TransferState::ACTIVE);

    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        err = "Failed to open database";
        return false;
    }

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        return false;
    }

    const char *insert_sql =
        "INSERT INTO transfers (transfer_id, destination_url, created_at, updated_at, bytes_transferred, upload_size, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt *stmt = nullptr;
    rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_bind_text(stmt, 1, transfer_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, destination_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, created_at);
    sqlite3_bind_int64(stmt, 4, updated_at);
    sqlite3_bind_int64(stmt, 5, bytes_transferred);
    sqlite3_bind_int64(stmt, 6, upload_bytes);
    sqlite3_bind_int(stmt, 7, status);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        err = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_finalize(stmt);

    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    return true;
}

bool
WritebackDB::UpdateTransfer(TransferState state,
                            const std::string &transfer_id,
                            uint64_t bytes_transferred,
                            std::string &err)
{
    // Do not allow updating to SUCCESS or FAILED state
    if (state == TransferState::SUCCESS || state == TransferState::FAILED) {
        err = "Update transfer cannot be used to set state to SUCCESS or FAILED";
        return false;
    }

    auto updated_at = static_cast<sqlite3_uint64>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    

    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        err = "Failed to open database";
        return false;
    }

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        return false;
    }

    const char *check_sql =
        "SELECT status FROM transfers WHERE transfer_id = ?;";
    sqlite3_stmt *check_stmt = nullptr;
    rc = sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, nullptr);
    if (rc != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_bind_text(check_stmt, 1, transfer_id.c_str(), -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(check_stmt);
    if (rc == SQLITE_ROW) {
        int current_status = sqlite3_column_int(check_stmt, 0);
        if (current_status == static_cast<int>(TransferState::SUCCESS) ||
            current_status == static_cast<int>(TransferState::FAILED)) {
            err = "Cannot update a transfer in SUCCESS or FAILED state";
            sqlite3_finalize(check_stmt);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }
    } else {
        err = "Transfer ID not found";
        sqlite3_finalize(check_stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }
    sqlite3_finalize(check_stmt);

    const char *update_sql =
        "UPDATE transfers SET bytes_transferred = ?, updated_at = ?, status = ? WHERE transfer_id = ?;";
    sqlite3_stmt *stmt = nullptr;
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(bytes_transferred));
    sqlite3_bind_int64(stmt, 2, updated_at);
    sqlite3_bind_int(stmt, 3, static_cast<int>(state));
    sqlite3_bind_text(stmt, 4, transfer_id.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        err = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_finalize(stmt);

    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    return true;
}

bool
WritebackDB::FinalizeTransfer(TransferState state,
                              const std::string &id,
                              const std::string &result,
                              uint64_t offset,
                              std::string &err)
{
    // Only allow SUCCESS or FAILED states
    if (state != TransferState::SUCCESS && state != TransferState::FAILED) {
        err = "Final transfer state must be SUCCESS or FAILED";
        return false;
    }

    auto updated_at = static_cast<sqlite3_uint64>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
    

    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        err = "Failed to open database";
        return false;
    }

    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        return false;
    }
    const char *update_sql =
        "UPDATE transfers SET status = ?, updated_at = ?, bytes_transferred = ? WHERE transfer_id = ?;";
    sqlite3_stmt *stmt = nullptr;
    rc = sqlite3_prepare_v2(db, update_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_bind_int(stmt, 1, static_cast<int>(state));
    sqlite3_bind_int64(stmt, 2, updated_at);
    sqlite3_bind_int64(stmt, 3, offset);
    sqlite3_bind_text(stmt, 4, id.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        err = sqlite3_errmsg(db);
        sqlite3_finalize(stmt);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    sqlite3_finalize(stmt);

    if (!result.empty()) {
        const char *insert_sql =
            "INSERT INTO transfer_messages (transfer_id, message) VALUES (?, ?);";
        sqlite3_stmt *msg_stmt = nullptr;
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &msg_stmt, nullptr);
        if (rc != SQLITE_OK) {
            err = sqlite3_errmsg(db);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }
        sqlite3_bind_text(msg_stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(msg_stmt, 2, result.c_str(), -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(msg_stmt);
        if (rc == SQLITE_DONE) {
            // Successfully inserted new message
            sqlite3_finalize(msg_stmt);
        } else if (rc == SQLITE_CONSTRAINT) {
            // Row exists, update the message instead
            sqlite3_finalize(msg_stmt);
            const char *update_msg_sql =
            "UPDATE transfer_messages SET message = ? WHERE transfer_id = ?;";
            rc = sqlite3_prepare_v2(db, update_msg_sql, -1, &msg_stmt, nullptr);
            if (rc != SQLITE_OK) {
                err = sqlite3_errmsg(db);
                sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
                return false;
            }
            sqlite3_bind_text(msg_stmt, 1, result.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(msg_stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
            rc = sqlite3_step(msg_stmt);
            if (rc != SQLITE_DONE) {
                err = sqlite3_errmsg(db);
                sqlite3_finalize(msg_stmt);
                sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
                return false;
            }
            sqlite3_finalize(msg_stmt);
        } else {
            err = sqlite3_errmsg(db);
            sqlite3_finalize(msg_stmt);
            sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
            return false;
        }
    }

    rc = sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        err = errmsg ? errmsg : "Unknown error";
        if (errmsg) sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK;", nullptr, nullptr, nullptr);
        return false;
    }

    return true;
}
bool
WritebackDB::GetTransferStatus(const std::string &id, TransferState &state, uint64_t &bytes_transferred, std::string &msg, std::string &err)
{
    DatabaseRef dbref;
    sqlite3 *db = dbref.GetHandle();
    if (!db) {
        err = "Failed to open database";
        return false;
    }

    // Single query joining transfers and transfer_messages (latest message)
    const char *select_sql =
        "SELECT t.status, t.bytes_transferred, m.message "
        "FROM transfers t "
        "LEFT JOIN ("
        "  SELECT transfer_id, message "
        "  FROM transfer_messages "
        "  WHERE transfer_id = ? "
        "  ORDER BY id DESC LIMIT 1"
        ") m ON t.transfer_id = m.transfer_id "
        "WHERE t.transfer_id = ?;";
    sqlite3_stmt *stmt = nullptr;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        err = sqlite3_errmsg(db);
        return false;
    }
    // Bind transfer_id for both ? placeholders
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        state = static_cast<TransferState>(sqlite3_column_int(stmt, 0));
        bytes_transferred = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL && sqlite3_column_text(stmt, 2)) {
            msg = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        } else {
            msg.clear();
        }
    } else {
        err = "Transfer ID not found";
        sqlite3_finalize(stmt);
        return false;
    }
    sqlite3_finalize(stmt);

    return true;
}
