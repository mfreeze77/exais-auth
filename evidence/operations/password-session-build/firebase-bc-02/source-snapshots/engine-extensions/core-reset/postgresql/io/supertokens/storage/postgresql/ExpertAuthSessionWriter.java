/*
 * Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.
 * Copyright (c) 2026 ExpertAuth contributors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Adapted from the pinned Apache-2.0 SessionQueries.createNewSession insert.
 * The same columns/values now use the caller's existing transaction connection.
 * No separate connection, commit, credential store or refresh state is created.
 */
package io.supertokens.storage.postgresql;

import com.google.gson.JsonObject;
import io.expertauth.core.TransactionalSessionWriter;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.sqlStorage.TransactionConnection;
import io.supertokens.storage.postgresql.config.Config;
import java.sql.Connection;
import java.sql.SQLException;

public final class ExpertAuthSessionWriter implements TransactionalSessionWriter {
    public ExpertAuthSessionWriter() {}
    @Override public boolean supports(Storage storage) { return storage instanceof Start; }
    @Override public void insert(Storage storage, TenantIdentifier tenant, TransactionConnection transaction,
            String handle, String recipeId, String refreshHash2, JsonObject databaseData, long expiry,
            JsonObject jwtData, long created, boolean staticKey) throws StorageQueryException {
        if (!(storage instanceof Start start) || !(transaction.getConnection() instanceof Connection connection)) {
            throw new StorageQueryException(new SQLException("Unsupported transactional session storage"));
        }
        try {
            if (connection.getAutoCommit()) throw new SQLException("Session insert requires an active transaction");
            String query = "INSERT INTO " + Config.getConfig(start).getSessionInfoTable()
                + "(app_id, tenant_id, session_handle, user_id, refresh_token_hash_2, session_data, expires_at,"
                + " jwt_user_payload, created_at_time, use_static_key) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            int changed = QueryExecutorTemplate.update(connection, query, statement -> {
                statement.setString(1, tenant.getAppId()); statement.setString(2, tenant.getTenantId());
                statement.setString(3, handle); statement.setString(4, recipeId); statement.setString(5, refreshHash2);
                statement.setString(6, databaseData.toString()); statement.setLong(7, expiry);
                statement.setString(8, jwtData.toString()); statement.setLong(9, created); statement.setBoolean(10, staticKey);
            });
            if (changed != 1) throw new SQLException("Session insert count differs");
        } catch (SQLException error) { throw new StorageQueryException(error); }
    }
}
