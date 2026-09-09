/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import com.google.gson.JsonObject;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.sqlStorage.TransactionConnection;

/** Storage plugin extension: one session insert on the caller's existing transaction. */
public interface TransactionalSessionWriter {
    boolean supports(Storage storage);
    void insert(Storage storage, TenantIdentifier tenant, TransactionConnection transaction,
        String handle, String recipeId, String refreshHash2, JsonObject databaseData, long expiry,
        JsonObject jwtData, long created, boolean staticKey) throws StorageQueryException;
}
