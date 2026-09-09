/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.StorageAndUserIdMapping;
import io.supertokens.useridmapping.UserIdType;
import io.supertokens.webserver.InputParser;
import io.supertokens.webserver.WebserverAPI;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Private Core API; inherited API-key, app, tenant and recipe guards remain active. */
public final class AtomicPasswordResetAPI extends WebserverAPI {
    private static final long serialVersionUID = 1L;
    private final boolean issue;
    public AtomicPasswordResetAPI(Main main, boolean issue) {
        super(main, RECIPE_ID.EMAIL_PASSWORD.toString()); this.issue = issue;
    }
    @Override public String getPath() {
        return issue ? "/expertauth/password/reset/token" : "/expertauth/password/reset";
    }
    @Override protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        JsonObject input = InputParser.parseJsonObjectOrThrowError(request);
        JsonObject result;
        try {
            TenantIdentifier tenant = getTenantIdentifier(request);
            io.supertokens.webserver.api.emailpassword.Utils.assertIfEmailPasswordIsEnabledForTenant(
                main, tenant, getVersionFromRequest(request));
            if (issue) {
                String userId = InputParser.parseStringOrThrowError(input, "userId", false);
                String email = InputParser.parseStringOrThrowError(input, "email", false);
                StorageAndUserIdMapping resolved = getStorageAndUserIdMappingForTenantSpecificApi(request, userId, UserIdType.ANY);
                if (resolved.userIdMapping != null) userId = resolved.userIdMapping.superTokensUserId;
                String token = AtomicPasswordReset.issue(main, tenant, resolved.storage, userId, email);
                result = new JsonObject(); result.addProperty("status", "OK");
                result.addProperty("policy", AtomicPasswordReset.POLICY); result.addProperty("token", token);
            } else {
                String token = InputParser.parseStringOrThrowError(input, "token", false);
                String password = InputParser.parseStringOrThrowError(input, "newPassword", false);
                result = AtomicPasswordReset.consume(main, tenant, getTenantStorage(request), token, password);
            }
        } catch (AtomicPasswordReset.Rejected error) {
            result = new JsonObject(); result.addProperty("status", error.status);
        } catch (ServletException error) {
            throw error;
        } catch (Exception error) {
            // Private response stays fixed even for transaction/storage failures.
            result = new JsonObject(); result.addProperty("status", "ATOMIC_RESET_OPERATION_FAILED");
            response.setHeader("Cache-Control", "no-store");
            sendJsonResponse(500, result, response); return;
        }
        response.setHeader("Cache-Control", "no-store");
        sendJsonResponse(200, result, response);
    }
}
