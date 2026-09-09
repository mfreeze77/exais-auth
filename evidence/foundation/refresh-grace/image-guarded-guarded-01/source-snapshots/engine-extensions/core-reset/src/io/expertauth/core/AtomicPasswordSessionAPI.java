/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.StorageAndUserIdMapping;
import io.supertokens.config.Config;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.session.accessToken.AccessToken;
import io.supertokens.useridmapping.UserIdType;
import io.supertokens.utils.SemVer;
import io.supertokens.webserver.InputParser;
import io.supertokens.webserver.WebserverAPI;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/** Private API; no browser credentials or tokens bypass the inherited Core authorization. */
public final class AtomicPasswordSessionAPI extends WebserverAPI {
    private static final long serialVersionUID = 1L;
    public AtomicPasswordSessionAPI(Main main) { super(main, RECIPE_ID.SESSION.toString()); }
    @Override public String getPath() { return "/expertauth/password/session"; }
    @Override protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try {
            AtomicPasswordSession.writer(getTenantStorage(request));
            JsonObject result = new JsonObject(); result.addProperty("status", "OK"); result.addProperty("policy", AtomicPasswordSession.POLICY);
            // These are effective engine settings for the authenticated request's
            // tenant, not a second policy store or a claim inferred from CDI support.
            var config = Config.getConfig(getTenantIdentifier(request), main);
            JsonObject session = new JsonObject();
            session.addProperty("refreshTokenRotationGracePeriodSeconds", config.getRefreshTokenRotationGracePeriodInSeconds());
            session.addProperty("recentTokenReuseBehaviour", config.getRecentTokenReuseBehaviour());
            result.add("sessionPolicy", session);
            result.addProperty("guardedSessionOperations", SessionPolicy.ID);
            response.setHeader("Cache-Control", "no-store"); sendJsonResponse(200, result, response);
        } catch (Exception | java.util.ServiceConfigurationError error) { failure(response); }
    }
    @Override protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        JsonObject input = InputParser.parseJsonObjectOrThrowError(request);
        try {
            SemVer version = getVersionFromRequest(request);
            if (!version.equals(SemVer.v5_4)) throw new AtomicPasswordSession.Rejected();
            var tenant = getTenantIdentifier(request);
            io.supertokens.webserver.api.emailpassword.Utils.assertIfEmailPasswordIsEnabledForTenant(main, tenant, version);
            String publicId = InputParser.parseStringOrThrowError(input, "userId", false);
            StorageAndUserIdMapping resolved = getStorageAndUserIdMappingForTenantSpecificApi(request, publicId, UserIdType.ANY);
            String internalId = resolved.userIdMapping == null ? publicId : resolved.userIdMapping.superTokensUserId;
            String email = io.supertokens.utils.Utils.normaliseEmail(InputParser.parseStringOrThrowError(input, "email", false));
            String password = InputParser.parseStringOrThrowError(input, "password", false);
            Boolean csrf = InputParser.parseBooleanOrThrowError(input, "enableAntiCsrf", false);
            Boolean dynamic = InputParser.parseBooleanOrThrowError(input, "useDynamicSigningKey", true);
            JsonObject jwt = InputParser.parseJsonObjectOrThrowError(input, "userDataInJWT", false);
            JsonObject dbData = InputParser.parseJsonObjectOrThrowError(input, "userDataInDatabase", false);
            JsonObject result = AtomicPasswordSession.create(main, resolved.storage, tenant, internalId, publicId, email, password,
                jwt, dbData, csrf, AccessToken.getAccessTokenVersionForCDI(version), Boolean.FALSE.equals(dynamic), null).toJsonObject();
            result.remove("idRefreshToken"); result.addProperty("status", "OK"); result.addProperty("policy", AtomicPasswordSession.POLICY);
            response.setHeader("Cache-Control", "no-store"); sendJsonResponse(200, result, response);
        } catch (ServletException error) { throw error; }
        catch (Exception | java.util.ServiceConfigurationError error) { failure(response); }
    }
    private void failure(HttpServletResponse response) throws IOException {
        JsonObject result = new JsonObject(); result.addProperty("status", "PASSWORD_SESSION_REJECTED");
        response.setHeader("Cache-Control", "no-store"); sendJsonResponse(503, result, response);
    }
}
