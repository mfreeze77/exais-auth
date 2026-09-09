/*
 * Copyright (c) 2026 ExpertAuth contributors.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Independently authored orchestration using the audited Apache-2.0 Core and
 * plugin interfaces. See reuse.json for exact upstream files and source pins.
 * No entitlement checks, cryptographic primitives or identity stores are replaced.
 */
package io.expertauth.core;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.authRecipe.AuthRecipe;
import io.supertokens.config.Config;
import io.supertokens.emailpassword.PasswordHashing;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.authRecipe.AuthRecipeUserInfo;
import io.supertokens.pluginInterface.authRecipe.LoginMethod;
import io.supertokens.pluginInterface.authRecipe.sqlStorage.AuthRecipeSQLStorage;
import io.supertokens.pluginInterface.emailpassword.PasswordResetTokenInfo;
import io.supertokens.pluginInterface.emailpassword.exceptions.DuplicatePasswordResetTokenException;
import io.supertokens.pluginInterface.emailpassword.sqlStorage.EmailPasswordSQLStorage;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.session.sqlStorage.SessionSQLStorage;
import io.supertokens.pluginInterface.useridmapping.UserIdMapping;
import io.supertokens.pluginInterface.useridmapping.UserLockingStorage;
import io.supertokens.pluginInterface.useridmapping.UserNotFoundForLockingException;
import io.supertokens.pluginInterface.useridmapping.sqlStorage.UserIdMappingSQLStorage;
import io.supertokens.storageLayer.StorageLayer;
import io.supertokens.utils.Utils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Engine-owned token consumption, password update and existing-session deletion. */
public final class AtomicPasswordReset {
    public static final String POLICY = "EXPERTAUTH-ATOMIC-RESET-1";
    private static final SecureRandom RANDOM = new SecureRandom();

    private AtomicPasswordReset() {}

    public static final class Rejected extends Exception {
        public final String status;
        public Rejected(String status) { super(status); this.status = status; }
    }

    private static void requireStorage(Storage storage) throws Rejected {
        if (!(storage instanceof EmailPasswordSQLStorage && storage instanceof AuthRecipeSQLStorage &&
              storage instanceof SessionSQLStorage && storage instanceof UserLockingStorage &&
              storage instanceof UserIdMappingSQLStorage)) {
            throw new Rejected("ATOMIC_RESET_STORAGE_UNSUPPORTED");
        }
    }

    private static LoginMethod method(AuthRecipeUserInfo user, String id, String email,
                                      TenantIdentifier tenant) throws Rejected {
        if (user == null || email == null || !user.tenantIds.contains(tenant.getTenantId())) {
            throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
        }
        LoginMethod selected = null;
        for (LoginMethod entry : user.loginMethods) {
            if (entry.recipeId == RECIPE_ID.EMAIL_PASSWORD && email.equals(entry.email) &&
                entry.tenantIds.contains(tenant.getTenantId()) &&
                (id.equals(user.getSupertokensUserId()) || id.equals(entry.getSupertokensUserId()))) {
                if (selected != null) throw new Rejected("RESET_IDENTITY_AMBIGUOUS");
                selected = entry;
            }
        }
        if (selected == null) throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
        return selected;
    }

    private static String prefix(TenantIdentifier tenant, AuthRecipeUserInfo user, LoginMethod method)
            throws Exception {
        // The entire opaque token, including this context digest, is hashed in
        // the existing engine token table. Editing context cannot retarget it.
        JsonArray context = new JsonArray();
        context.add(POLICY); context.add(tenant.getConnectionUriDomain());
        context.add(tenant.getAppId()); context.add(tenant.getTenantId());
        context.add(user.getSupertokensUserId()); context.add(method.getSupertokensUserId());
        context.add(method.email);
        return "ear1." + Utils.hashSHA256(context.toString()) + ".";
    }

    public static String issue(Main main, TenantIdentifier tenant, Storage storage, String id, String email)
            throws Exception {
        requireStorage(storage);
        AuthRecipeUserInfo user = AuthRecipe.getUserById(tenant.toAppIdentifier(), storage, id);
        LoginMethod selected = method(user, id, email, tenant);
        long expiry = Math.addExact(System.currentTimeMillis(), Config.getConfig(tenant, main).getPasswordResetTokenLifetime());
        String prefix = prefix(tenant, user, selected);
        for (int attempt = 0; attempt < 4; attempt++) {
            byte[] secret = new byte[64]; RANDOM.nextBytes(secret);
            String token = prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(secret);
            try {
                ((EmailPasswordSQLStorage) storage).addPasswordResetToken(tenant.toAppIdentifier(),
                    new PasswordResetTokenInfo(selected.getSupertokensUserId(), Utils.hashSHA256(token), expiry, selected.email));
                return token;
            } catch (DuplicatePasswordResetTokenException collision) {
                // A bounded retry of secure randomness; no existing token is replaced.
            }
        }
        throw new Rejected("RESET_TOKEN_CREATION_FAILED");
    }

    public static JsonObject consume(Main main, TenantIdentifier tenant, Storage storage,
                                     String token, String password) throws Exception {
        requireStorage(storage);
        if (token == null || !token.matches("ear1\\.[0-9a-f]{64}\\.[A-Za-z0-9_-]{86}")) {
            throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
        }
        if (password == null || password.isEmpty() || password.getBytes(StandardCharsets.UTF_8).length > 4096) {
            throw new Rejected("PASSWORD_INPUT_INVALID");
        }
        EmailPasswordSQLStorage passwords = (EmailPasswordSQLStorage) storage;
        String tokenHash = Utils.hashSHA256(token);
        PasswordResetTokenInfo observed = passwords.getPasswordResetTokenInfo(tenant.toAppIdentifier(), tokenHash);
        if (observed == null || observed.tokenExpiry <= System.currentTimeMillis()) {
            throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
        }
        // Reuse Core's configured password hasher outside the row-lock interval.
        String passwordHash = PasswordHashing.getInstance(main).createHashWithSalt(tenant.toAppIdentifier(), password);
        try {
            return passwords.startTransaction(transaction -> {
                try {
                    ((UserLockingStorage) storage).lockUser(tenant.toAppIdentifier(), transaction, observed.userId);
                    AuthRecipeUserInfo user = ((AuthRecipeSQLStorage) storage).getPrimaryUserById_Transaction(
                        tenant.toAppIdentifier(), transaction, observed.userId);
                    PasswordResetTokenInfo matched = null;
                    for (PasswordResetTokenInfo row : passwords.getAllPasswordResetTokenInfoForUser_Transaction(
                            tenant.toAppIdentifier(), transaction, observed.userId)) {
                        if (row.token.equals(tokenHash)) { matched = row; break; }
                    }
                    if (matched == null || matched.tokenExpiry <= System.currentTimeMillis()) {
                        throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
                    }
                    LoginMethod selected = method(user, matched.userId, matched.email, tenant);
                    if (!token.startsWith(prefix(tenant, user, selected))) {
                        throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
                    }
                    // One transaction can cover only one actual identity pool.
                    // Cross-pool sharing is refused rather than partially revoked.
                    for (String tenantId : user.tenantIds) {
                        Storage sibling = StorageLayer.getStorage(new TenantIdentifier(
                            tenant.getConnectionUriDomain(), tenant.getAppId(), tenantId), main);
                        if (!storage.getUserPoolId().equals(sibling.getUserPoolId())) {
                            throw new Rejected("RESET_IDENTITY_STORAGE_BOUNDARY_ERROR");
                        }
                    }
                    Set<String> ids = new LinkedHashSet<>();
                    ids.add(user.getSupertokensUserId());
                    for (LoginMethod entry : user.loginMethods) ids.add(entry.getSupertokensUserId());
                    List<UserIdMapping> mappings = ((UserIdMappingSQLStorage) storage).getMultipleUserIdMapping_Transaction(
                        transaction, tenant.toAppIdentifier(), new ArrayList<>(ids), true);
                    HashMap<String, String> publicIds = new HashMap<>();
                    for (UserIdMapping mapping : mappings) publicIds.put(mapping.superTokensUserId, mapping.externalUserId);

                    passwords.updateUsersPassword_Transaction(tenant.toAppIdentifier(), transaction,
                        selected.getSupertokensUserId(), passwordHash);
                    for (String id : ids) {
                        passwords.deleteAllPasswordResetTokensForUser_Transaction(tenant.toAppIdentifier(), transaction, id);
                    }
                    ids.addAll(publicIds.values());
                    for (String id : ids) {
                        ((SessionSQLStorage) storage).deleteSessionsOfUser_Transaction(transaction, tenant.toAppIdentifier(), id);
                    }
                    JsonObject result = new JsonObject();
                    result.addProperty("status", "OK"); result.addProperty("policy", POLICY);
                    result.addProperty("userId", publicIds.getOrDefault(user.getSupertokensUserId(), user.getSupertokensUserId()));
                    result.addProperty("recipeUserId", publicIds.getOrDefault(selected.getSupertokensUserId(), selected.getSupertokensUserId()));
                    result.addProperty("email", selected.email);
                    passwords.commitTransaction(transaction);
                    return result;
                } catch (Rejected | UserNotFoundForLockingException error) {
                    throw new StorageTransactionLogicException(error);
                } catch (Exception error) {
                    // Includes context-hash/config/mapping/storage failures. Never
                    // commit a partial reset or serialize an upstream exception.
                    throw new StorageTransactionLogicException(error);
                }
            });
        } catch (StorageTransactionLogicException error) {
            if (error.actualException instanceof Rejected) throw (Rejected) error.actualException;
            if (error.actualException instanceof UserNotFoundForLockingException) {
                throw new Rejected("RESET_PASSWORD_INVALID_TOKEN_ERROR");
            }
            throw error;
        }
    }
}
