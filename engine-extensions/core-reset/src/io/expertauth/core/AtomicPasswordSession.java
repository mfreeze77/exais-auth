/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import com.google.gson.JsonObject;
import io.supertokens.Main;
import io.supertokens.authRecipe.AuthRecipe;
import io.supertokens.pluginInterface.RECIPE_ID;
import io.supertokens.pluginInterface.Storage;
import io.supertokens.pluginInterface.authRecipe.AuthRecipeUserInfo;
import io.supertokens.pluginInterface.authRecipe.LoginMethod;
import io.supertokens.pluginInterface.authRecipe.sqlStorage.AuthRecipeSQLStorage;
import io.supertokens.pluginInterface.emailpassword.sqlStorage.EmailPasswordSQLStorage;
import io.supertokens.pluginInterface.exceptions.StorageQueryException;
import io.supertokens.pluginInterface.exceptions.StorageTransactionLogicException;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.multitenancy.exceptions.TenantOrAppNotFoundException;
import io.supertokens.pluginInterface.sqlStorage.SQLStorage;
import io.supertokens.pluginInterface.useridmapping.UserIdMapping;
import io.supertokens.pluginInterface.useridmapping.UserLockingStorage;
import io.supertokens.pluginInterface.useridmapping.UserNotFoundForLockingException;
import io.supertokens.pluginInterface.useridmapping.sqlStorage.UserIdMappingSQLStorage;
import io.supertokens.session.Session;
import io.supertokens.session.accessToken.AccessToken;
import io.supertokens.session.info.SessionInformationHolder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Reuses Core token minting; credential revalidation and session insertion share one commit. */
public final class AtomicPasswordSession {
    public static final String POLICY = "EXPERTAUTH-PASSWORD-SESSION-1";
    private AtomicPasswordSession() {}

    @FunctionalInterface public interface Insert {
        void insert(String handle, String recipeId, String primaryId, String refreshHash2,
            JsonObject databaseData, long expiry, JsonObject jwtData, long created, boolean staticKey)
            throws StorageQueryException, StorageTransactionLogicException, TenantOrAppNotFoundException;
    }

    public static class Rejected extends Exception {
        public Rejected() { super("PASSWORD_SESSION_REJECTED"); }
    }

    /** The verified hash was replaced before the commit, for example by a concurrent on-login rehash. */
    public static final class HashChanged extends Rejected {}

    private static boolean hashChanged(Throwable error) {
        for (int depth = 0; error != null && depth < 8; depth++) {
            if (error instanceof HashChanged) return true;
            error = error instanceof StorageTransactionLogicException logic && logic.actualException != null
                ? logic.actualException : error.getCause();
        }
        return false;
    }

    public static TransactionalSessionWriter writer(Storage storage) throws Rejected {
        if (!(storage instanceof SQLStorage && storage instanceof AuthRecipeSQLStorage && storage instanceof EmailPasswordSQLStorage &&
              storage instanceof UserLockingStorage && storage instanceof UserIdMappingSQLStorage)) throw new Rejected();
        TransactionalSessionWriter selected = null;
        // A loader is local to this call; ServiceLoader itself is not thread-safe.
        for (TransactionalSessionWriter candidate : ServiceLoader.load(TransactionalSessionWriter.class, storage.getClass().getClassLoader())) {
            if (candidate.supports(storage)) {
                if (selected != null) throw new Rejected();
                selected = candidate;
            }
        }
        if (selected == null) throw new Rejected();
        return selected;
    }

    private static LoginMethod method(AuthRecipeUserInfo user, TenantIdentifier tenant, String id, String email)
            throws Rejected {
        if (user == null || !user.tenantIds.contains(tenant.getTenantId())) throw new Rejected();
        LoginMethod found = null;
        for (LoginMethod m : user.loginMethods) {
            if (m.recipeId == RECIPE_ID.EMAIL_PASSWORD && id.equals(m.getSupertokensUserId()) &&
                email.equals(m.email) && m.tenantIds.contains(tenant.getTenantId())) {
                if (found != null) throw new Rejected();
                found = m;
            }
        }
        if (found == null || found.passwordHash == null) throw new Rejected();
        return found;
    }

    /**
     * One bounded retry when the only failure is a changed hash: the retry re-reads the user and
     * re-verifies the password against the new hash, so a concurrent reset still rejects.
     */
    public static SessionInformationHolder create(Main main, Storage storage, TenantIdentifier tenant,
            String internalRecipeId, String publicRecipeId, String email, String password,
            JsonObject jwt, JsonObject databaseData, boolean csrf, AccessToken.VERSION version, boolean staticKey,
            Long validity) throws Exception {
        try {
            return attempt(main, storage, tenant, internalRecipeId, publicRecipeId, email, password, jwt, databaseData, csrf, version, staticKey, validity);
        } catch (Exception error) {
            if (!hashChanged(error)) throw error;
            return attempt(main, storage, tenant, internalRecipeId, publicRecipeId, email, password, jwt, databaseData, csrf, version, staticKey, validity);
        }
    }

    private static SessionInformationHolder attempt(Main main, Storage storage, TenantIdentifier tenant,
            String internalRecipeId, String publicRecipeId, String email, String password,
            JsonObject jwt, JsonObject databaseData, boolean csrf, AccessToken.VERSION version, boolean staticKey,
            Long validity) throws Exception {
        TransactionalSessionWriter writer = writer(storage);
        if (password.isEmpty() || password.getBytes(StandardCharsets.UTF_8).length > 4096) throw new Rejected();
        AuthRecipeUserInfo observed = AuthRecipe.getUserById(tenant.toAppIdentifier(), storage, internalRecipeId);
        LoginMethod observedMethod = method(observed, tenant, internalRecipeId, email);
        PasswordUpgrade.Outcome verified = PasswordUpgrade.check(main, tenant.toAppIdentifier(), password, observedMethod.passwordHash);
        if (!verified.accepted()) throw new Rejected();

        // Password hashing and rehash preparation, Core key lookup/minting and identity mapping happen
        // before acquiring a row lock. The callback does no nested pool borrow.
        // No tokens leave Core until this callback's transaction commits.
        return Session.createNewSessionWithWriter(tenant, storage, main, publicRecipeId, jwt, databaseData,
            csrf, version, staticKey, validity,
            (handle, recipeId, primaryId, refreshHash2, dbData, expiry, jwtData, created, useStatic) -> {
                ((SQLStorage) storage).startTransaction(transaction -> {
                    try {
                        ((UserLockingStorage) storage).lockUser(tenant.toAppIdentifier(), transaction, internalRecipeId);
                        AuthRecipeUserInfo current = ((AuthRecipeSQLStorage) storage).getPrimaryUserById_Transaction(
                            tenant.toAppIdentifier(), transaction, internalRecipeId);
                        LoginMethod currentMethod = method(current, tenant, internalRecipeId, email);
                        if (!observed.getSupertokensUserId().equals(current.getSupertokensUserId())) throw new Rejected();
                        if (!observedMethod.passwordHash.equals(currentMethod.passwordHash)) throw new HashChanged();
                        // A legacy-decoded or outdated hash is replaced in the same commit as the session.
                        if (verified.replacementHash() != null && !PasswordUpgrade.replace(storage, tenant.toAppIdentifier(),
                                transaction, internalRecipeId, observedMethod.passwordHash, verified.replacementHash())) throw new HashChanged();
                        List<String> ids = new ArrayList<>(new LinkedHashSet<>(List.of(internalRecipeId, current.getSupertokensUserId())));
                        Map<String, String> publicIds = new HashMap<>();
                        for (UserIdMapping mapping : ((UserIdMappingSQLStorage) storage).getMultipleUserIdMapping_Transaction(
                                transaction, tenant.toAppIdentifier(), ids, true)) publicIds.put(mapping.superTokensUserId, mapping.externalUserId);
                        if (!recipeId.equals(publicIds.getOrDefault(internalRecipeId, internalRecipeId)) ||
                            !primaryId.equals(publicIds.getOrDefault(current.getSupertokensUserId(), current.getSupertokensUserId()))) throw new Rejected();
                        writer.insert(storage, tenant, transaction, handle, recipeId, refreshHash2, dbData, expiry, jwtData, created, useStatic);
                        ((SQLStorage) storage).commitTransaction(transaction);
                        return null;
                    } catch (Exception error) {
                        throw new StorageTransactionLogicException(error);
                    }
                });
            });
    }
}
