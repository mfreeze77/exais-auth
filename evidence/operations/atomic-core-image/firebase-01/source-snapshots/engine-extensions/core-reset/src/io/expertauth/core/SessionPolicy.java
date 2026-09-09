/* Copyright (c) 2026 ExpertAuth contributors. SPDX-License-Identifier: Apache-2.0 */
package io.expertauth.core;

import io.supertokens.Main;
import io.supertokens.config.Config;
import io.supertokens.config.CoreConfig;
import io.supertokens.pluginInterface.multitenancy.TenantIdentifier;
import io.supertokens.pluginInterface.multitenancy.exceptions.TenantOrAppNotFoundException;

/** Request-selected constraint on the existing engine, not another session store. */
public final class SessionPolicy {
    public static final String ID = "OSS-CDI56-GRACE5-V1";
    private SessionPolicy() {}

    public static final class Rejected extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        public Rejected() { super("Required session policy is unavailable"); }
    }

    public static CoreConfig requireConfig(TenantIdentifier tenant, Main main, String expected)
            throws TenantOrAppNotFoundException {
        CoreConfig config = Config.getConfig(tenant, main);
        if (expected != null && (!ID.equals(expected) || !TenantIdentifier.DEFAULT_TENANT_ID.equals(tenant.getTenantId()) ||
                config.getRefreshTokenRotationGracePeriodInSeconds() != 5 ||
                !"TOKEN_THEFT".equals(config.getRecentTokenReuseBehaviour()))) {
            throw new Rejected();
        }
        // Refresh uses this exact CoreConfig object for its transaction's policy
        // decisions. There is no preflight-to-operation configuration re-read.
        return config;
    }
}
