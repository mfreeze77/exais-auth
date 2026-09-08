package org.expertauth.keycloak;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticator;

/** Delegates verification and non-reusable-code state to Keycloak's OTP provider. */
public final class JsonOtpAuthenticator extends OTPFormAuthenticator {
    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        return JsonChallenge.render(context, "totp", error != null);
    }
}
