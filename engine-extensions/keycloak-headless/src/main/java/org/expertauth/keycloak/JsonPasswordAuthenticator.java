package org.expertauth.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;

/** Uses the upstream password action and brute-force enforcement unchanged. */
public final class JsonPasswordAuthenticator extends UsernamePasswordForm {
    public JsonPasswordAuthenticator() {
        // This bounded password/TOTP profile does not activate conditional passkeys.
        super();
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> data) {
        return JsonChallenge.render(context, "password", false);
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        return JsonChallenge.render(context, "password", error != null);
    }
}
