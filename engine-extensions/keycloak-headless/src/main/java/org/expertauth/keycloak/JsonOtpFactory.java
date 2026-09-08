package org.expertauth.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.OTPFormAuthenticatorFactory;
import org.keycloak.models.KeycloakSession;

public final class JsonOtpFactory extends OTPFormAuthenticatorFactory {
    @Override public String getId() { return "expertauth-json-totp"; }
    @Override public String getDisplayType() { return "ExpertAuth JSON TOTP challenge"; }
    @Override public String getHelpText() { return "Engine-owned OTP validation and replay policy with JSON challenges."; }
    @Override public Authenticator create(KeycloakSession session) { return new JsonOtpAuthenticator(); }
}
