package org.expertauth.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;

public final class JsonPasswordFactory extends UsernamePasswordFormFactory {
    @Override public String getId() { return "expertauth-json-password"; }
    @Override public String getDisplayType() { return "ExpertAuth JSON password challenge"; }
    @Override public String getHelpText() { return "Engine-owned password flow with first-party JSON challenges."; }
    @Override public Authenticator create(KeycloakSession session) { return new JsonPasswordAuthenticator(); }
}
