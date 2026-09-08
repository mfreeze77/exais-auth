package org.expertauth.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;

/** Rendering boundary only: Keycloak creates and validates all action/session state. */
final class JsonChallenge {
    private JsonChallenge() { }

    static Response render(AuthenticationFlowContext context, String step, boolean failed) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "CHALLENGE");
        result.put("step", step);
        result.put("authenticated", false);
        result.put("action", context.getActionUrl(context.generateAccessCode()).toString());
        result.put("method", "POST");
        result.put("contentType", "application/x-www-form-urlencoded");
        result.put("fields", step.equals("password") ? List.of("username", "password") : List.of("otp"));
        if (failed) {
            // Do not reveal whether the username exists or which lockout condition
            // caused password rejection. Engine event/audit handling is inherited.
            result.put("error", "AUTHENTICATION_FAILED");
        }
        return Response.status(failed ? 401 : 200)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache")
                .header("Referrer-Policy", "no-referrer")
                .entity(result).build();
    }
}
