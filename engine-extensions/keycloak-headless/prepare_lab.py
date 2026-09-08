"""Create private synthetic Keycloak import fixtures; never package .runtime/."""
import base64
import argparse
import json
import pathlib
import secrets
import uuid

ROOT = pathlib.Path(__file__).resolve().parent
runtime = ROOT / ".runtime"
parser = argparse.ArgumentParser()
parser.add_argument("--replace-generated-fixtures", action="store_true", help="Replace this isolated lab's generated synthetic credentials before recreating its container")
args = parser.parse_args()
if runtime.exists() and not args.replace_generated_fixtures:
    raise SystemExit("Lab fixtures already exist; reuse them or select a fresh isolated lab directory explicitly")
runtime.mkdir(exist_ok=True)
fixtures = {"realm": "expertauth-headless-proof", "client_id": "headless-proof-client", "redirect_uri": "http://headless-client.example.test/callback", "users": {}}
users = []
for name in ("primary", "bruteforce", "replay", "missingaction", "tamperedaction", "crosssession", "nocookie", "missingotp", "client-python", "client-browser", "client-negative", "client-audit"):
    password = "P9!" + secrets.token_urlsafe(24)
    otp_secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
    fixtures["users"][name] = {"username": "proof-" + name, "password": password, "otp_secret": otp_secret}
    users.append({"id": str(uuid.uuid4()), "username": "proof-" + name, "enabled": True, "email": name + "@example.invalid", "emailVerified": True, "firstName": "Synthetic", "lastName": "Proof", "credentials": [{"type": "password", "value": password, "temporary": False}, {"id": str(uuid.uuid4()), "type": "otp", "userLabel": "Synthetic proof TOTP", "secretData": json.dumps({"value": otp_secret}), "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA1", "secretEncoding": "BASE32"})}]})
realm = {"realm": fixtures["realm"], "enabled": True, "registrationAllowed": False, "resetPasswordAllowed": False, "rememberMe": False, "sslRequired": "none", "loginWithEmailAllowed": True, "duplicateEmailsAllowed": False, "bruteForceProtected": True, "permanentLockout": False, "failureFactor": 3, "waitIncrementSeconds": 60, "minimumQuickLoginWaitSeconds": 60, "maxFailureWaitSeconds": 60, "quickLoginCheckMilliSeconds": 0, "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 0, "otpPolicyCodeReusable": False, "browserFlow": "expertauth-json-browser", "authenticationFlows": [{"alias": "expertauth-json-browser", "description": "Isolated candidate JSON password and required TOTP SPI proof", "providerId": "basic-flow", "topLevel": True, "builtIn": False, "authenticationExecutions": [{"authenticator": "expertauth-json-password", "authenticatorFlow": False, "requirement": "REQUIRED", "priority": 10, "userSetupAllowed": False}, {"authenticator": "expertauth-json-totp", "authenticatorFlow": False, "requirement": "REQUIRED", "priority": 20, "userSetupAllowed": False}]}], "clients": [{"clientId": fixtures["client_id"], "enabled": True, "protocol": "openid-connect", "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "redirectUris": [fixtures["redirect_uri"]], "webOrigins": ["http://headless-client.example.test"], "attributes": {"pkce.code.challenge.method": "S256"}}], "users": users}
realm["organizationsEnabled"] = True
realm["organizations"] = [{"id": str(uuid.uuid4()), "name": "alpha", "alias": "alpha", "enabled": True, "members": [{"username": "proof-" + name, "membershipType": "UNMANAGED"} for name in ("client-python", "client-browser", "client-negative", "client-audit")]}]
realm["clients"].append({"clientId": "expertauth-node-candidate", "enabled": True, "protocol": "openid-connect", "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "serviceAccountsEnabled": False, "redirectUris": ["http://expertauth-kc-clients-node:3000/candidate/callback"], "webOrigins": ["http://expertauth-kc-clients-node:3000"], "optionalClientScopes": ["organization"], "attributes": {"pkce.code.challenge.method": "S256"}, "protocolMappers": [{"name": "candidate-resource-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "expertauth-candidate-api", "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true"}}]})
fixtures["dedicated_candidate_client"] = {"client_id": "expertauth-node-candidate", "redirect_uri": "http://expertauth-kc-clients-node:3000/candidate/callback", "scope": "openid organization:alpha", "resource_audience": "expertauth-candidate-api", "organization": "alpha", "members": ["client-python", "client-browser", "client-negative", "client-audit"]}
# Explicit optional scopes suppress Keycloak's implicit default-scope assignment.
# Retain the maintained basic scope so access tokens carry a signed subject.
realm["clients"][-1]["defaultClientScopes"] = ["basic"]
(runtime / "realm-import.json").write_text(json.dumps(realm, indent=2) + "\n")
(runtime / "fixtures.json").write_text(json.dumps(fixtures, indent=2) + "\n")
print("Synthetic realm and private probe fixtures prepared; no credential values emitted")
