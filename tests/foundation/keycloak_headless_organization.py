"""Verify dedicated candidate-client audience and real imported organization membership."""
import base64
import hashlib
import json
import pathlib
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pyotp

ROOT = pathlib.Path(__file__).resolve().parents[2]
fixtures = json.loads((ROOT / "engine-extensions/keycloak-headless/.runtime/fixtures.json").read_text())
candidate = fixtures["dedicated_candidate_client"]
user = fixtures["users"]["client-audit"]
issuer = "http://kc-headless.example.test:8080/realms/" + fixtures["realm"]
oidc = issuer + "/protocol/openid-connect"
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
state = secrets.token_urlsafe(24)
with httpx.Client(trust_env=False, timeout=20, follow_redirects=False) as client:
    response = client.get(oidc + "/auth", params={"client_id": candidate["client_id"], "redirect_uri": candidate["redirect_uri"], "scope": candidate["scope"], "response_type": "code", "code_challenge_method": "S256", "code_challenge": challenge, "state": state})
    assert response.status_code == 200 and response.json()["step"] == "password", f"Initial response HTTP {response.status_code}"
    response = client.post(response.json()["action"], data={"username": user["username"], "password": user["password"]})
    assert response.status_code == 200 and response.json()["step"] == "totp", f"Password response HTTP {response.status_code}"
    response = client.post(response.json()["action"], data={"otp": pyotp.TOTP(user["otp_secret"]).now()})
    assert response.status_code == 302, f"TOTP response HTTP {response.status_code}"
    callback = parse_qs(urlparse(response.headers["location"]).query)
    assert callback["state"] == [state]
    response = client.post(oidc + "/token", data={"grant_type": "authorization_code", "client_id": candidate["client_id"], "redirect_uri": candidate["redirect_uri"], "code_verifier": verifier, "code": callback["code"][0]})
    assert response.status_code == 200, f"Token response HTTP {response.status_code}"
    token = response.json()["access_token"]
    kid = jwt.get_unverified_header(token)["kid"]
    keys = client.get(oidc + "/certs").json()["keys"]
    public_key = jwt.PyJWK.from_dict(next(key for key in keys if key["kid"] == kid)).key
    claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=candidate["resource_audience"], issuer=issuer)
    assert claims["azp"] == candidate["client_id"]
    assert "alpha" in claims.get("organization", {}), "Signed token omitted real alpha membership"
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/foundation/keycloak_headless_organization.py", "exit_code": 0, "client": candidate["client_id"], "issuer_verified": issuer, "audience_verified": candidate["resource_audience"], "authorized_party_verified": claims["azp"], "signed_organizations": sorted(claims["organization"]), "membership_source": "Keycloak RealmRepresentation organizations.members imported through DefaultExportImportManager and emitted by built-in organization mapper", "hardcoded_claim_mapper": False, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (pathlib.Path(__file__), ROOT / "engine-extensions/keycloak-headless/prepare_lab.py")}, "qualification": "dedicated-client fixture proof only; not full tenant authorization acceptance"}
(ROOT / "evidence/foundation/keycloak-headless/organization-client-report.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
