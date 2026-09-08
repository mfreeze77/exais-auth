"""Run the owned, private two-replica Keycloak/PostgreSQL session proof lab.

This is an isolated candidate characterization harness, not production deployment.
Only explicitly labeled expertauth-kc-sessions-* resources may be replaced/stopped.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT = ROOT / "engine-extensions/keycloak-headless"
RUNTIME = EXT / ".runtime/cluster"
OUT = ROOT / "evidence/foundation/keycloak-sessions"
NETWORK = "expertauth-kc-sessions-proof"
LABEL = "org.expertauth.lab=keycloak-sessions"
IMAGE = "expertauth-kc-headless-postgres:0.1.0"
PG_IMAGE = "postgres@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675"
CLIENT_IMAGE = "expertauth-python-app:0.1.0"
RESOURCES = ("expertauth-kc-sessions-a", "expertauth-kc-sessions-b", "expertauth-kc-sessions-pg")


def command(args, check=True):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]} {args[1]}; inspect owned lab logs")
    return result


def inspect(name):
    result = command(["docker", "inspect", name], check=False)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def remove_owned():
    for name in RESOURCES:
        value = inspect(name)
        if value:
            if value["Config"].get("Labels", {}).get("org.expertauth.lab") != "keycloak-sessions":
                raise RuntimeError(f"Refusing to remove unlabeled container {name}")
            command(["docker", "rm", "-f", name])


def prepare():
    RUNTIME.mkdir(parents=True, exist_ok=True)
    secret = secrets.token_urlsafe(36)
    (RUNTIME / "postgres.env").write_text("POSTGRES_DB=keycloak\nPOSTGRES_USER=keycloak\nPOSTGRES_PASSWORD=" + secret + "\n")
    (RUNTIME / "keycloak.env").write_text("KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://kc-postgres:5432/keycloak\nKC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=" + secret + "\nKC_CACHE=ispn\nKC_CACHE_STACK=jdbc-ping\n")
    users, private_users = [], {}
    for label in ("serial", "race", "response-loss", "client-revoke", "global-logout", "replay", "access-validation"):
        password = "P9!" + secrets.token_urlsafe(24)
        otp = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        private_users[label] = {"username": label, "password": password, "otp_secret": otp}
        users.append({"id": str(uuid.uuid4()), "username": label, "enabled": True, "email": label + "@example.invalid", "emailVerified": True, "firstName": "Synthetic", "lastName": "Cluster", "credentials": [{"type": "password", "value": password, "temporary": False}, {"id": str(uuid.uuid4()), "type": "otp", "secretData": json.dumps({"value": otp}), "credentialData": json.dumps({"subType": "totp", "digits": 6, "counter": 0, "period": 30, "algorithm": "HmacSHA1", "secretEncoding": "BASE32"})}]})
    clients = [{"clientId": name, "protocol": "openid-connect", "enabled": True, "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "redirectUris": ["http://cluster-client.example.test/callback"], "webOrigins": ["http://cluster-client.example.test"], "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "http://cluster-client.example.test/logout"}, "protocolMappers": [{"name": "cluster-api-audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": {"included.custom.audience": "expertauth-cluster-api", "access.token.claim": "true", "id.token.claim": "false"}}]} for name in ("cluster-alpha", "cluster-beta")]
    realm = {"realm": "expertauth-cluster-proof", "enabled": True, "sslRequired": "none", "registrationAllowed": False, "resetPasswordAllowed": False, "rememberMe": False, "revokeRefreshToken": True, "refreshTokenMaxReuse": 0, "accessTokenLifespan": 120, "ssoSessionIdleTimeout": 900, "ssoSessionMaxLifespan": 3600, "clientSessionIdleTimeout": 900, "clientSessionMaxLifespan": 3600, "otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6, "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 0, "otpPolicyCodeReusable": False, "browserFlow": "cluster-browser", "authenticationFlows": [{"alias": "cluster-browser", "providerId": "basic-flow", "topLevel": True, "builtIn": False, "authenticationExecutions": [{"authenticator": "auth-cookie", "authenticatorFlow": False, "requirement": "ALTERNATIVE", "priority": 10}, {"flowAlias": "cluster-json-forms", "authenticatorFlow": True, "requirement": "ALTERNATIVE", "priority": 20}]}, {"alias": "cluster-json-forms", "providerId": "basic-flow", "topLevel": False, "builtIn": False, "authenticationExecutions": [{"authenticator": "expertauth-json-password", "authenticatorFlow": False, "requirement": "REQUIRED", "priority": 10}, {"authenticator": "expertauth-json-totp", "authenticatorFlow": False, "requirement": "REQUIRED", "priority": 20}]}], "users": users, "clients": clients}
    (RUNTIME / "realm-import.json").write_text(json.dumps(realm, indent=2) + "\n")
    (RUNTIME / "fixtures.json").write_text(json.dumps({"realm": realm["realm"], "users": private_users, "issuer": "http://kc-cluster.example.test:8080/realms/expertauth-cluster-proof", "refresh_token_policy": {"revokeRefreshToken": True, "refreshTokenMaxReuse": 0}}, indent=2) + "\n")


def wait_http(replica):
    script = "import httpx,time,sys\nfor i in range(45):\n try:\n  r=httpx.get('http://" + replica + ":8080/realms/expertauth-cluster-proof/.well-known/openid-configuration',timeout=2,trust_env=False)\n  if r.status_code==200: print('ready');sys.exit(0)\n except Exception: pass\n time.sleep(1)\nsys.exit(1)"
    result = command(["docker", "run", "--rm", "--network", NETWORK, CLIENT_IMAGE, "python", "-c", script], check=False)
    if result.returncode:
        raise RuntimeError(f"Replica {replica} did not become HTTP-ready")


def up(reset=False):
    OUT.mkdir(parents=True, exist_ok=True)
    if reset:
        remove_owned()
    existing = [inspect(name) for name in RESOURCES]
    if any(existing):
        if not all(existing):
            raise RuntimeError("Partial owned lab exists; inspect before explicit --reset")
        print("Owned cluster containers already exist; preserving their state")
        return
    prepare()
    build = command(["docker", "build", "-f", "engine-extensions/keycloak-headless/Dockerfile.postgres", "-t", IMAGE, "engine-extensions/keycloak-headless"])
    (OUT / "image-build.log").write_text(build.stdout + build.stderr)
    network = command(["docker", "network", "inspect", NETWORK], check=False)
    if network.returncode:
        command(["docker", "network", "create", "--internal", "--label", LABEL, NETWORK])
    else:
        detail = json.loads(network.stdout)[0]
        if not detail["Internal"] or detail.get("Labels", {}).get("org.expertauth.lab") != "keycloak-sessions":
            raise RuntimeError("Existing network is not the expected labeled internal lab")
    command(["docker", "run", "-d", "--name", RESOURCES[2], "--label", LABEL, "--network", NETWORK, "--network-alias", "kc-postgres", "--env-file", str(RUNTIME / "postgres.env"), PG_IMAGE])
    for _ in range(30):
        if command(["docker", "exec", RESOURCES[2], "pg_isready", "-U", "keycloak", "-d", "keycloak"], check=False).returncode == 0:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Owned PostgreSQL did not become ready")
    for name, alias in ((RESOURCES[0], "kc-a"), (RESOURCES[1], "kc-b")):
        args = ["docker", "run", "-d", "--name", name, "--label", LABEL, "--network", NETWORK, "--network-alias", alias, "--env-file", str(RUNTIME / "keycloak.env")]
        if alias == "kc-a":
            args += ["--network-alias", "kc-cluster.example.test"]
        args += ["--mount", f"type=bind,source={RUNTIME / 'realm-import.json'},target=/opt/keycloak/data/import/realm-import.json,readonly", IMAGE]
        command(args)
        wait_http(alias)
        print(alias + " is HTTP ready")
    # Extract only cluster membership lines, omitting request identities and secrets.
    cluster_lines = {}
    for name in RESOURCES[:2]:
        logs = command(["docker", "logs", name], check=False)
        cluster_lines[name] = [line for line in (logs.stdout + logs.stderr).splitlines() if any(term in line for term in ("ISPN000094", "JDBC_PING", "physical addresses", "cluster view"))]
    containers = [inspect(name) for name in RESOURCES]
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tools/run_keycloak_cluster.py up", "private_network": NETWORK, "network_internal": True, "replicas": 2, "postgres_image": PG_IMAGE, "containers": [{"name": item["Name"], "image_id": item["Image"], "published_ports": item["HostConfig"]["PortBindings"]} for item in containers], "cluster_membership_log_lines": cluster_lines, "policy": {"revokeRefreshToken": True, "refreshTokenMaxReuse": 0}, "candidate_selected": False, "foundation_gate_passed": False, "exit_code": 0, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (pathlib.Path(__file__), EXT / "Dockerfile.postgres", EXT / "build.gradle", EXT / "gradle.lockfile", EXT / "gradle/verification-metadata.xml")}}
    (OUT / "startup-report.json").write_text(json.dumps(report, indent=2) + "\n")


def probe():
    OUT.mkdir(parents=True, exist_ok=True)
    args = ["docker", "run", "--rm", "--network", NETWORK, "--mount", f"type=bind,source={ROOT},target=/work,readonly", "--mount", f"type=bind,source={OUT},target=/work/evidence/foundation/keycloak-sessions", "-w", "/work", CLIENT_IMAGE, "python", "tests/foundation/keycloak_sessions.py"]
    result = command(args, check=False)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    (OUT / "probe-command.json").write_text(json.dumps({"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command_argv": args, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
    return result.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "probe", "stop"))
    parser.add_argument("--reset", action="store_true", help="Replace only this labeled lab's containers/synthetic database before startup")
    args = parser.parse_args()
    if args.action == "up":
        up(args.reset)
    elif args.action == "probe":
        raise SystemExit(probe())
    else:
        remove_owned()
