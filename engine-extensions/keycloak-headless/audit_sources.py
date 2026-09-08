"""Fetch only immutable primary-source/license evidence for this SPI boundary."""
import hashlib
import json
import pathlib
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent
COMMIT = "6d238b6558037085cc25c915893c3d301a80243e"
PREFIX = "https://raw.githubusercontent.com/keycloak/keycloak/" + COMMIT + "/"
FILES = {
    "services/src/main/java/org/keycloak/authentication/authenticators/browser/UsernamePasswordForm.java": ["JsonPasswordAuthenticator.java", "Inherited authenticate/action/password validation"],
    "services/src/main/java/org/keycloak/authentication/authenticators/browser/AbstractUsernameFormAuthenticator.java": ["JsonPasswordAuthenticator.java", "Inherited credential checks, dummy hashing, brute-force enforcement, user context"],
    "services/src/main/java/org/keycloak/authentication/authenticators/browser/OTPFormAuthenticator.java": ["JsonOtpAuthenticator.java", "Inherited OTP action and credential-provider validation"],
    "services/src/main/java/org/keycloak/credential/OTPCredentialProvider.java": ["JsonOtpAuthenticator.java", "Engine-owned OTP and SingleUseObjectProvider replay policy"],
    "server-spi/src/main/java/org/keycloak/models/credential/OTPCredentialModel.java": ["prepare_lab.py", "Synthetic credential import representation and base32 encoding"],
    "services/src/main/java/org/keycloak/authentication/authenticators/browser/UsernamePasswordFormFactory.java": ["JsonPasswordFactory.java", "Inherited factory metadata with unique extension provider ID"],
    "services/src/main/java/org/keycloak/authentication/authenticators/browser/OTPFormAuthenticatorFactory.java": ["JsonOtpFactory.java", "Inherited factory metadata with unique extension provider ID"],
    "server-spi-private/src/main/java/org/keycloak/authentication/AuthenticationFlowContext.java": ["JsonChallenge.java", "Engine-created access code and action URL"],
    "services/src/main/java/org/keycloak/authentication/AuthenticationProcessor.java": ["JsonChallenge.java", "Engine action URL/session code and flow transitions"],
    "services/src/main/java/org/keycloak/services/resources/SessionCodeChecks.java": ["keycloak_headless_probe.py", "Engine action/session/tab validation and restart behavior"],
    "core/src/main/java/org/keycloak/representations/idm/RealmRepresentation.java": ["prepare_lab.py", "Realm policy and flow import contract"],
    "core/src/main/java/org/keycloak/representations/idm/OrganizationRepresentation.java": ["prepare_lab.py", "Real organization membership import representation"],
    "core/src/main/java/org/keycloak/representations/idm/MemberRepresentation.java": ["prepare_lab.py", "Real unmanaged organization membership representation"],
    "model/storage-private/src/main/java/org/keycloak/storage/datastore/DefaultExportImportManager.java": ["prepare_lab.py", "Official organization/member import implementation"],
    "services/src/main/java/org/keycloak/organization/protocol/mappers/oidc/OrganizationMembershipMapper.java": ["prepare_lab.py", "Built-in selected-organization signed claim mapping"],
}
records = []
for path, (destination, purpose) in FILES.items():
    raw = urllib.request.urlopen(PREFIX + path, timeout=30).read()
    records.append({"repository": "keycloak/keycloak", "commit": COMMIT, "source_path": path, "url": PREFIX + path, "sha256": hashlib.sha256(raw).hexdigest(), "license": "Apache-2.0", "license_source": "LICENSE.txt at same commit; file-level headers examined where present", "destination_or_dependency": destination, "reuse_boundary": "unmodified pinned runtime dependency; source examined, not copied", "purpose": purpose, "modifications_to_upstream_file": [], "requirements_mapping": ["MFA-002", "MFA-009"], "milestone_mapping": "M1 foundation headless/intermediate MFA", "validation": "evidence/foundation/keycloak-headless/probe-report.json"})
license_raw = urllib.request.urlopen(PREFIX + "LICENSE.txt", timeout=30).read()
(ROOT / "LICENSES").mkdir(exist_ok=True)
(ROOT / "LICENSES/keycloak-LICENSE.txt").write_bytes(license_raw)
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "source_version": "26.7.3", "source_commit": COMMIT, "source_license_sha256": hashlib.sha256(license_raw).hexdigest(), "files": records, "original_extension_files": [str(path.relative_to(ROOT)) for path in sorted((ROOT / "src").rglob("*")) if path.is_file()], "source_code_copied": False, "new_authentication_or_refresh_store": False, "candidate_selected": False, "warning": "Keycloak runtime marks the Authenticator SPI internal; version pin and regression qualification are required", "independent_security_review": "blocked-not-performed"}
(ROOT / "SOURCE_REUSE_REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"Audited {len(records)} pinned source boundaries; retained Apache-2.0 license")
