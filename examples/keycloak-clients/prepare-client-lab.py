"""Copy the private synthetic realm for an isolated candidate proof; preserve original lab."""
import hashlib
import json
import pathlib
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
source = ROOT / 'engine-extensions/keycloak-headless/.runtime/realm-import.json'
destination = pathlib.Path(__file__).resolve().parent / '.runtime/realm-import.json'
if destination.exists():
    raise SystemExit('Candidate import already exists; reuse the existing isolated fixture')
realm = json.loads(source.read_text())
client = next(row for row in realm['clients'] if row['clientId'] == 'expertauth-node-candidate')
before = client.get('defaultClientScopes', [])
client['defaultClientScopes'] = sorted(set(before) | {'basic'})
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(realm, indent=2) + '\n')
report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'scope': 'Private disposable candidate engine import only',
          'change': {'client': client['clientId'], 'defaultClientScopes_before': before, 'defaultClientScopes_after': client['defaultClientScopes']},
          'purpose': 'Use maintained built-in basic scope to emit signed subject; keep API sub validation required',
          'source_private_import_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
          'corrected_private_import_sha256': hashlib.sha256(destination.read_bytes()).hexdigest(),
          'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
          'original_lab_modified': False, 'password_grant': False}
output = ROOT / 'evidence/foundation/keycloak-clients/lab-scope-correction.json'
output.write_text(json.dumps(report, indent=2) + '\n')
print('Private candidate import copied with built-in basic scope; original lab unchanged')
