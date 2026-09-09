"""Acquire bounded public metadata, not the image, for the private SMTP lab.

Run inside the already cached Python container when host networking is unavailable.
Anonymous registry credentials stay in memory. No runtime qualification is claimed.
"""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path('/repo')
DIGEST = 'sha256:3856f9327f3f228afe8c4ce2dcca3cb2aa00f6ec60b569f36483f7ebb1ff44f7'
COMMIT = '17a70ba7a87dc96c04646a59493389ec17af5cfb'
MAX_COMPRESSED = 64 * 1024 * 1024


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        result = super().redirect_request(req, fp, code, msg, headers, newurl)
        if result is not None:
            result.remove_header('Authorization')
        return result


def get(url, headers=None, maximum=2 * 1024 * 1024):
    with urllib.request.build_opener(Redirect()).open(
            urllib.request.Request(url, headers=headers or {}), timeout=25) as response:
        assert response.url.startswith('https://')
        data = response.read(maximum + 1)
        assert len(data) <= maximum
        return data


def main():
    target = Path('/out')
    assert target.is_dir() and not any(target.iterdir()), 'Require an empty, narrowly mounted output'
    token = json.loads(get('https://ghcr.io/token?service=ghcr.io&scope=repository:axllent/mailpit:pull'))['token']
    headers = {'Authorization': 'Bearer ' + token,
               'Accept': 'application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'}
    manifest = get('https://ghcr.io/v2/axllent/mailpit/manifests/' + DIGEST, headers)
    assert 'sha256:' + hashlib.sha256(manifest).hexdigest() == DIGEST
    parsed = json.loads(manifest)
    total = sum(layer['size'] for layer in parsed['layers'])
    assert 0 < total <= MAX_COMPRESSED
    config_digest = parsed['config']['digest']
    config = get('https://ghcr.io/v2/axllent/mailpit/blobs/' + config_digest, headers)
    assert 'sha256:' + hashlib.sha256(config).hexdigest() == config_digest
    conf = json.loads(config)
    assert conf['architecture'] == 'amd64' and conf['os'] == 'linux'
    license_bytes = get('https://raw.githubusercontent.com/axllent/mailpit/' + COMMIT + '/LICENSE', maximum=16384)
    assert b'MIT License' in license_bytes and b'Ralph Slooten' in license_bytes
    for name, data in [('manifest.json', manifest), ('config.json', config), ('LICENSE', license_bytes)]:
        (target / name).write_bytes(data)
    result = {'schema': 'expertauth-mailpit-artifact-metadata-v1', 'platform_manifest_digest': DIGEST,
              'config_digest': config_digest, 'compressed_layer_bytes': total,
              'compressed_limit_bytes': MAX_COMPRESSED, 'platform': 'linux/amd64', 'source_commit': COMMIT,
              'license_sha256': hashlib.sha256(license_bytes).hexdigest(), 'image_pulled': False,
              'full_transitive_license_closure': False, 'runtime_qualified': False}
    (target / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
