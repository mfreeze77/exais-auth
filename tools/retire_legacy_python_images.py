"""Retire two exact unused legacy Python image records, without pruning parents.

These are historical build/fixture intermediates, not the current Python image.
Never force removal, prune globally, remove shared parents or mutate containers.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    'sha256:eea3027f238275812536382f10d4b24d1d325c7789f63e1b232ecb068c452c3f':
        {'parent': 'sha256:fa94fb47cebff6532330795a1f1ad6ed731c4a9acf763293286cb5cea39b863d',
         'labels': {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': 'python-foundation',
                    'org.expertauth.lifecycle.fixture': 'b332b3b649674a188cf6dae578a1bb24'}},
    'sha256:b6bc50314f3598fe92e1140905648e0b8078b39703e70ffcb7d2870c19170916':
        {'parent': 'sha256:4f8751c411b6f299376e00443d30f50daf7a98f9d5d73a121b06b5200ae6a899',
         'labels': {'org.expertauth.project': 'expert-auth'}},
}


def docker(*argv):
    return subprocess.run(['docker', *argv], capture_output=True, text=True, check=True, timeout=40).stdout


def inventory():
    return {name: sorted(docker(*argv).splitlines()) for name, argv in {
        'containers': ('ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Image}} {{.Names}} {{.Status}}'),
        'tags': ('image', 'ls', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'),
        'volumes': ('volume', 'ls', '-q'), 'networks': ('network', 'ls', '-q', '--no-trunc')}.items()}


def main():
    output = ROOT / 'evidence/operations/hygiene/legacy-python-intermediates.json'
    if output.exists():
        raise ValueError('Preserve previous retirement evidence')
    before = inventory()
    ids = sorted(set(docker('image', 'ls', '-aq', '--no-trunc').splitlines()))
    all_images = json.loads(docker('image', 'inspect', *ids))
    index = {row['Id']: row for row in all_images}
    record = {'started': datetime.now(timezone.utc).isoformat(), 'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope': 'Two exact legacy Python image records; no force, parent prune, volume or container mutation',
              'physical_host_bytes_freed': None, 'images': [], 'errors': []}
    # Validate the entire removal set before the first mutation.
    for target, expected in TARGETS.items():
        row = index[target]
        assert row.get('Parent') == expected['parent'] and row['Config'].get('Labels') == expected['labels']
        assert not row.get('RepoTags') and not row.get('RepoDigests')
        assert not any(item.get('Parent') == target for item in all_images), 'Image still has children'
        assert not docker('ps', '-aq', '--filter', 'ancestor=' + target).strip(), 'Image still has container references'
        record['images'].append({'id': target, 'parent': row['Parent'], 'labels': row['Config']['Labels'],
                                 'created': row['Created'], 'docker_inspect_size': row['Size'], 'tags': [], 'consumers': []})
    try:
        for item in record['images']:
            target = item['id']
            current = json.loads(docker('image', 'inspect', target))[0]
            assert current['Id'] == target and not current.get('RepoTags') and not current.get('RepoDigests')
            assert current['Config']['Labels'] == item['labels']
            assert not docker('ps', '-aq', '--filter', 'ancestor=' + target).strip()
            item['removal_output'] = docker('image', 'rm', '--no-prune', target)
        after = inventory()
        record['remaining_target_ids'] = sorted(set(docker('image', 'ls', '-aq', '--no-trunc').splitlines()) & set(TARGETS))
        record['preserved_parent_ids'] = [parent for parent in (value['parent'] for value in TARGETS.values())
                                          if json.loads(docker('image', 'inspect', parent))[0]['Id'] == parent]
        record['containers_volumes_networks_unchanged'] = all(before[key] == after[key] for key in ('containers', 'volumes', 'networks'))
        record['named_tags_unchanged'] = [row for row in before['tags'] if '<none>' not in row] == [row for row in after['tags'] if '<none>' not in row]
        assert not record['remaining_target_ids'] and record['containers_volumes_networks_unchanged'] and record['named_tags_unchanged']
        record['passed'] = True
    except Exception as error:
        record['errors'].append(type(error).__name__)
        record['passed'] = False
    finally:
        record['finished'] = datetime.now(timezone.utc).isoformat()
        with output.open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), 'passed': record['passed'], 'errors': record['errors']}))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
