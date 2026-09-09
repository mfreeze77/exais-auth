"""Retire only the six proven, unreferenced parents of the old Node image.

This one-time operation never forces removal or prunes parents/shared cache.
The pinned historical inspection links each exact ID to the retired task build.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HISTORY = 'evidence/operations/node-image-build/offline-build-02/command-001.log'
HISTORY_SHA = 'a8e376f15d067d5cdfa478eea99b19e84be70fd23b5ed8010d25c649060e599a'
OLD = 'sha256:a0cf7009def4f1fb626e67c2e43103dbc6d654fc2697aab28a4390868d869eaf'
TARGETS = ['sha256:' + value for value in (
    '24086414367a4281d5db6b784dde8975e0c812f7985048a5e58f8562adc20c0a',
    'f7f7fa369238d15d9b250ccf8c08acb42421f6687b42cb4d439a4cf073b4efed',
    '4c0c621a208b4bc88834af0dd2047ed4f71d8e2683b07ff6cfab3fb16816ccfe',
    '86276d87b6ca8d54ace59633cb236773bb408044c07a5d533fbd64571160ee45',
    '76468de3b3352320f620a13c5c0c7a61c98b749c6d4c29ef44f631e11123c71c',
    '7ff88b1ef2e55d5cee69136b7e22e8569a712a064b2e852b85eda520fe8057cc')]
STOP = 'sha256:73add44eb2d11852b6fd665df9506ffddd53848944d8cb4b11e2fd9b7bf02961'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=45)
    require(result.returncode == 0, 'Docker operation failed: ' + ' '.join(args) + '\n' + result.stderr)
    return result.stdout


def inventory():
    return {key: sorted(docker(*args).splitlines()) for key, args in {
        'containers': ('ps', '-a', '--no-trunc', '--format', '{{.ID}} {{.Image}} {{.Names}}'),
        'tags': ('image', 'ls', '--no-trunc', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'),
        'volumes': ('volume', 'ls', '-q'), 'networks': ('network', 'ls', '-q', '--no-trunc')}.items()}


def images():
    ids = sorted(set(docker('image', 'ls', '-aq', '--no-trunc').splitlines()))
    return {row['Id']: row for row in json.loads(docker('image', 'inspect', *ids))}


def main():
    output = ROOT / 'evidence/operations/hygiene/legacy-node-intermediates.json'
    require(not output.exists(), 'Preserve previous evidence; this operation is not repeatable')
    report = {'schema': 'expertauth-exact-legacy-node-retirement-v1',
              'started': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'historical_image_inspection': HISTORY, 'historical_inspection_sha256': HISTORY_SHA,
              'physical_host_bytes_freed': None, 'images': [], 'errors': [],
              'scope': 'Six exact old Node build records, --no-prune, no force, no filesystem/container/volume mutation'}

    def persist():
        output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    persist()
    try:
        raw = (ROOT / HISTORY).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == HISTORY_SHA, 'Historical proof hash differs')
        old = json.loads(raw)[0]
        require(old['Id'] == OLD and old['Parent'] == TARGETS[0], 'Historical task ancestry differs')
        before = inventory()
        index = images()
        require(OLD not in index and STOP not in index, 'Retired/missing ancestry boundary differs')
        report['before'] = before
        report['non_target_images_before'] = sorted(set(index) - set(TARGETS))
        # Validate the entire chain and reject consumers outside it before mutation.
        for position, target in enumerate(TARGETS):
            row = index[target]
            parent = (TARGETS + [STOP])[position + 1]
            children = sorted(r['Id'] for r in index.values() if r.get('Parent') == target)
            require(row.get('Parent') == parent, 'Exact parent differs')
            require(children == ([] if position == 0 else [TARGETS[position - 1]]), 'Unexpected child image')
            require(not row.get('RepoTags') and not row.get('RepoDigests') and not row['Config'].get('Labels'), 'Legacy references or labels differ')
            require('2026-09-08T21:59:28' <= row['Created'] < old['Created'], 'Historical build time differs')
            layers = row['RootFS']['Layers']
            require(layers and layers == old['RootFS']['Layers'][:len(layers)], 'Historical layer prefix differs')
            require(not docker('ps', '-aq', '--filter', 'ancestor=' + target).strip(), 'Container consumer exists')
            report['images'].append({key: row[key] for key in ('Id', 'Parent', 'Created', 'RepoTags', 'RepoDigests', 'Size', 'RootFS')})
        report['preflight_passed'] = True
        persist()
        for item in report['images']:
            target = item['Id']
            current = images()
            row = current[target]
            require(row.get('Parent') == item['Parent'] and row['RootFS'] == item['RootFS'], 'Image changed before removal')
            require(not row.get('RepoTags') and not row.get('RepoDigests') and not row['Config'].get('Labels'), 'New reference appeared')
            require(not any(r.get('Parent') == target for r in current.values()), 'Child appeared before removal')
            require(not docker('ps', '-aq', '--filter', 'ancestor=' + target).strip(), 'Container appeared before removal')
            item['removal_output'] = docker('image', 'rm', '--no-prune', target)
            item['retired'] = True
            persist()
        after = inventory()
        final_ids = set(images())
        report['after'] = after
        report['remaining_target_ids'] = sorted(final_ids.intersection(TARGETS))
        report['all_other_image_records_preserved'] = final_ids == set(report['non_target_images_before'])
        report['containers_volumes_networks_unchanged'] = all(before[k] == after[k] for k in ('containers', 'volumes', 'networks'))
        report['named_tags_unchanged'] = [r for r in before['tags'] if '<none>' not in r] == [r for r in after['tags'] if '<none>' not in r]
        require(not report['remaining_target_ids'] and report['all_other_image_records_preserved'] and
                report['containers_volumes_networks_unchanged'] and report['named_tags_unchanged'], 'Final preservation differs')
        report['passed'] = True
    except Exception as error:
        report['errors'].append(str(error))
    finally:
        report['finished'] = datetime.now(timezone.utc).isoformat()
        persist()
    print(json.dumps({'passed': report['passed'], 'retired': sum(r.get('retired', False) for r in report['images']),
                      'report': output.relative_to(ROOT).as_posix(), 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
