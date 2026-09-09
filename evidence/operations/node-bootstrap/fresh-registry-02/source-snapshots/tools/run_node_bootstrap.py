"""Acquire locked npm archives or qualify fresh acquisition in disposable tmpfs.

Uses one already cached Node base. No images, volumes or networks are created.
The probe disconnects its own bridge endpoint before fresh offline installation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
BASE = 'node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436'
TOOLS = ['tools/fetch_node_packages.mjs', 'tools/export_node_packages.mjs']
PROBE = ['tools/verify_node_runtime.mjs', 'tests/reuse/node_bootstrap_probe.mjs',
         'evidence/operations/node-image-build/offline-build-02/candidate-runtime/runtime-report.json']
APP = ['examples/node-react/' + p for p in ('package.json', 'package-lock.json', 'server.js',
       'email-delivery.js', 'client.jsx', 'build.mjs', 'public/index.html')]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def need(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', choices=['offline', 'online'], default='offline')
    parser.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', args.name), 'Invalid evidence name')
    need(not args.probe or args.mode == 'online', 'Fresh registry probe requires explicit online mode')
    output = ROOT / 'evidence/operations/node-bootstrap' / args.name
    need(not output.exists(), 'Preserve previous evidence')
    output.mkdir(parents=True)
    suffix = uuid.uuid4().hex
    name = 'expertauth-node-bootstrap-' + suffix[:12]
    labels = {'org.expertauth.project': 'expert-auth', 'org.expertauth.purpose': 'node-package-bootstrap',
              'org.expertauth.bootstrap-run': suffix}
    sources = ['tools/run_node_bootstrap.py', *TOOLS, *(PROBE + APP if args.probe else ['examples/node-react/package-lock.json'])]
    inputs = {p: sha(ROOT / p) for p in sources}
    report = {'schema': 'expertauth-node-bootstrap-host-v1', 'passed': False, 'started': datetime.now(timezone.utc).isoformat(),
              'mode': args.mode, 'fresh_probe': args.probe, 'inputs': inputs, 'commands': [], 'errors': [],
              'new_images': 0, 'new_networks': 0, 'new_volumes': 0, 'published_ports': [],
              'container_name': name, 'container_id': None, 'container_retired': False,
              'foundation_passed': False, 'full_distribution_approved': False, 'source_bindings': {}}
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    for source, digest in inputs.items():
        result = subprocess.run(['git', 'show', revision + ':' + source], cwd=ROOT, capture_output=True)
        if result.returncode == 0 and hashlib.sha256(result.stdout).hexdigest() == digest:
            report['source_bindings'][source] = {'git_commit': revision, 'sha256': digest}
        else:
            target = output / 'source-snapshots' / source
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / source).read_bytes())
            need(sha(target) == digest, 'Source changed before capture')
            report['source_bindings'][source] = {'path': target.relative_to(ROOT).as_posix(), 'sha256': digest}

    def persist():
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    def call(argv, timeout=35, required=True):
        row = {'argv': ['docker', *argv], 'exit_code': None, 'timed_out': False}
        report['commands'].append(row)
        paths = {stream: output / f'command-{len(report["commands"]):03d}.{stream}' for stream in ('stdout', 'stderr')}
        result = None
        try:
            with paths['stdout'].open('xb') as out, paths['stderr'].open('xb') as err:
                result = subprocess.run(row['argv'], stdout=out, stderr=err, stdin=subprocess.DEVNULL, timeout=timeout)
            row['exit_code'] = result.returncode
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
        finally:
            for stream, file in paths.items():
                row[stream] = {'path': file.name, 'bytes': file.stat().st_size, 'sha256': sha(file)}
            persist()
        need(result is not None, 'Docker command deadline exceeded')
        need(not required or result.returncode == 0, 'Docker command failed: ' + paths['stderr'].name)
        need(paths['stdout'].stat().st_size <= 4 * 1024 * 1024, 'Command output exceeds bound')
        return result.returncode, paths['stdout'].read_text(encoding='utf-8', errors='replace')

    def resources():
        return {key: sorted(set(call(args)[1].splitlines())) for key, args in {
            'containers': ['ps', '-aq', '--no-trunc'], 'images': ['image', 'ls', '-aq', '--no-trunc'],
            'volumes': ['volume', 'ls', '-q'], 'networks': ['network', 'ls', '-q', '--no-trunc']}.items()}

    inspect_format = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                      '"labels":{{json .Config.Labels}},"running":{{json .State.Running}},'
                      '"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}}}')

    def owned_container(reference, image_id):
        code, raw = call(['container', 'inspect', '--format', inspect_format, reference], required=False)
        if code:
            return None
        state = json.loads(raw)
        need(state['name'] == '/' + name and state['image'] == image_id and
             all((state['labels'] or {}).get(k) == v for k, v in labels.items()) and not state['ports'], 'Container ownership differs')
        return state

    before = None
    image_id = cid = None
    launched = False
    persist()
    try:
        before = report['resources_before'] = resources()
        _, raw = call(['image', 'inspect', '--format', '{"id":{{json .Id}},"volumes":{{json (index .Config "Volumes")}}}', BASE])
        state = json.loads(raw)
        need(not state['volumes'], 'Pinned base would create anonymous volumes')
        image_id = report['base_image_id'] = state['id']
        need(not call(['ps', '-aq', '--filter', 'name=^/' + name + '$'])[1].strip(), 'Container name already exists')
        argv = ['run', '--rm', '--pull=never', '--name', name, '--cidfile', str(output / 'container.cid'),
                '--network', 'bridge' if args.mode == 'online' else 'none', '--read-only', '--user=0',
                '--memory=512m', '--cpus=2', '--pids-limit=128', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=16m']
        for key, value in labels.items():
            argv += ['--label', key + '=' + value]
        for source in [*TOOLS, *(PROBE + APP if args.probe else ['examples/node-react/package-lock.json'])]:
            argv += ['--mount', f'type=bind,source={ROOT / source},target=/repo/{source},readonly']
        argv += ['--mount', f'type=bind,source={output},target=/out']
        if args.probe:
            argv += ['--tmpfs', '/cache:rw,nosuid,nodev,noexec,size=64m', '--tmpfs', '/work:rw,exec,nosuid,nodev,size=192m',
                     '-d', '--entrypoint', 'node', image_id, '-e',
                     "process.on('SIGTERM',()=>process.exit(0)); setTimeout(()=>process.exit(124),420000);"]
        else:
            cache = (ROOT / '.cache/node-packages').resolve()
            need(cache.parent == (ROOT / '.cache').resolve() and cache.is_relative_to(ROOT.resolve()), 'Cache boundary differs')
            cache.mkdir(parents=True, exist_ok=True)
            argv += ['--mount', f'type=bind,source={cache},target=/cache', '--entrypoint', 'node', image_id,
                     '/repo/tools/fetch_node_packages.mjs', '--lock', '/repo/examples/node-react/package-lock.json',
                     '--cache', '/cache', '--report', '/out/acquisition.json', '--mode', args.mode]
        launched = True
        call(argv, timeout=210 if not args.probe else 40)
        cid = (output / 'container.cid').read_text().strip()
        need(re.fullmatch('[0-9a-f]{64}', cid), 'Container ID malformed')
        report['container_id'] = cid
        if args.probe:
            state = owned_container(cid, image_id)
            need(state and state['running'] and set(state['networks']) == {'bridge'}, 'Fresh probe network differs')
            _, raw = call(['exec', cid, 'node', '-e',
                "const fs=require('node:fs');process.stdout.write(JSON.stringify(fs.readFileSync('/proc/self/mountinfo','utf8').split('\\n').map(line=>line.split(' ')).filter(p=>['/work','/cache','/tmp'].includes(p[4])).map(p=>({path:p[4],options:p[5].split(',')}))));"])
            mounts = {row['path']: row['options'] for row in json.loads(raw)}
            need(set(mounts) == {'/work', '/cache', '/tmp'} and 'noexec' not in mounts['/work'] and
                 all('noexec' in mounts[p] for p in ('/cache', '/tmp')) and
                 all({'rw', 'nosuid', 'nodev'}.issubset(value) for value in mounts.values()), 'Actual temporary build mount policy differs')
            report['actual_tmpfs_mount_options'] = mounts
            print('Fresh registry acquisition started in one disposable container.', flush=True)
            call(['exec', cid, 'node', '/repo/tests/reuse/node_bootstrap_probe.mjs', '--stage', 'online'], timeout=210)
            need(json.loads((output / 'online-probe.json').read_text())['passed'], 'Online bootstrap proof failed')
            call(['network', 'disconnect', 'bridge', cid])
            state = owned_container(cid, image_id)
            need(state and state['running'] and not state['networks'], 'Probe still connected before offline install')
            report['offline_networks'] = state['networks']
            print('Registry acquisition passed; network disconnected before fresh npm installation.', flush=True)
            call(['exec', cid, 'node', '/repo/tests/reuse/node_bootstrap_probe.mjs', '--stage', 'offline'], timeout=150)
            need(json.loads((output / 'offline-probe.json').read_text())['passed'], 'Offline bootstrap proof failed')
        else:
            need(json.loads((output / 'acquisition.json').read_text())['passed'], 'Archive acquisition failed')
        report['work_passed'] = True
    except Exception as error:
        report['errors'].append(str(error) if isinstance(error, RuntimeError) else type(error).__name__)
    finally:
        try:
            if launched:
                if cid is None and (output / 'container.cid').exists():
                    cid = (output / 'container.cid').read_text().strip()
                need(cid is None or re.fullmatch('[0-9a-f]{64}', cid), 'Unsafe cleanup CID')
                state = owned_container(cid or name, image_id)
                if state:
                    cid = state['id']
                    if state['running']:
                        call(['stop', '--time=5', cid], timeout=20)
                    if owned_container(cid, image_id):
                        call(['rm', cid])
                report['container_id'] = cid
                need(not call(['ps', '-aq', '--filter', 'name=^/' + name + '$'])[1].strip(), 'Task container remains')
                if cid:
                    need(cid not in call(['ps', '-aq', '--no-trunc'])[1].splitlines(), 'Exact container ID remains')
            report['container_retired'] = True
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, RuntimeError) else 'Cleanup observation failed')
        try:
            report['resources_after'] = resources()
            report['resources_unchanged'] = before is not None and report['resources_after'] == before
            report['inputs_after'] = {p: sha(ROOT / p) for p in sources}
            report['inputs_unchanged'] = report['inputs_after'] == inputs
            need(report['resources_unchanged'] and report['inputs_unchanged'], 'Final resources or inputs changed')
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, RuntimeError) else 'Final preservation observation failed')
        report['passed'] = not report['errors'] and report.get('work_passed') is True and report['container_retired']
        report['finished'] = datetime.now(timezone.utc).isoformat()
        persist()
    print(json.dumps({'passed': report['passed'], 'report': output.relative_to(ROOT).as_posix(),
                      'container_retired': report['container_retired'], 'errors': report['errors']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
