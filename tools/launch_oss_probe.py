"""Create private two-replica source-built Core lab with persistent PostgreSQL.

No public ports. This is foundation characterization, not production deployment.
Existing owned containers/data are preserved. Never uses the vendor packaged image.
"""
from __future__ import annotations
import json
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
NETWORK = 'expertauth-oss-proof'
IMAGE = 'expertauth-oss-core:12.2.0-probe'
POSTGRES = 'postgres@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675'

def command(args, check=True):
    result = subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace')
    if check and result.returncode:
        raise RuntimeError(f'Command {args[:3]} failed: {result.stderr}')
    return result

def main():
    import argparse
    from build_oss_runtime import build_runtime_image
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-only', action='store_true', help='Verify the image and retire scratch without starting services')
    parser.add_argument('--evidence-name')
    args = parser.parse_args()
    built = build_runtime_image(evidence_name=args.evidence_name)
    if args.build_only:
        return
    image_id = built['image_id']
    copied = [row for row in built['installed_files'] if row['path'].startswith(('lib/', 'plugin/'))]
    runtime_evidence = ROOT/'evidence/runtime/oss-core'/str(time.time_ns())
    runtime_evidence.mkdir(parents=True)
    runtime = ROOT/'.runtime/oss-core'
    runtime.mkdir(parents=True,exist_ok=True)
    env = runtime/'runtime.env'
    if not env.exists():
        env.write_text(f'EXPERTAUTH_CORE_API_KEY={secrets.token_hex(32)}\nPOSTGRES_PASSWORD={secrets.token_hex(32)}\nPOSTGRES_USER=expertauth\nPOSTGRES_DB=expertauth\n',encoding='utf-8')
    values = dict(line.split('=',1) for line in env.read_text().splitlines() if line)
    config = runtime/'config.yaml'
    config.write_text('core_config_version: 0\npostgresql_config_version: 0\nhost: 0.0.0.0\nport: 3567\n'
                     f'api_keys: "{values["EXPERTAUTH_CORE_API_KEY"]}"\n'
                     'postgresql_host: postgres\npostgresql_port: 5432\npostgresql_user: expertauth\n'
                     f'postgresql_password: "{values["POSTGRES_PASSWORD"]}"\npostgresql_database_name: expertauth\n'
                     'disable_telemetry: true\naccess_token_validity: 60\naccess_token_validity_jitter: 0\n'
                     'refresh_token_rotation_grace_period: 0\nrecent_token_reuse_behaviour: TOKEN_THEFT\n'
                     'max_server_pool_size: 20\npostgresql_connection_pool_size: 20\n',encoding='utf-8')
    if command(['docker','network','inspect',NETWORK],False).returncode:
        command(['docker','network','create','--internal',NETWORK])
    assert json.loads(command(['docker','network','inspect',NETWORK]).stdout)[0]['Internal'], 'Lab network must block external egress'
    def launch(name,args):
        existing = command(['docker','container','inspect',name],False)
        if not existing.returncode:
            state = json.loads(existing.stdout)[0]
            assert state['Config'].get('Labels',{}).get('org.expertauth.purpose')=='oss-foundation', 'Unowned container name'
            assert state['State']['Running'], 'Owned container is stopped; investigate before restarting'
            assert not state['HostConfig']['PortBindings'], 'Foundation services must have no public ports'
            if name.startswith('expertauth-oss-core-'):
                assert state['Image'] == image_id, 'Existing Core runs a different image; preserve it and perform an explicit local replacement before qualification'
            print(f'Preserved existing {name}; state={state["State"]["Status"]}')
            return
        command(['docker','run','-d','--name',name,'--network',NETWORK,'--label','org.expertauth.project=expert-auth','--label','org.expertauth.purpose=oss-foundation',*args])
    launch('expertauth-oss-postgres',['--network-alias','postgres','--env-file',str(env),'-v','expertauth-oss-proof-pg:/var/lib/postgresql/data',POSTGRES])
    for _ in range(40):
        if command(['docker','exec','expertauth-oss-postgres','pg_isready','-U','expertauth','-d','expertauth'],False).returncode==0:
            break
        time.sleep(1)
    else:
        raise SystemExit('PostgreSQL readiness failed')
    # Start sequentially; schema initialization first must finish before second replica.
    launch('expertauth-oss-core-a',['--network-alias','core-a','--tmpfs','/home/gradle/.gradle:rw,noexec,nosuid,size=16m','-v',f'{config}:/run/expertauth/config.yaml:ro',image_id])
    def storage_ready(replica):
        ready = command(['docker','run','--rm','--network',NETWORK,'--env-file',str(env),'-v',f'{ROOT}:/repo:ro',
                         'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36',
                         'python','/repo/tools/wait_oss_storage.py',f'http://{replica}:3567'])
        print(ready.stdout.strip())
    storage_ready('core-a')
    launch('expertauth-oss-core-b',['--network-alias','core-b','--tmpfs','/home/gradle/.gradle:rw,noexec,nosuid,size=16m','-v',f'{config}:/run/expertauth/config.yaml:ro',image_id])
    storage_ready('core-b')
    output = {'image_id':image_id,'postgres_digest':POSTGRES,'network':NETWORK,'internal':True,'published_ports':[],
              'artifacts':copied,'remaining':'Foundation authentication and full parity acceptance are separate from storage readiness.',
              'replicas_storage_ready':['core-a','core-b'],'production_approved':False,'source_build_tested':True,'runtime_authentication_tested':False}
    (runtime_evidence/'runtime-image.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({'image':image_id,'network':NETWORK,'both_replicas_storage_ready':True,'ports':[],'evidence':str(runtime_evidence)}))

if __name__ == '__main__':
    main()
