"""Build pinned Argon2 C source offline in a cached compiler; retain one native candidate.

No image build/download, persistent service change, or native-platform/full license
qualification is implied. Original C sources and test vectors remain unchanged.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid
from run_sdk_session_faults import inspect, inventory

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'evidence/reuse/native-correspondence/argon2'
PIN = '62358ba2123abd17fccf2a108a301d4b52c01a7c'
IMAGE = 'node@sha256:0557ac14e0d45d02ed563067b82856ca5e7aa3437fa28d98d4350ea9c3d9494a'

def need(ok, message):
    if not ok: raise ValueError(message)

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def source_inputs():
    request = json.loads((BASE/'native-source-request.json').read_text())
    acquired = json.loads((BASE/'native-source/acquisition.json').read_text())
    metadata = json.loads((BASE/'native-metadata-01/commit.json').read_text())
    tree = json.loads((BASE/'native-metadata-01/tree.json').read_text())
    need(request['commit'] == metadata['sha'] == PIN and request['tree'] == metadata['tree']['sha'] == tree['sha'] and tree['truncated'] is False, 'Native source revision mismatch')
    objects = {r['path']: r for r in tree['tree'] if r['type'] == 'blob'}
    need(acquired['passed'] and len(acquired['records']) == len(request['files']) == 68, 'Complete pinned native acquisition required')
    records = {r['path']: r for r in acquired['records']}
    result = []
    for entry in request['files']:
        path = BASE/'native-source'/entry['path']; raw = path.read_bytes()
        blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        need(path.resolve().is_relative_to((BASE/'native-source').resolve()) and not path.is_symlink(), 'Unsafe native source')
        need(blob == entry['expected_git_blob_sha1'] == objects[entry['path']]['sha'] and len(raw) == entry['expected_bytes'] == objects[entry['path']]['size'] and sha(path) == records[entry['path']]['sha256'], 'Native source changed: '+entry['path'])
        if path.suffix in {'.c', '.h'}:
            need(b'Creative Commons CC0 1.0' in raw[:1300] and b'Apache Public License 2.0' in raw[:1300], 'Native code license header requires review')
        result.append({'path':path.relative_to(ROOT).as_posix(),'source_path':entry['path'],'source_url':entry['url'],'sha256':sha(path),'bytes':len(raw),'git_blob_sha1':blob,
                       'license_evidence':'LICENSE and README.md; explicit dual-license header for C/header files',
                       'selected_source_terms':'CC0-1.0', 'modifications':'none'})
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--name',required=True); args=parser.parse_args()
    need(re.fullmatch('[a-z0-9-]{1,40}',args.name), 'Invalid native build name')
    output=BASE/'native-build'/args.name; cache=(ROOT/'.cache/native-argon2').resolve()
    need(not output.exists() and not cache.exists(), 'Preserve prior build evidence/candidate')
    inputs=source_inputs(); compiler=inspect('image',IMAGE)
    need(compiler['Id']==IMAGE.split('@')[1] and not compiler['Config'].get('Volumes'), 'Pinned compiler unavailable or declares volumes')
    output.mkdir(parents=True);cache.mkdir()
    run=uuid.uuid4().hex;name='expertauth-argon2-build-'+run[:12]
    private=ROOT/'.runtime/native-argon2';private.mkdir(exist_ok=True);cidfile=private/(run+'.cid')
    labels={'org.expertauth.project':'expert-auth','org.expertauth.purpose':'native-argon2-build','org.expertauth.run':run}
    report={'kind':'native-argon2-source-build','passed':False,'complete':False,'native_commit':PIN,'platform':'linux-x86_64',
            'historical_binary_reproduced':False,'independent_distribution_review':False,'compiler_image':compiler['Id'],
            'inputs':inputs,'tool_sha256':sha(Path(__file__)),'commands':[],'errors':[],
            'images_built':0,'image_downloads':0,'new_volumes':0,'new_networks':0,'published_ports':[],
            'started':datetime.now(timezone.utc).isoformat(),'resources_before':inventory()}
    def persist(): (output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    def call(argv,required=True,timeout=30):
        row={'argv':argv,'exit_code':None,'timed_out':False}; report['commands'].append(row); persist()
        try:
            r=subprocess.run(argv,capture_output=True,cwd=ROOT,timeout=timeout)
            row['exit_code']=r.returncode
            for stream in ['stdout','stderr']:
                data=getattr(r,stream);path=output/f'command-{len(report["commands"]):03d}.{stream}'
                path.write_bytes(data);row[stream]={'path':path.relative_to(ROOT).as_posix(),'sha256':sha(path),'bytes':len(data)}
            need(not required or r.returncode==0,'Native command failed: '+str(len(report['commands'])))
            return r
        except subprocess.TimeoutExpired:
            row['timed_out']=True;raise
        finally:persist()
    script=r'''set -eu
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=1561994425
gcc --version > /out/compiler.txt
make --version >> /out/compiler.txt
ld --version >> /out/compiler.txt
dpkg-query -W -f='${Package}\t${Version}\n' gcc gcc-12 cpp-12 binutils make libc6 libc6-dev linux-libc-dev libgcc-12-dev > /out/compiler-packages.tsv
sha256sum /usr/bin/x86_64-linux-gnu-gcc-12 /usr/bin/make /usr/bin/x86_64-linux-gnu-ld.bfd /usr/lib/gcc/x86_64-linux-gnu/12/cc1 /usr/lib/x86_64-linux-gnu/libc.so.6 > /out/compiler-sha256.txt
for build in a b; do
    mkdir /tmp/build-$build
    cp -R /source/. /tmp/build-$build/
    cd /tmp/build-$build
    export CFLAGS='-m64 -ffile-prefix-map=/tmp/build-a=/usr/src/argon2 -ffile-prefix-map=/tmp/build-b=/usr/src/argon2'
    make CC=gcc OPTTARGET=generic ARGON2_VERSION=20190702 libargon2.so.1
    if [ "$build" = a ]; then
        make CC=gcc OPTTARGET=generic test > /out/upstream-tests.txt 2>&1
    fi
done
cmp /tmp/build-a/libargon2.so.1 /tmp/build-b/libargon2.so.1
readelf -h -d -V /tmp/build-a/libargon2.so.1 > /out/elf.txt
nm -D --defined-only /tmp/build-a/libargon2.so.1 > /out/exported-symbols.txt
ldd /tmp/build-a/libargon2.so.1 > /out/dynamic-dependencies.txt
install -m 0644 /tmp/build-a/libargon2.so.1 /candidate/libargon2.so
sha256sum /tmp/build-a/libargon2.so.1 /tmp/build-b/libargon2.so.1 /candidate/libargon2.so
'''
    (output/'build.sh').write_text(script,encoding='utf-8')
    try:
        argv=['docker','run','--rm','--pull=never','--name',name,'--cidfile',str(cidfile),'--network=none','--read-only',
              '--memory=768m','--cpus=2','--pids-limit=128','--cap-drop=ALL','--security-opt=no-new-privileges',
              '--tmpfs','/tmp:rw,nosuid,size=64m','--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
              '--mount',f'type=bind,source={BASE/"native-source"},target=/source,readonly',
              '--mount',f'type=bind,source={output},target=/out','--mount',f'type=bind,source={cache},target=/candidate']
        for key,value in labels.items():argv+=['--label',key+'='+value]
        call(argv+['--entrypoint','sh',IMAGE,'/out/build.sh'],timeout=240)
        tests=(output/'upstream-tests.txt').read_text()
        need(tests.count(': OK')==12 and 'Fail on salt too short: PASS' in tests and 'ERROR' not in tests,'Original native KAT/API tests incomplete')
        elf=(output/'elf.txt').read_text();need('Advanced Micro Devices X86-64' in elf and '[libc.so.6]' in elf,'Unexpected ELF architecture/dependencies')
        need(elf.count('(NEEDED)')==1,'Unexpected additional linked runtime')
        candidate=cache/'libargon2.so'
        report.update(work_passed=True,upstream_kat_comparisons=12,upstream_api_pass_lines=tests.count(': PASS'),
                      independent_builds_byte_identical=True,candidate={'path':candidate.relative_to(ROOT).as_posix(),'bytes':candidate.stat().st_size,'sha256':sha(candidate)})
    except Exception as error:report['errors'].append(str(error) if isinstance(error,ValueError) else type(error).__name__)
    finally:
        try:
            if cidfile.exists():
                cid=cidfile.read_text().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'Invalid owned CID');report['container_id']=cid
                live=call(['docker','container','ls','-aq','--no-trunc','--filter','id='+cid]).stdout.strip()
                if live:
                    state=inspect('container',cid)
                    need(state['Id']==cid and state['Name']=='/'+name and state['Image']==compiler['Id'] and all(state['Config']['Labels'].get(k)==v for k,v in labels.items()),'Cleanup ownership mismatch')
                    call(['docker','rm','-f',cid])
                need(not call(['docker','container','ls','-aq','--no-trunc','--filter','id='+cid]).stdout.strip(),'Compiler still present')
                cidfile.unlink();report['container_retired']=True
            report['resources_after']=inventory();need(report['resources_before']==report['resources_after'],'Resource preservation differs')
            need(inputs==source_inputs(),'Native sources changed during build')
        except Exception as error:report['errors'].append('Cleanup: '+str(error))
        report['passed']=report.get('work_passed') is True and report.get('container_retired') is True and not report['errors']
        report['finished']=datetime.now(timezone.utc).isoformat();persist()
    print(json.dumps({'passed':report['passed'],'report':output.relative_to(ROOT).as_posix(),'errors':report['errors']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
