"""Assemble one qualified PHC source-native library into the bounded Core image context."""
import hashlib
import json
from pathlib import Path
import re
import zipfile
from build_native_argon2 import ROOT, PIN, source_inputs

SOURCES=['tools/install_native_argon2.py','tools/build_native_argon2.py','deploy/native-argon2-start.sh',
         'deploy/NativeArgon2Check.java','reuse/native-argon2-components.json']

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def native_build(name):
    need(re.fullmatch('[a-z0-9-]{1,40}',name),'Invalid native build name')
    path=ROOT/'evidence/reuse/native-correspondence/argon2/native-build'/name/'report.json'
    report=json.loads(path.read_text());library=(ROOT/report['candidate']['path']).resolve()
    need(report['passed'] and report['native_commit']==PIN and report['inputs']==source_inputs() and
         report['independent_builds_byte_identical'] and library.parent==(ROOT/'.cache/native-argon2').resolve() and
         not library.is_symlink() and sha(library)==report['candidate']['sha256'],'Qualified native source/library differs')
    return path,report,library

def install(context,expected,notices,bom,name):
    context=context.resolve();need(context.parent==(ROOT/'.cache').resolve() and context.name.startswith('runtime-image-'),'Bounded image context required')
    build_path,build,library=native_build(name)
    removed='lib/argon2-jvm-2.11.jar';original=context/removed
    dependencies=json.loads((ROOT/'reuse/runtime-dependencies.json').read_text())['dependencies']
    dep=next(r for r in dependencies if r['coordinate']=='de.mkammerer:argon2-jvm:2.11')
    need(expected[removed]==dep['jar']['sha256']==sha(original),'Original native bundle differs')
    with zipfile.ZipFile(original) as archive:
        need(not any(p.endswith('.class') for p in archive.namelist()) and len([p for p in archive.namelist() if p.endswith(('.so','.dll','.dylib'))])==8,'Native-only bundle boundary differs')
    original.unlink();del expected[removed]
    members=[r for r in bom['components'] if r.get('name')=='argon2-jvm' and r.get('group')=='de.mkammerer']
    need(len(members)==1,'Native bundle SBOM identity differs');bom['components'].remove(members[0])
    bom['components'].append({'type':'library','name':'phc-winner-argon2','version':'20190702+source-linux-x86_64',
        'bom-ref':'expertauth:phc-argon2:'+PIN,'licenses':[{'license':{'id':'CC0-1.0'}}],
        'hashes':[{'alg':'SHA-256','content':build['candidate']['sha256']}],
        'externalReferences':[{'type':'vcs','url':'https://github.com/P-H-C/phc-winner-argon2/tree/'+PIN}],
        'properties':[{'name':'expertauth:source-path','value':'licenses/expertauth/native-argon2/source'},
                      {'name':'expertauth:distribution-approval','value':'pending'}]})
    def put(path,body):
        target=context/path;need(not target.exists(),'Native context collision');target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
        digest=sha(target);expected[path]=digest
        if path.startswith('licenses/'):notices['files'].append({'path':path.removeprefix('licenses/'),'bytes':len(body),'sha256':digest})
    put('native/libargon2.so',library.read_bytes())
    template=(ROOT/'deploy/native-argon2-start.sh').read_bytes()
    need(template.count(b'@ARGON2_SHA256@')==1 and b'\r' not in template,'Native launch template differs')
    put('native/start.sh',template.replace(b'@ARGON2_SHA256@',build['candidate']['sha256'].encode()))
    put('native/NativeArgon2Check.java',(ROOT/'deploy/NativeArgon2Check.java').read_bytes())
    for row in build['inputs']:put('licenses/expertauth/native-argon2/source/'+row['source_path'],(ROOT/row['path']).read_bytes())
    mapping={'kind':'installed-native-argon2-nolibs-profile','commit':PIN,'source_build_report':build_path.relative_to(ROOT).as_posix(),
        'source_build_report_sha256':sha(build_path),'library':build['candidate'],'source_files':build['inputs'],
        'removed_native_bundle':{'path':removed,'sha256':dep['jar']['sha256'],'java_classes':0,'native_members':8},
        'wrapper':'Unchanged argon2-jvm-nolibs2.11, LGPL-3.0; its incorporated GPL3 terms and other dependency obligations remain.',
        'complete':False,'other_platforms_qualified':False,'independent_distribution_review':False}
    put('licenses/expertauth/native-argon2/source-map.json',(json.dumps(mapping,indent=2)+'\n').encode())
    dockerfile=context/'Dockerfile';body=dockerfile.read_text();lines=body.splitlines();cmd=[line for line in lines if line.startswith('CMD ')]
    need(len(cmd)==1 and body.count('USER gradle')==1,'Core Dockerfile composition differs')
    args=json.loads(cmd[0][4:]);need(args[0]=='java','Original Java launch missing')
    replacement='COPY --chown=root:root native /opt/expertauth/native\nRUN mkdir -p /opt/expertauth/.native-tmp && chown gradle:gradle /opt/expertauth/.native-tmp && chmod 0700 /opt/expertauth/.native-tmp && chmod 0644 /opt/expertauth/native/*\nUSER gradle'
    body=body.replace('USER gradle',replacement).replace(cmd[0],'CMD '+json.dumps(['sh','/opt/expertauth/native/start.sh',*args]))
    dockerfile.write_bytes(body.encode())
    return mapping
