"""Execute an argv command and retain redacted output plus immutable input hashes."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', required=True)
    parser.add_argument('--input', action='append', default=[])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1]==['--'] else args.command
    assert command, 'Command argv required'
    output = ROOT/'evidence/runs'/args.id
    assert output.resolve().is_relative_to((ROOT/'evidence/runs').resolve())
    assert not output.exists(), 'Evidence run ID already exists; choose a new ID'
    output.mkdir(parents=True)
    def hashes():
        return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in args.input}
    inputs = hashes()
    # Local synthetic secrets are never part of source/evidence.
    secret_values = []
    for env in (ROOT/'.runtime').rglob('*.env'):
        for line in env.read_text().splitlines():
            if '=' in line:
                key,value = line.split('=',1)
                if any(token in key for token in ['PASSWORD','SECRET','API_KEY']) and value:
                    secret_values.append(value)
    started = time.time()
    run = subprocess.run(command,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace')
    text = run.stdout + run.stderr
    for secret in secret_values:
        text = text.replace(secret,'[REDACTED]')
    (output/'output.log').write_text(text,encoding='utf-8')
    record = {'command':command,'exit_code':run.returncode,'started_unix':started,'elapsed_seconds':round(time.time()-started,3),
              'input_sha256':inputs,'inputs_changed':hashes()!=inputs,'output_sha256':hashlib.sha256(text.encode()).hexdigest(),
              'scope':'command execution only; requirement acceptance must be reviewed separately'}
    (output/'command.json').write_text(json.dumps(record,indent=2)+'\n')
    print(text)
    print(json.dumps({'evidence':str(output),'exit_code':run.returncode,'inputs_changed':record['inputs_changed']}))
    raise SystemExit(run.returncode or int(record['inputs_changed']))

if __name__ == '__main__':
    main()
