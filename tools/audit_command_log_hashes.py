"""Diagnose historical command-log digests without changing original evidence."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    rows = []
    for path in sorted((ROOT / 'evidence/runs').glob('*/command.json')):
        record = json.loads(path.read_text())
        log = path.parent / 'output.log'
        raw = log.read_bytes()
        expected = record['output_sha256']
        actual = sha(raw)
        status = 'exact' if actual == expected else 'historical-crlf-mismatch' if sha(raw.replace(b'\r\n', b'\n')) == expected else 'unexplained-mismatch'
        rows.append({'record': path.relative_to(ROOT).as_posix(), 'record_sha256': sha(path.read_bytes()),
                     'log': log.relative_to(ROOT).as_posix(), 'reported_sha256': expected,
                     'actual_file_sha256': actual, 'status': status})
    report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'rows': rows,
              'source_sha256': sha(Path(__file__).read_bytes()), 'original_files_changed': False,
              'authentication_complete': False,
              'scope': 'Forensic byte-hash correction index only. Original mismatched reports remain ineligible as exact-digest release evidence; this does not rerun tests or create acceptance claims.'}
    counts = {status: sum(row['status'] == status for row in rows) for status in ('exact', 'historical-crlf-mismatch', 'unexplained-mismatch')}
    report['counts'] = counts
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    output = ROOT / 'evidence/integrity' / f'command-log-newline-audit-{stamp}.json'
    with output.open('xb') as stream:
        stream.write((json.dumps(report, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'report': output.relative_to(ROOT).as_posix(), **counts}))
    return int(bool(counts['unexplained-mismatch']))


if __name__ == '__main__':
    raise SystemExit(main())
