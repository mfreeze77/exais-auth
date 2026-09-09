"""Bounded, immutable candidate JAR directories; no overwriting a qualified pair."""
import hashlib
from pathlib import Path
import re

NAMES = {'core': 'core-12.2.0.jar', 'postgresql': 'postgresql-plugin-9.8.0.jar'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def safe_directory(root, path):
    cache = root / '.cache'
    need(path.parent == cache and re.fullmatch(r'password-session(?:-[A-Za-z0-9_-]{1,54})?', path.name),
         'Candidate path outside bounded cache')
    for item in (root, cache, path):
        need(not item.is_symlink() and not (item.exists() and getattr(item.lstat(), 'st_file_attributes', 0) & 0x400),
             'Candidate cache must not use links or reparse points')
    need(path.resolve().parent == cache.resolve(), 'Candidate path escaped cache')

def validate_pair(root, report):
    need(report.get('passed') is True and len(report.get('candidates', [])) == 2, 'Prior candidate build incomplete')
    rows = report['candidates']
    need({r['component'] for r in rows} == set(NAMES), 'Exact Core/plugin pair required')
    paths = [root / r['path'] for r in rows]
    folder = paths[0].parent
    safe_directory(root, folder)
    need(folder.is_dir() and {p for p in folder.iterdir()} == set(paths), 'Unexpected candidate cache contents')
    for row, path in zip(rows, paths):
        need(path.parent == folder and path.name == NAMES[row['component']] and path.is_file() and
             not path.is_symlink() and not getattr(path.lstat(), 'st_file_attributes', 0) & 0x400 and
             path.stat().st_size == row['bytes'] and hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256'],
             'Prior candidate differs')
    return folder

def new_candidate(root, name, prior):
    need(re.fullmatch('[A-Za-z0-9_-]{1,54}', name), 'Invalid candidate name')
    previous = validate_pair(root, prior)
    target = root / '.cache' / ('password-session-' + name)
    safe_directory(root, target)
    need(not target.exists(), 'Preserve existing candidate')
    existing = set((root / '.cache').glob('password-session*'))
    need(existing == {previous}, 'Retire the previously superseded pair before another candidate build')
    return target
