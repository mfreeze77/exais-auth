# Empty directory comparison correction

The actual offline build completed, all49 installed versions and418 immutable
SDK Python source files matched, and pip check passed. Distribution qualification
failed because the first verifier required every directory archive entry to
exist after installation. The locked pycryptodome3.20.0 wheel contains precisely
one `pycryptodome.libs/` entry, zero bytes and no descendant files.

The actual installed base pip is25.0.1. Its
[wheel installer](https://github.com/pypa/pip/blob/25.0.1/src/pip/_internal/operations/install/wheel.py)
filters directory entries at lines490–492 and creates directories only as file
parents at lines534–542. It deliberately does not install empty directories.
The verifier's directory-preservation assumption was incorrect.

The correction records each empty directory entry and its installed presence,
requires zero bytes/no descendant files, and still validates any present directory
against the no-symlink policy. Nonempty directories remain required. Every actual
wheel file except the already-declared pip-rewritten RECORD must still match
exactly. The denominator remains49 distributions and418 SDK Python files.
No native, license or functional acceptance rule is waived.

`verify_python_distribution.executed.py` preserves the exact failed checker;
the original report and command hashes remain unchanged. Both temporary containers
and the failed candidate094724f838d3 were removed; the previous image tag7a4bb6dcfd63
remained current. The next build uses these existing BuildKit filesystem caches
and the verified wheel cache, without a new dependency download or forced rebuild.
