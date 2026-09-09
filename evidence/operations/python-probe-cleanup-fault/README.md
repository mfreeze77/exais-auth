# Python probe transport-failure cleanup

`run-02` passed four harness regression checks against the actual FastAPI app and
existing private SuperTokens Core/PostgreSQL. The pass-through proxy forwarded
normal requests and closed only the second `POST /auth/signout` connection before
forwarding. This produced a real `RemoteProtocolError` in the probe's auxiliary
signout operation.

The child probe correctly exited **1**, preserved its incomplete report (12
executed checks, 7 unexecuted, no skipped-success claim), and removed its one
synthetic identity through Core. The 52 pre-existing identity IDs were unchanged.
The fault harness performed zero compensating deletions. Secret-value and JWT
shape checks passed; identities and tokens are not emitted.

The outer fault test exited **0** because the expected failure was handled and
recorded correctly. These four checks qualify test-harness cleanup only. They do
not qualify authentication parity, all Python profiles, production operations,
or independent security review.

Run from the repository after the private Core/PostgreSQL lab is running, with no
concurrent tests that create/delete identities:

```powershell
python tools/run_python_probe_cleanup_fault.py --name NEW_UNIQUE_RUN_NAME
```

The wrapper requires the cached image
`sha256:7a4bb6dcfd634a98f603d65bc2c1219fef5b3a46a00be705631201c4f78802f1`.
It checks installed app/lock hashes, creates two named private containers, and
removes them using exact container IDs plus both ownership labels in `finally`.
It performs no builds, downloads, image-tag changes, database restarts, new
volumes/networks, or published ports. Run-02 recorded zero Docker resource delta,
unchanged Core/PG IDs, images, mounts and start times, and empty private scratch.

Run-02 retired container IDs:

- App: `ba2aff87f4ef133071c9853de41be4f1706f8ad70fe0a7021df0961dac59cae7`
- Probe: `44f15e2eaa82faea36f93d521131073dc51bbb763ffd6b04a5d2d2842e75fa8f`

`run-01` is a preserved failed preflight: its 1,000-user page exceeded the pinned
Core's actual `AuthRecipe.USER_PAGINATION_LIMIT = 500` (despite an outdated API
comment). No signup or fault request occurred. Its containers retired with zero
resource delta. Exact prior owned source files and hashes are under
`run-01/inputs/`; the corrected run uses a bounded 500-user page and fails closed
if another page would be needed.

Run-02 host report SHA-256:
`7153b862873c83131fa992dd01ec3003059be120879092a73a0d86b86be9a0a5`.
The report binds all seven current source inputs and all four result artifacts.
