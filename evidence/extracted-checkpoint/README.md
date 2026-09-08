# Exact source-ZIP application proof

The run `20260908T222920Z-23f3d2` qualified representative applications from the
unchanged source ZIP `expertauth-partial-checkpoint-69c68e8b4994.zip`:

- Commit: `69c68e8b4994621c3e83c3b07377f470ecf1b006`.
- ZIP SHA-256: `fa2928981992492faf8f30bfb6485425080e23be4bbdc8a60195013c818623ad`.
- Report file SHA-256: `cf3e1c71a448f463996d5e064b3fe5df520479e21bfe7c85a1d5097555ada16a`.
- Executed wrapper SHA-256: `b55e7c8fcd7816ba4f913da6c7219c4c7d26a55522a7da3a5dfdbd91c7149877`.

All724 manifest files were checked before building the Node/React and Python
images using only the extracted application source and locks. All12 Node HTTP,
19 Python HTTP and4 Chromium checks passed, with no skipped checks. The report
contains source hashes, exact commands, image IDs, sanitized logs and screenshots.
The source ZIP and extracted manifest files remained unchanged during execution.

The original wrapper's displayed/`latest.json` digest hashed the LF JSON string,
but Windows wrote CRLF bytes: it reported `4d1360a39899cd204b018d9605a607f1d8c94802a6c221e2040a3b46f07924c4`
instead of the physical file hash above. The historical report is preserved;
`latest.json` is corrected and future reports are written as exact UTF-8 bytes.
Ledger references hash the actual file. This correction does not rerun any test.

The existing private Core and PostgreSQL were reused. This proves representative
application build/behavior from the archive, not fresh database deployment,
backup/restore, migrations, a selected engine, full API/SDK parity or security review.

The earlier `20260908T222718Z-a632c0` failure is retained: the SDK rejected a bare
Docker hostname. The corrected run used unique dotted aliases/origins, with no
application source change. Rebuilding both dependency layers again was unnecessary
for that configuration fix; the revised wrapper now defaults to cached builds.

The user-requested hygiene cleanup retired all4 extracted application containers,
all4 temporary image tags and both extracted trees. Raw logs are preserved with
their original hashes under ignored `.runtime/retired-proof-logs/20260908T223704Z`;
the original reports retain their historical paths. See `../operations/hygiene`.

The current wrapper has subsequent cleanup/label/cache changes and12 passing
integrity/filesystem tests. Its new full Docker flow has not been executed. The
old report must not be relabeled as proof of a different wrapper or ZIP. Before
repeating live qualification for a relevant application/lock change, inventory
resources and use this command; cleanup is automatic:

```powershell
python tools/qualify_extracted_checkpoint.py --zip artifacts/expertauth-partial-checkpoint-69c68e8b4994.zip --sha256 fa2928981992492faf8f30bfb6485425080e23be4bbdc8a60195013c818623ad
```

Do not rebuild merely because documentation or cleanup code changed. The immutable
baseline and all original requirement/API/profile IDs remain binding.
