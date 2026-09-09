# make_sunver.pl grant review

**BLOCKED: exact grant remains unresolved.** The research found strong GCC
provenance and a downstream GPL-3.0-or-later classification. It did not establish
an unambiguous grant for the exact JNA file and all relevant contributions.
The original evidence and existing export exclusion remain unchanged. This
finding is not a license approval and does not change WP-002 or foundation gates.

The pinned JNA file is `native/libffi/make_sunver.pl` at commit
`cc4ce71d511a9aa17219cc36e2338dd1b0f52770`:

| Property | Verified value |
| --- | --- |
| Length | 9,021 bytes / 333 lines |
| Git blob SHA-1 | `8a90b1fea0d366f7a9ec0857d5304a67ee34f389` |
| SHA-256 | `ca40d3458893e03a90807be87d720a59e921ee6bf678c6696779d635004a261f` |

`findings.json` records these hashes, enclosing-notice hashes, eight primary
source references, the unresolved grant and bounded resume inputs. Regenerate
the local record without network or native execution:

```powershell
python -B evidence/reuse/native-correspondence/jna/grant-review/record_review.py
```

## Provenance found

JNA's [January 2021 import](https://github.com/java-native-access/jna/commit/ffb7e0e7ed963d88eec3ed93fe9a47efccecd557)
identifies libffi revision `5c63b463b87d3c06102a4a7f05f395929d9ea79b`, described as
v3.3 plus 64 commits. This is more specific than the `3.3` version label in
`configure.ac`; it is not proof that every JNA-vendored file is an unchanged
libffi release file.

Anthony Green's [October 2019 libffi addition](https://github.com/libffi/libffi/commit/ca112537df7b9cdbccad7541aa3cb43b2a2dac9a.patch)
adds the 333-line script with Git blob prefix `8a90b1fea`. It changes the build
reference from `../contrib/make_sunver.pl` to the local copy and adds its name to
the build-tool scope paragraph of `LICENSE-BUILDTOOLS`. The following sentence
assigning GPL v2 still names only `msvcc.sh` and the bhaible tests. The newly
added script has no individual copyright/license header.

GCC's [February 2013 edit](https://github.com/gcc-mirror/gcc/commit/d809887a669e7c2c709d1ca37d2f0e44ecfdb341.patch)
has target blob prefix `8a90b1fea0d36`, also matching the pinned JNA blob.
That edit, by Rainer Orth, enforces the C locale (SVN r196309). The
[July 2010 addition](https://github.com/gcc-mirror/gcc/commit/1e0859a29e0b7ca2f70e156aafdac7b4db30663b)
already lacks a file grant header. Matching abbreviated blob identities and
history strongly support GCC-to-libffi-to-JNA provenance. This lane did not
re-acquire upstream full blob metadata or bytes, so it does not elevate those
prefix matches to independently verified full-byte equality.

## Terms boundary

At the matching GCC revision, the
[README](https://raw.githubusercontent.com/gcc-mirror/gcc/d809887a669e7c2c709d1ca37d2f0e44ecfdb341/README)
directs readers to `COPYING*` and notes differing terms for some components.
Both [GPL v2](https://raw.githubusercontent.com/gcc-mirror/gcc/d809887a669e7c2c709d1ca37d2f0e44ecfdb341/COPYING)
and [GPL v3](https://raw.githubusercontent.com/gcc-mirror/gcc/d809887a669e7c2c709d1ca37d2f0e44ecfdb341/COPYING3)
texts are present. This research did not find a source declaration selecting
the exact script's applicable terms.

FFmpeg's [2015 import](https://github.com/FFmpeg/FFmpeg/commit/c1aac39eaccd32dc3b74ccfcce701d3d888fbc6b)
explicitly identifies GCC as the source and adds an FSF 2010–2013,
GPL-3.0-or-later header to its downstream copy. That establishes FFmpeg's
treatment of its copy; it is not, by itself, an originating rightsholder grant
for the exact JNA bytes. GPL-3.0-or-later remains a candidate to qualify, not a
resolved classification here. Neither JNA's root Apache/LGPL offer nor libffi's
root MIT notice justifies automatically overriding this separate tooling history.

The next decisive inputs are full immutable GCC/libffi file identity and an
originating license declaration or authorized clarification explicitly covering
the script/revision. Candidate URLs and expected blob identity are recorded in
`findings.json`. No upstream message has been sent. Web API/Gitiles metadata
access was unavailable; failed endpoints were not retried through Docker or
host-network workarounds. No archives, binaries, containers, runtime changes or
native tests were introduced.
