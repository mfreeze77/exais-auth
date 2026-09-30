# Correction: cloud-source-01 cleanup claim

`report.json` records `"volumes_created": 0`. That was a constant in the runner, not
a measurement, and it was wrong. The pinned runtime image
`gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2`
declares `VOLUME /home/gradle/.gradle`. Each of the seven Core containers therefore
received an anonymous volume, and `docker rm -f` without `-v` left them behind. One
more anonymous volume came from a pre-lab network-reachability test container.

The session's post-run hygiene check found all eight: anonymous, created
2026-09-30T05:56–05:59Z on a Docker daemon started fresh at 05:50Z, holding no lab
data. They were removed by exact ID. No other resource was affected.

The runner now mounts tmpfs over `/home/gradle/.gradle`, as `tools/launch_oss_probe.py`
does. It removes containers with `-v`, measures volumes before and after, and fails
on any leak. `cloud-source-02` reran all 20 cases with the corrected runner and
recorded `volumes_left: []`. The authentication results of this run are unaffected
and are kept as historical evidence.
