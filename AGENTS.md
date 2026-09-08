# ExpertAuth working rules

The original kickoff and immutable full-parity baseline remain authoritative.
The user's explicit disk/Docker hygiene instruction applies to every agent.

- Inspect current containers/images/scratch usage before adding resources. Use
  task-specific names and `org.expertauth.project=expert-auth` labels.
- One-off containers use `--rm`. Service probes must stop AND remove their own
  temporary containers in `finally`, after retaining sanitized evidence.
- Keep one current image per component. Remove obsolete task tags and task-proven
  unused layers after evidence/source pins make the build reproducible. Do not
  retain a fleet of old images merely because historical reports mention them.
- Use normal content-addressed build caching. `--no-cache` requires a concrete
  reproducibility need. A runtime configuration or test-harness fix is not a
  reason to rebuild unchanged application/dependency layers.
- Remove duplicate extracted trees and scratch builds at package completion.
  Preserve small private raw logs under ignored `.runtime/` when needed, plus
  sanitized reports and source/ZIP hashes. Keep necessary source/dependency caches
  bounded; never make repeated anonymous copies of the same build.
- Before recursive removal, verify the resolved absolute target is inside the
  intended workspace cache. Preserve repository files, immutable baseline,
  persistent databases, user work and unrelated Docker resources. Back up H2 data
  from a retired container's writable layer before removing that container.
- Never use global Docker prune/volume prune or compact/restart Docker/WSL as
  incidental cleanup. Shared base images, unrelated containers and data volumes
  are outside this task's cleanup scope.
- Bounded subagents must report and retire their resource IDs/scratch directories
  when finished. Parent integration verifies cleanup and actual evidence.
- Hygiene does not waive any requirement or acceptance test. Keep foundation,
  native/provider and independent-review blockers visible. Do not retry the
  automatically rejected identity-hardening action through another agent/tool.
