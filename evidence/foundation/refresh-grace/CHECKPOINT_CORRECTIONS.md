The first checkpoint-idempotence check found WP-004's qualification note doubled
on repeated ledger regeneration. Its implementation/evidence arrays and status
were unchanged. The updater now initializes its owned WP-004 note before adding
candidate observations; the final check verifies identical complete ledger bytes
across regeneration. No requirement status or acceptance denominator changed.

Git's whitespace check also flagged an existing trailing-space line in the
hash-bound upstream CoreConfig.java snapshots. Those original bytes were preserved.
The repository attributes exclude only that audited-upstream snapshot subtree
from whitespace styling, just as raw command logs already are. Source SHA-256
verification still applies; product, test and launcher code retain normal checks.
