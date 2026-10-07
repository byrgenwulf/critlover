# tests — grepper self-test

This suite regression-tests critlover's READ-ONLY recon scripts (`scripts/sink-grep.sh`,
`scripts/authz-census.sh`, `scripts/churn.sh`, and `scripts/entrypoints.sh` once it lands)
by running them against the tiny **synthetic** fixtures in `fixtures/` and asserting their
actual output: that `sink-grep` reports the `pickle.loads` (deser) and `memcpy` (native)
and `eval(` (exec) sinks, that `authz-census` lists both the guarded GET and the unguarded
`[MUTATING]` POST and that `ONLY_NONE=1` narrows to just the blank-guard POST, that
`entrypoints.sh` surfaces the route/listener (or SKIPs if the script is not present yet),
and that `churn.sh` ranks a file in a throwaway git tree. Run it with `bash tests/run.sh`
from anywhere (it locates its own repo root); it prints `PASS`/`FAIL`/`SKIP` per check and
exits non-zero if anything fails. The fixtures (`fixtures/app.py`, `fixtures/buf.c`) are
fake, non-exploitable grep bait — they are never imported, served, or executed; the suite
only tests that the greppers still match and label what we expect.
