# tests — grepper self-test

This suite regression-tests critlover's READ-ONLY recon scripts (`scripts/sink-grep.sh`,
`scripts/authz-census.sh`, `scripts/churn.sh`, and `scripts/entrypoints.sh` once it lands)
by running them against the tiny **synthetic** fixtures in `fixtures/` and asserting their
actual output: that `sink-grep` reports the `pickle.loads` (deser) and `memcpy` (native)
and `eval(` (exec) sinks, that `authz-census` lists both the guarded GET and the unguarded
`[MUTATING]` POST and that `ONLY_NONE=1` narrows to just the blank-guard POST, that
`entrypoints.sh` surfaces the route/listener (or SKIPs if the script is not present yet),
and that `churn.sh` ranks a file in a throwaway git tree. It also carries regression checks for
fixed defects: multi-language sink coverage (JS/Rust, not just Python+C), the context-count
invariant (`CONTEXT>0` must not inflate the hit count), that a non-auth `Depends(get_db)` is not
treated as a guard, and that `patch-variant.sh` does not execute a malicious repo's
`diff.*.textconv`. It also runs `workflow.test.mjs` (a node stub harness that loads the actual
`.claude/workflows/crit-hunt.js` body with fake agents and asserts its grading control flow —
Gate-A short-circuit, identity dedup, drop reasons, the MED floor — with no subagents or target;
SKIPs if node is absent). Run it with `bash tests/run.sh` from anywhere (it locates its own repo root);
it prints `PASS`/`FAIL`/`SKIP` per check and exits non-zero if anything fails. The fixtures
(`fixtures/app.py`, `fixtures/app.js`, `fixtures/app.rs`, `fixtures/buf.c`) are fake,
non-exploitable grep bait — never imported, served, or executed; the suite only tests that the
greppers still match and label what we expect.
