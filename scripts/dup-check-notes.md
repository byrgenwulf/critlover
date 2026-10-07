# critlover — dup-check notes

*The dup-check gate's playbook. This is **stage 4, Gate B**: before a candidate
becomes a `SUBMISSION`, prove it is **not already known**. A dup is worth **zero** and costs
credibility — enumerate honestly, match hard, and when a prior disclosure of the same root cause
exists, discard (a correctly discarded finding is a win, STRATEGY §5).*

> **Reading-only.** Everything here is enumeration and matching against *public* records — advisories,
> PRs, issues, commits, changelogs. No exploitation, no probing a live system, no contacting
> maintainers mid-hunt. Authorized, in-scope target; responsible disclosure via the official program.

`gh` is preconfigured here; the GitHub MCP tools (`mcp__github__*`) are equivalent — call
`mcp__github__get_me` once first, prefer `list_*` for broad pulls and `search_*` for keyword/filter
queries, and page in batches of 5–10 with `minimal_output` where offered.

---

## 1 · What is — and isn't — a dup

| Already known → **DUP (discard)** | Looks similar → **NOT a dup (keep, grade honestly)** |
|---|---|
| Same root cause in a **published advisory / CVE** (GHSA, OSV, huntr, ZDI). | A **sibling path the fix missed** (incomplete-fix, §5) — a *new* finding; cite the CVE. |
| **Silently fixed on `main`** / in an unreleased branch (no advisory yet). | A **different bug class** in the same file (e.g. OOB-write where the DoS was excluded). |
| An **open or recently-merged PR** that patches the same sink. | The **same shape, different reachability** that the known issue didn't cover (guest-unpriv vs root). |
| An **open/closed issue** describing the same bug. | A candidate whose only match is a **shared keyword**, not the same root cause. |
| **Documented behavior / wontfix / by-design** (§5) — not a vuln at all. | — |
| Inside a **carve-out** the vendor declared out of scope (STRATEGY §2). | A path that routes **around** the carve-out into a defended boundary. |

**Match on the root cause, not the words.** Two reports with different prose can be the same bug; two
with the same keyword can be unrelated. Decide on: the **vulnerable symbol/function**, the
**file/subsystem**, the **bug class (CWE)**, and the **reachability/trigger** — not on adjectives.

---

## 2 · Enumeration checklist

Run every row; a dup hides in whichever one you skip. Replace `<owner/repo>`, `<pkg>`, `<keyword>`,
`<symbol>`.

**a) Published advisories (the vendor's own + the global DBs).**
```sh
# Repo-level GHSA (draft+published the repo exposes):
gh api repos/<owner>/<repo>/security-advisories --paginate
# Global GitHub Advisory DB for the package/ecosystem:
gh api "/advisories?ecosystem=pip&affects=<pkg>&per_page=100" --paginate
# OSV (cross-ecosystem), reading-only:
# POST https://api.osv.dev/v1/query  { "package": { "name": "<pkg>", "ecosystem": "PyPI" } }
```
Also eyeball the repo **Security** tab, `SECURITY.md`, and the venue listings: **huntr** (the package's
disclosures), **ZDI** published advisories, and any vendor security page / release notes.

**b) Open + recently-merged PRs** (silent fixes land here before any advisory).
```sh
gh pr list   --repo <owner>/<repo> --state all  --search "<keyword>" --limit 50
gh search prs "<keyword> repo:<owner>/<repo>"            # or mcp__github__search_pull_requests
```
MCP: `list_pull_requests` (broad) / `search_pull_requests` (keyword). Read the diff of any hit near
your sink — a merged fix you didn't notice is still a dup.

**c) Open + closed issues** (bug reports, and wontfix/by-design verdicts, §4).
```sh
gh issue list --repo <owner>/<repo> --state all --search "<keyword>" --limit 50
gh search issues "<keyword> repo:<owner>/<repo>"         # or mcp__github__search_issues
```

**d) Silent fix on `main` / in history** — match the *symbol*, not the advisory.
```sh
gh search commits "<symbol> repo:<owner>/<repo>"         # or mcp__github__search_commits
# Human, local checkout, reading-only — pickaxe the sink's add/remove and any touch:
git log -S'<symbol>' --oneline -- <path>     # commits that changed how often <symbol> appears
git log -G'<regex>'  --oneline -- <path>     # commits whose diff matches <regex>
git log --oneline -- <path>                  # recent history of the file you're flagging
```

**e) Releases / changelog** — a fix may be shipped but not advisory-tracked.
```sh
gh release list --repo <owner>/<repo> --limit 20
gh api repos/<owner>/<repo>/releases --paginate --jq '.[].body'   # grep for your symbol/keyword
```

---

## 3 · Cache advisory + fix titles for fast matching

Pull once, match many. Build a small local index so every candidate is a `grep`, not a round-trip.
Write the cache to your scratch dir (not into the repo under review).

```sh
# Advisories -> TSV of ghsa_id, cve_id, summary:
gh api repos/<owner>/<repo>/security-advisories --paginate \
  --jq '.[] | [.ghsa_id, (.cve_id // "-"), .summary] | @tsv'        >  advisories.tsv
gh api "/advisories?ecosystem=pip&affects=<pkg>&per_page=100" --paginate \
  --jq '.[] | [.ghsa_id, (.cve_id // "-"), .summary] | @tsv'        >> advisories.tsv

# Open PR + issue titles (silent fixes / known reports):
gh pr    list --repo <owner>/<repo> --state all --limit 300 --json number,title,state \
  --jq '.[] | ["PR",  (.number|tostring), .state, .title] | @tsv'  >  known.tsv
gh issue list --repo <owner>/<repo> --state all --limit 300 --json number,title,state,labels \
  --jq '.[] | ["ISS", (.number|tostring), .state, .title] | @tsv'  >> known.tsv
```
Match a candidate against the cache on its strongest tokens — the **symbol**, the **CWE/class word**
(`deserialization`, `ssrf`, `path traversal`, `oob`, `use-after-free`), and the **subsystem**:
```sh
grep -iE '<symbol>|<subsystem>|<class-word>' advisories.tsv known.tsv
```
A hit is a *lead to read*, not an automatic dup — open it and compare **root cause + reachability**.
No hit lowers the odds but is **not** proof of novelty; the silent-fix (§2d) and incomplete-fix (§6)
checks still have to pass.

---

## 4 · Documented behavior / wontfix — recognize it before you file

Behavior the vendor has **accepted** is not a vulnerability; filing it burns credibility faster than a
dup. Signals, in order of authority:

- **Threat model / `SECURITY.md` / scope page** (already captured in the threat-model-filter block of
  `templates/PROGRESS.md` at stage 0). If the behavior sits inside a declared carve-out, it is out of
  scope — attack *around* it
  (STRATEGY §2), don't report *into* it.
- **Closed issues/PRs with a verdict label:** `wontfix`, `by-design`, `works-as-intended`, `invalid`,
  `security:accepted-risk`, `notabug`. Read the maintainer's closing comment.
  ```sh
  gh issue list --repo <owner>/<repo> --state closed --label wontfix --search "<keyword>"
  ```
- **Maintainer language that caps severity:** "requires admin", "trusted input", "not a security
  boundary", "run it on a trusted network", "misconfiguration". That phrasing *is* the carve-out —
  honor it and re-score (downgrade, never inflate, STRATEGY §6).
- **Docs that warn against the dangerous use:** a config flag documented as "do not enable with
  untrusted input" usually means the unsafe path is accepted behavior behind that flag.

---

## 5 · Incomplete-fix siblings — a variant is NOT a dup

The highest-EV source-review move (STRATEGY §3c). A patch typically closes **one** call path, not the
root cause's siblings — so a sibling the fix missed is a **new** finding, filed as *"incomplete fix of
`<CVE/GHSA>`"*, not a duplicate.

1. **Find the fix** for the recent CVE: the advisory's patched-version / referenced PR, or `git log`
   around the disclosure date.
2. **Read the diff *and its regression test*.** The test reveals exactly which path the maintainer
   considered closed — and, by omission, which they didn't.
3. **Grep the same sink shape in the untouched siblings** (use `scripts/sink-grep.sh`):
   - the *other* caller of the same sink that still passes attacker data,
   - the adjacent function with the identical unchecked-length/bounds pattern,
   - the fix applied to the sync path but not the async one (or header but not trailer, read but not
     write).
4. **Confirm the sibling isn't *separately* already filed** — re-run §2/§3 on the sibling's own symbol.
   Incomplete fixes are under-swept *by construction* (everyone assumes the CVE closed it), but still
   dup-check the variant itself.

---

## 6 · Verdict → record it

Make the dup-check **auditable**: log every query and its result in `templates/PROGRESS.md`, so a
reviewer can see the finding is novel without re-running the search.

- **Any prior disclosure of the same root cause** (advisory / silent fix / open PR / open issue) →
  **DUP → discard.** Note the link in `PROGRESS.md` and move on.
- **Documented behavior / inside a carve-out** → **not a vuln** (or honestly-capped) → skip or
  downgrade per the rubric (STRATEGY §6). Never relabel it a crit to clear a quota.
- **Survives all of §2–§5** → carry the dup-check **trail** (the links you checked) into
  `templates/SUBMISSION.md`; it is part of the deliverable, not a side note.

> The `gh` / MCP commands in §2–§3 are the enumeration to run by hand; these notes are the judgment no
> command can make. The queries list candidates; **you** decide same-root-cause vs. sibling vs. novel —
> and you stay default-skeptical of your own candidate until the records say it's new.
