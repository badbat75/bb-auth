---
name: docs-playbook
description: How the docs agent keeps the project docs accurate, and the pitfalls met so far. Use when editing README, AGENTS.md or docs/.
---

Rules are in `AGENTS.md`. Format of this file: `AGENTS.md`, under "Skills".

## How to

- For each fact, say whether it was measured here, read in a source, or reported by the user.
- When a measurement proves a note wrong, replace the note. Do not leave both.
- When a target is added, moved or deleted, grep for the **counts**, not only for the name:
  `grep -n "five targets\|four programs\|all three\|three programs\|three HTML" AGENTS.md
  README.md docs/ARCHITECTURE.md`. How many programs emit HTML, read the settings file, answer
  `--version`, and link the library are stated as numbers in prose in a dozen places, including
  the check table under "Commands", and none of them is pinned by a test.
- A prose count of code (`about 7,000 lines`, `nine that drive real HTTP`) is a measurement with
  no source in the file. Re-measure it (`wc -l`, the `cargo test` summary) before repeating it,
  and when the thing it counts moved between targets, drop the number rather than invent one.
- To check a `bb-auth-adm` recipe before documenting it, run it on a **scratch copy** under
  `/tmp/opencode` (`bb-auth-adm -f /tmp/opencode/…/access.json init`, then the recipe, then
  `can WHO URL` for the verdict the docs claim). Every write leaves an `access.json.bak` beside
  the file it wrote, so never point it at a tracked file such as `deploy/access.example.json`.
  `cargo build --bin bb-auth-adm` is instant when the tree is current.
- To check a startup rule before documenting an env var, **run the binary** on scratch files
  under `/tmp/opencode` and read its banner, which prints the value the process took
  (`workers=8`). `bb-auth-web` starts with a `{"version":1,…}` access file, a
  `{"version":3,"web":{"admins":[…]}}` settings file, `BB_AUTH_WEB_BASE_PATH=/admin` and a
  40-character `BB_AUTH_WEB_PROXY_SECRET`; run it with `timeout 3` and a spare
  `BB_AUTH_WEB_LISTEN=127.0.0.1:18091`. A unit test proves the parser; only the run proves the
  fatal path (exit 1, message naming the variable) and what the banner says.

- The CHANGELOG's released sections (`## 1.99.8 (…)`) are the record of that release. When
  unreleased work undoes a claim one of them makes, say so in a new `###` section under
  `## Unreleased` and name the release it replaces ("replacing the 1.99.8 compromise"): never
  rewrite the released section.
- To re-measure the `node e2e/shots.js` figures: scenes are the `['name', …]` entries between
  `const SCENES = [` and its `];`, interaction states the same inside `const STATES = [`, and
  the shot total is per `VIEWS` entry (a view with `states: true` runs both lists, the Italian
  view runs its own `only` list, the last views run two each). A real run is the source: it ends
  with `N screenshots -> …` (~5 minutes for the full walk) and rewrites `e2e/artifacts/visual/`,
  which is gitignored, so read that line and `ls artifacts/visual/* | wc -l` per view. The
  `['…` count needs **two** leading spaces and the block boundaries: a looser regex finds 11.
- `e2e/README.md`'s area table is a ledger of counts and of files: `run.js`'s `AREAS` list is
  the areas that exist, and each row's "N checks" is that area's line in the
  `node e2e/run.js` summary (measured 2026-11-27 after step 19: 11 areas, `settings 410/410`,
  total 1506; a step that rewrites one area's walk moves that area's count by tens).
  The suite prints them all in ~3 minutes and never touches a repo file.

## Pitfalls

- A source about something similar looks like a source, but is only a hint.
- A prose re-wrap of a Markdown line, not only a table row, brings its existing em-dash into the
  `+` side of the diff, so the added-lines em-dash grep counts it as new. Keep the dash only
  where it is data (a cell meaning "not applicable"); in prose, replace it (parentheses work).
- A scope pattern must match its application's base **including the scheme**: `*://host/*` is
  refused as outside base `https://host`. So a documented catch-all is `https://host/*`, and a
  recipe that runs `scope add … --user X` needs `user add X` first, since a name not in the
  roster aborts that command.
- `npx markdownlint-cli2 "**/*.md" "#target" "#dist" "#e2e/node_modules"` is **not clean**: it
  reports ~22 pre-existing MD041 and MD032 errors in the `.agents/`, `.claude/` and `.opencode/`
  skill and agent files, because MD041 fires on their YAML frontmatter. Judge the run by whether
  your own files appear in the list, not by the exit code, and do not "fix" the frontmatter.
- The line-number prefix (`N:` and a space) that `read` prints makes an AGENTS.md bullet continuation look indented **three**
  spaces; it is **two** (same in CHANGELOG.md's `*` bullets, and in `docs/ARCHITECTURE.md` §13's
  `-` bullets: §13.29/§13.30 use two, so a `read` copy fails to match there too). An `edit`
  oldString copied from `read` fails to match. Check with
  `sed -n 'A,Bp' AGENTS.md | awk '{printf "[%s]\n", $0}'`.
- The invariant count in `AGENTS.md` is stated in **three** places and pinned by no test: the
  contents-table row (`**42 rules…**`), the lead sentence (`Forty-two of them`), and the index
  list at the top of the section.
  The body's count is `grep -c '^- \*\*'` over the section after `### What lives where`; the
  index is the bullet list at the top of the section. Add the missing index entry, before
  repeating any number: the body carried 42 while both prose copies said 41.
- CHANGELOG.md: each `## 1.99.9 (2026-11-27, …)` heading is the release tagged with that
  number; new work goes under `## Unreleased` above the newest one (create the heading if a
  release just consumed it), as `###` sections newest first. When a section is inserted, renumber
  any "except the first N sections" clause in a lead paragraph: those clauses are a ledger.
- `docs/ARCHITECTURE.md` §13 is the architect's section: it is rewritten whole when the design
  moves, so a docs edit belongs in §2/§3 and in the stray counts outside it, not inside §13.
  Grep the line numbers before editing, since a §13 mention of an old name is the architect's
  record of the move, not rot.
- A repo-wide licence grep for "MIT" hits things that are **not** project claims: `e2e/package.json` says `UNLICENSED` (dev harness), `e2e/package-lock.json` carries dependency licences, `docs/ARCHITECTURE.md` has the Lucide/Feather (MIT) third-party sentence, and Italian UI text inside `e2e/artifacts/visual/*.png` matches `-w mit` in binaries. The packages' `copyright` file is generated by cargo-deb from the `license` line of `Cargo.toml`; `deploy/debian/` names no licence at all, so a licence change touches only LICENSE, Cargo.toml, README and CHANGELOG.
- Inside §13, each `### 13.x` is one plan step's design record. Its "Impact on the … tests",
  "What is new" and "Tests:" lists are where a shipped slice leaves rot ("unchanged", "dropped
  `.vh`", a class that shipped under another name), while its header/body prose for a step not
  built yet is **design, not rot**: tell the two by grepping the symbols and test names it
  names, in the working tree **and** in `git show HEAD:src/bin/…`, since an uncommitted slice
  (staged, not committed) has its tests only in the tree. Amend a false sentence with the file's
  own marker, "(Changed by §13.x …)" / "(Superseded by §13.x …)", so the design stays the record.
  When the change came from a plan step that has no §13.x of its own, mark it "(Changed by plan
  step N, YYYY-MM-DD: …)" and name what is true now, not only what was removed.
- A §13 bullet that names **several** tests is usually moved by only some of them. Read each
  test's body, and `git show <commit> -- src/bin/<target> | grep -n '^@@'` to see which hunks
  moved, before writing "(Changed by …)" on it: a note about "the assertion is now a constant"
  belongs on the test whose assertion moved, and a step that widened the self-service page left
  the console-route walk of `no_page_but_the_reveal_carries_a_script` byte for byte as it was.
- `src/assets/admin.css` is embedded and emitted **into the page**, so its comments travel in
  the response body, and tests assert on body substrings: the proxy-secret refusal tests assert
  `!body.contains("Dashboard")`, and a CSS comment naming "the Dashboard tab" turned them red.
  Never write in a CSS asset comment a word a body-substring test forbids.
- The design record runs **ahead of** the code, and the newest §13.x word is not what ships.
  §13.34 §12g records the user reversing the phone brand rule on 2026-11-27 (commit b04706f,
  docs only) while the CSS from 7f13066 still hides the mark at 640px and below. Check
  `git log --oneline -N -- src/assets/admin.css` against the docs commits, and write what the
  tree does, naming the reversal as **not built**.
- An area's "N checks" in `e2e/README.md` goes stale by a **factor**, not by one: each check
  inside a walk over widths × languages × names multiplies (the row said 74 where the run
  reported 379). A green suite is no evidence about the number; only the summary line is.
